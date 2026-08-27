from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Protocol, cast

import httpx
from langchain_aws import ChatBedrock
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

from incident_agent.models import Action, ExplanationModel, Incident, OperationResult, Plan, Priority, TriageResult
from incident_agent.observability import emit_metric
from incident_agent.planning.prompt_loader import PromptLoader


class Planner(Protocol):
    async def triage(self, incident: Incident) -> TriageResult: ...

    async def plan(self, incident: Incident, evidence: list[OperationResult]) -> Plan: ...


class ProviderInvocationError(RuntimeError):
    provider = "provider"


class BedrockInvocationError(ProviderInvocationError):
    provider = "bedrock"


class OpenAIInvocationError(ProviderInvocationError):
    provider = "openai"


class BedrockPlanner:
    def __init__(
        self,
        model_id: str,
        max_prompt_bytes: int,
        region_name: str,
        prompts_dir: str | Path = "",
        transient_retry_attempts: int = 2,
    ):
        self.model_id = model_id
        self.region_name = region_name
        self.model: BaseChatModel = ChatBedrock(model=model_id, region=region_name, temperature=0)
        self.max_prompt_bytes = max_prompt_bytes
        self.prompts = PromptLoader(prompts_dir or None)
        self.transient_retry_attempts = max(1, transient_retry_attempts)

    def explain_model(self) -> ExplanationModel:
        return ExplanationModel(
            provider="bedrock",
            plannerType="bedrock",
            modelId=self.model_id,
            awsRegion=self.region_name,
            temperature=0,
            maxPromptBytes=self.max_prompt_bytes,
            promptTemplates={
                name: _template_hash(self.prompts.prompts_dir / name)
                for name in ["triage_system.md.j2", "triage_user.md.j2", "plan_system.md.j2", "plan_user.md.j2"]
            },
        )

    async def triage(self, incident: Incident) -> TriageResult:
        prompt = _bounded(
            self.prompts.render(
                "triage_user.md.j2",
                alarm_name=incident.alarm_name,
                host_id=incident.host_id,
                reason=incident.reason,
            ),
            self.max_prompt_bytes,
        )
        system_prompt = _bounded(self.prompts.render("triage_system.md.j2"), self.max_prompt_bytes)
        message = await self._invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(content=prompt),
            ],
            phase="triage",
        )
        return _decode_triage(str(message.content))

    async def plan(self, incident: Incident, evidence: list[OperationResult]) -> Plan:
        evidence_json = json.dumps([item.model_dump(by_alias=True) for item in evidence])
        prompt = _bounded(
            self.prompts.render(
                "plan_user.md.j2",
                alarm_name=incident.alarm_name,
                reason=incident.reason,
                host_id=incident.host_id,
                evidence_json=evidence_json,
            ),
            self.max_prompt_bytes,
        )
        system_prompt = _bounded(self.prompts.render("plan_system.md.j2"), self.max_prompt_bytes)
        message = await self._invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(content=prompt),
            ],
            phase="plan",
        )
        return Plan.model_validate_json(_strip_fence(str(message.content)))

    async def _invoke(self, messages: list[BaseMessage], phase: str) -> BaseMessage:
        last_error: Exception | None = None
        for attempt in range(1, self.transient_retry_attempts + 1):
            started = time.monotonic()
            try:
                message = await self.model.ainvoke(messages)
                emit_metric("BedrockRequestLatencyMs", (time.monotonic() - started) * 1000, "Milliseconds", phase=phase)
                return message
            except Exception as exc:  # noqa: BLE001 - provider SDK exceptions vary
                last_error = exc
                emit_metric("BedrockErrors", 1, phase=phase, errorKind=type(exc).__name__)
                if attempt >= self.transient_retry_attempts:
                    raise BedrockInvocationError(f"Bedrock invocation failed during {phase}: {exc}") from exc
                await asyncio.sleep(0.1 * attempt)
        raise RuntimeError("Bedrock invocation failed") from last_error


class OpenAIPlanner:
    endpoint = "https://api.openai.com/v1/responses"

    def __init__(
        self,
        api_key: str,
        model_id: str,
        max_prompt_bytes: int,
        prompts_dir: str | Path = "",
        timeout_seconds: float = 10.0,
        transient_retry_attempts: int = 2,
    ):
        self.api_key = api_key
        self.model_id = model_id
        self.max_prompt_bytes = max_prompt_bytes
        self.prompts = PromptLoader(prompts_dir or None)
        self.timeout_seconds = timeout_seconds
        self.transient_retry_attempts = max(1, transient_retry_attempts)

    def explain_model(self) -> ExplanationModel:
        return ExplanationModel(
            provider="openai",
            plannerType="openai",
            modelId=self.model_id,
            temperature=None,
            maxPromptBytes=self.max_prompt_bytes,
            promptTemplates={
                name: _template_hash(self.prompts.prompts_dir / name)
                for name in ["triage_system.md.j2", "triage_user.md.j2", "plan_system.md.j2", "plan_user.md.j2"]
            },
        )

    async def triage(self, incident: Incident) -> TriageResult:
        prompt = _bounded(
            self.prompts.render(
                "triage_user.md.j2",
                alarm_name=incident.alarm_name,
                host_id=incident.host_id,
                reason=incident.reason,
            ),
            self.max_prompt_bytes,
        )
        system_prompt = _bounded(self.prompts.render("triage_system.md.j2"), self.max_prompt_bytes)
        text = await self._invoke(system_prompt, prompt, phase="triage")
        return _decode_triage(text)

    async def plan(self, incident: Incident, evidence: list[OperationResult]) -> Plan:
        evidence_json = json.dumps([item.model_dump(by_alias=True) for item in evidence])
        prompt = _bounded(
            self.prompts.render(
                "plan_user.md.j2",
                alarm_name=incident.alarm_name,
                reason=incident.reason,
                host_id=incident.host_id,
                evidence_json=evidence_json,
            ),
            self.max_prompt_bytes,
        )
        system_prompt = _bounded(self.prompts.render("plan_system.md.j2"), self.max_prompt_bytes)
        text = await self._invoke(system_prompt, prompt, phase="plan")
        return Plan.model_validate_json(_strip_fence(text))

    async def _invoke(self, system_prompt: str, prompt: str, phase: str) -> str:
        last_error: Exception | None = None
        payload = {
            "model": self.model_id,
            "input": [
                {
                    "role": "system",
                    "content": [{"type": "input_text", "text": system_prompt}],
                },
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": prompt}],
                },
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        for attempt in range(1, self.transient_retry_attempts + 1):
            started = time.monotonic()
            try:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.post(self.endpoint, headers=headers, json=payload)
                    response.raise_for_status()
                emit_metric("OpenAIRequestLatencyMs", (time.monotonic() - started) * 1000, "Milliseconds", phase=phase)
                return _extract_openai_text(response.json())
            except Exception as exc:  # noqa: BLE001 - provider/API exceptions vary
                last_error = exc
                emit_metric("OpenAIErrors", 1, phase=phase, errorKind=type(exc).__name__)
                if attempt >= self.transient_retry_attempts:
                    raise OpenAIInvocationError(f"OpenAI invocation failed during {phase}: {exc}") from exc
                await asyncio.sleep(0.1 * attempt)
        raise RuntimeError("OpenAI invocation failed") from last_error


class FallbackPlanner:
    def __init__(self, primary: Planner, fallback: Planner) -> None:
        self.primary = primary
        self.fallback = fallback

    def explain_model(self) -> ExplanationModel:
        primary_explainer = getattr(self.primary, "explain_model", None)
        if callable(primary_explainer):
            model = cast(ExplanationModel, primary_explainer())
            model.planner_type = f"{model.planner_type}_with_rule_fallback"
            return model
        return ExplanationModel(provider="hybrid", plannerType="fallback")

    async def triage(self, incident: Incident) -> TriageResult:
        try:
            return await self.primary.triage(incident)
        except ProviderInvocationError as exc:
            emit_metric("ProviderFallbacks", 1, phase="triage", provider=exc.provider)
            return await self.fallback.triage(incident)

    async def plan(self, incident: Incident, evidence: list[OperationResult]) -> Plan:
        try:
            return await self.primary.plan(incident, evidence)
        except ProviderInvocationError as exc:
            emit_metric("ProviderFallbacks", 1, phase="plan", provider=exc.provider)
            return await self.fallback.plan(incident, evidence)


class RuleBasedPlanner:
    def explain_model(self) -> ExplanationModel:
        return ExplanationModel(
            provider="deterministic",
            plannerType="rule_based",
            modelId="rule-based-planner",
            temperature=None,
            maxPromptBytes=0,
            promptTemplates={},
        )

    async def triage(self, incident: Incident) -> TriageResult:
        reason = incident.reason.lower()
        if any(term in reason for term in ["down", "unhealthy", "5xx", "500", "critical"]):
            priority = Priority.HIGH
        else:
            priority = Priority.MEDIUM
        return TriageResult(
            priority=priority,
            category="availability",
            summary=f"{incident.alarm_name} on {incident.host_id}",
            rationale="Deterministic fallback triage based on alarm reason.",
        )

    async def plan(self, incident: Incident, evidence: list[OperationResult]) -> Plan:
        combined = "\n".join(f"{item.stdout}\n{item.stderr}".lower() for item in evidence)
        service_status = "\n".join(
            f"{item.stdout}\n{item.stderr}".lower() for item in evidence if item.operation_id == "service_status"
        )
        health_check = "\n".join(
            f"{item.stdout}\n{item.stderr}".lower() for item in evidence if item.operation_id == "health_check"
        )
        if "unhealthy" in health_check and "active" in service_status:
            return Plan(
                summary="Demo app is active but unhealthy; request approval to recover the demo app.",
                rationale="Diagnostics show the service is active while the health endpoint reports unhealthy.",
                actions=[Action(operationId="recover_demo_app", reason="Demo app health check failed.")],
            )
        if "failed" in combined or "inactive" in combined or "unhealthy" in combined:
            return Plan(
                summary="Service appears unhealthy; request approval to restart the managed service.",
                rationale="Diagnostics include unhealthy service indicators.",
                actions=[Action(operationId="restart_service", reason="Managed service health check failed.")],
            )
        return Plan(
            summary="No remediation proposed.",
            rationale="Diagnostics do not justify the allowed restart operation.",
            actions=[],
        )


def _decode_triage(text: str) -> TriageResult:
    return TriageResult.model_validate_json(_strip_fence(text))


def _strip_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```json"):
        stripped = stripped.removeprefix("```json")
    if stripped.startswith("```"):
        stripped = stripped.removeprefix("```")
    if stripped.endswith("```"):
        stripped = stripped.removesuffix("```")
    return stripped.strip()


def _extract_openai_text(response: dict[str, Any]) -> str:
    output_text = response.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text
    output = response.get("output")
    if not isinstance(output, list):
        raise ValueError("OpenAI response missing output text")
    chunks: list[str] = []
    for item in output:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                chunks.append(str(part["text"]))
    text = "".join(chunks).strip()
    if not text:
        raise ValueError("OpenAI response missing output text")
    return text


def _bounded(prompt: str, max_prompt_bytes: int) -> str:
    if max_prompt_bytes > 0 and len(prompt.encode("utf-8")) > max_prompt_bytes:
        raise ValueError("Planner prompt exceeds configured limit")
    return prompt


def _template_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""
