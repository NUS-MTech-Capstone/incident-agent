from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path
from typing import Protocol

from langchain_aws import ChatBedrock
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

from incident_agent.models import Action, ExplanationModel, Incident, OperationResult, Plan, Priority, TriageResult
from incident_agent.observability import emit_metric
from incident_agent.planning.prompt_loader import PromptLoader
from incident_agent.planning.supervisor import validate_plan


class Planner(Protocol):
    async def triage(self, incident: Incident) -> TriageResult: ...

    async def plan(self, incident: Incident, evidence: list[OperationResult]) -> Plan: ...


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
        plan = Plan.model_validate_json(_strip_fence(str(message.content)))
        return validate_plan(plan)

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
                    raise
                await asyncio.sleep(0.1 * attempt)
        raise RuntimeError("Bedrock invocation failed") from last_error


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
            return validate_plan(
                Plan(
                    summary="Demo app is active but unhealthy; request approval to recover the demo app.",
                    rationale="Diagnostics show the service is active while the health endpoint reports unhealthy.",
                    actions=[Action(operationId="recover_demo_app", reason="Demo app health check failed.")],
                )
            )
        if "failed" in combined or "inactive" in combined or "unhealthy" in combined:
            return validate_plan(
                Plan(
                    summary="Service appears unhealthy; request approval to restart the managed service.",
                    rationale="Diagnostics include unhealthy service indicators.",
                    actions=[Action(operationId="restart_service", reason="Managed service health check failed.")],
                )
            )
        return validate_plan(
            Plan(
                summary="No remediation proposed.",
                rationale="Diagnostics do not justify the allowed restart operation.",
                actions=[],
            )
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


def _bounded(prompt: str, max_prompt_bytes: int) -> str:
    if max_prompt_bytes > 0 and len(prompt.encode("utf-8")) > max_prompt_bytes:
        raise ValueError("Bedrock prompt exceeds configured limit")
    return prompt


def _template_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""
