from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Protocol, cast

import httpx
from boto3.session import Session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from langchain_aws import ChatBedrock
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

from incident_agent.model_trace import TraceSink, span
from incident_agent.models import Action, ExplanationModel, Incident, OperationResult, Plan, Priority, TriageResult
from incident_agent.observability import emit_metric
from incident_agent.planning.catalog import DIAGNOSTIC_OPERATIONS, REMEDIATION_OPERATIONS
from incident_agent.planning.prompt_loader import PromptLoader


class Planner(Protocol):
    """GoF Strategy contract shared by interchangeable triage and plan algorithms."""

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
    direct_endpoint = "https://api.openai.com/v1/responses"

    def __init__(
        self,
        api_key: str,
        model_id: str,
        max_prompt_bytes: int,
        prompts_dir: str | Path = "",
        timeout_seconds: float = 10.0,
        transient_retry_attempts: int = 2,
        *,
        auth_mode: str = "api_key",
        gateway_url: str = "",
        gateway_target: str = "openai",
        aws_region: str = "",
        reasoning_effort: str = "low",
        max_output_tokens: int = 4096,
        aws_session: Session | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        trace_sink: TraceSink | None = None,
    ):
        self.api_key = api_key
        self.model_id = model_id
        self.max_prompt_bytes = max_prompt_bytes
        self.prompts = PromptLoader(prompts_dir or None)
        self.timeout_seconds = timeout_seconds
        self.transient_retry_attempts = max(1, transient_retry_attempts)
        self.auth_mode = auth_mode.strip().lower()
        self.gateway_target = gateway_target.strip()
        self.aws_region = aws_region.strip()
        self.reasoning_effort = reasoning_effort.strip().lower()
        self.max_output_tokens = max_output_tokens
        self.aws_session = aws_session or Session(region_name=self.aws_region or None)
        self.transport = transport
        self.trace_sink = trace_sink
        if self.auth_mode == "aws_iam":
            if not gateway_url.strip() or not self.aws_region:
                raise ValueError("AWS IAM OpenAI mode requires gateway URL and region")
            gateway_origin = gateway_url.rstrip("/").removesuffix("/mcp")
            self.endpoint = gateway_origin + "/inference/v1/responses"
            self.route = f"{self.gateway_target}/{self.model_id}"
        elif self.auth_mode == "api_key":
            if not self.api_key.strip():
                raise ValueError("API-key OpenAI mode requires an API key")
            self.endpoint = self.direct_endpoint
            self.route = self.model_id
        else:
            raise ValueError("Unsupported OpenAI authentication mode")

    def explain_model(self) -> ExplanationModel:
        return ExplanationModel(
            provider="openai",
            plannerType="openai_agentcore" if self.auth_mode == "aws_iam" else "openai",
            modelId=self.model_id,
            awsRegion=self.aws_region,
            gatewayRoute=self.route if self.auth_mode == "aws_iam" else "",
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
        with span(
            self.trace_sink,
            "reasoning",
            incident_id=incident.id,
            stage="triage",
            model=self.model_id,
            prompt_hashes=self.explain_model().prompt_templates,
        ):
            text = await self._invoke(system_prompt, prompt, phase="triage")
            with span(self.trace_sink, "result_validation"):
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
        with span(
            self.trace_sink,
            "reasoning",
            incident_id=incident.id,
            stage="plan",
            model=self.model_id,
            prompt_hashes=self.explain_model().prompt_templates,
        ):
            text = await self._invoke(system_prompt, prompt, phase="plan")
            with span(self.trace_sink, "result_validation"):
                return Plan.model_validate_json(_strip_fence(text))

    async def _invoke(self, system_prompt: str, prompt: str, phase: str) -> str:
        last_error: Exception | None = None
        payload = {
            "model": self.route,
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
            "reasoning": {"effort": self.reasoning_effort},
            "text": {
                "verbosity": "low",
                "format": _openai_response_format(phase),
            },
            "max_output_tokens": self.max_output_tokens,
            "store": False,
        }
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        for attempt in range(1, self.transient_retry_attempts + 1):
            started = time.monotonic()
            try:
                with span(self.trace_sink, "provider_attempt", attempt=attempt, stage=phase) as attempt_span:
                    headers = self._request_headers(body)
                    async with httpx.AsyncClient(timeout=self.timeout_seconds, transport=self.transport) as client:
                        response = await client.post(self.endpoint, headers=headers, content=body)
                        response.raise_for_status()
                    response_data = response.json()
                    duration_ms = (time.monotonic() - started) * 1000
                    emit_metric(
                        "OpenAIRequestLatencyMs",
                        duration_ms,
                        "Milliseconds",
                        phase=phase,
                        provider="openai",
                        model=self.model_id,
                        gatewayRoute=self.route if self.auth_mode == "aws_iam" else "direct",
                    )
                    _emit_openai_token_metrics(response_data, phase)
                    usage = response_data.get("usage") or {}
                    attempt_span.update(
                        returned_model=response_data.get("model"),
                        input_tokens=usage.get("input_tokens"),
                        output_tokens=usage.get("output_tokens"),
                    )
                    return _extract_openai_text(response_data)
            except Exception as exc:  # noqa: BLE001 - provider/API exceptions vary
                last_error = exc
                error_kind = _openai_error_kind(exc)
                emit_metric(
                    "OpenAIErrors",
                    1,
                    phase=phase,
                    provider="openai",
                    model=self.model_id,
                    gatewayRoute=self.route if self.auth_mode == "aws_iam" else "direct",
                    errorKind=error_kind,
                )
                if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 429:
                    emit_metric("AgentCoreGatewayThrottles", 1, phase=phase, provider="openai")
                if isinstance(exc, httpx.HTTPStatusError):
                    status = exc.response.status_code
                    if status not in {408, 429} and not 500 <= status < 600:
                        raise ValueError(f"OpenAI request rejected during {phase} (HTTP{status})") from None
                elif not isinstance(exc, httpx.TransportError) or isinstance(
                    exc, httpx.UnsupportedProtocol | httpx.LocalProtocolError
                ):
                    # Invalid output, credentials and configuration are not availability
                    # failures. Do not turn them into apparently successful rule fallback.
                    raise
                if attempt >= self.transient_retry_attempts:
                    raise OpenAIInvocationError(f"OpenAI invocation failed during {phase} ({error_kind})") from exc
                await asyncio.sleep(0.1 * attempt)
        raise RuntimeError("OpenAI invocation failed") from last_error

    def _request_headers(self, body: bytes) -> dict[str, str]:
        if self.auth_mode == "api_key":
            return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        credentials = self.aws_session.get_credentials()
        if credentials is None:
            raise RuntimeError("AWS credentials are unavailable for AgentCore gateway signing")
        request = AWSRequest(
            method="POST",
            url=self.endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        SigV4Auth(credentials.get_frozen_credentials(), "bedrock-agentcore", self.aws_region).add_auth(request)
        return {str(key): str(value) for key, value in request.headers.items()}


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
            with span(
                getattr(self.primary, "trace_sink", None),
                "deterministic_fallback",
                incident_id=incident.id,
                stage="triage",
                fallback=True,
                outcome="fallback",
            ):
                return await self.fallback.triage(incident)

    async def plan(self, incident: Incident, evidence: list[OperationResult]) -> Plan:
        try:
            return await self.primary.plan(incident, evidence)
        except ProviderInvocationError as exc:
            emit_metric("ProviderFallbacks", 1, phase="plan", provider=exc.provider)
            with span(
                getattr(self.primary, "trace_sink", None),
                "deterministic_fallback",
                incident_id=incident.id,
                stage="plan",
                fallback=True,
                outcome="fallback",
            ):
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
            suggestedDiagnosticOperationIds=["system_overview", "disk_usage", "memory_usage"],
        )

    async def plan(self, incident: Incident, evidence: list[OperationResult]) -> Plan:
        service_status = "\n".join(
            item.stdout.lower() for item in evidence if item.operation_id == "service_status" and item.exit_code >= 0
        )
        health_check = "\n".join(
            item.stdout.lower() for item in evidence if item.operation_id == "health_check" and item.exit_code >= 0
        )
        unhealthy = bool(re.search(r"\bunhealthy\b", health_check))
        inactive = bool(re.search(r"\b(inactive|failed)\b", service_status))
        active = bool(re.search(r"\bactive\b", service_status)) and not inactive
        if unhealthy and active:
            return Plan(
                summary="Demo app is active but unhealthy; request approval to recover the demo app.",
                rationale="Diagnostics show the service is active while the health endpoint reports unhealthy.",
                actions=[Action(operationId="recover_demo_app", reason="Demo app health check failed.")],
            )
        if inactive or unhealthy:
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


def _openai_response_format(phase: str) -> dict[str, Any]:
    if phase == "triage":
        schema = {
            "type": "object",
            "properties": {
                "priority": {"type": "string", "enum": [item.value for item in Priority]},
                "category": {"type": "string"},
                "summary": {"type": "string"},
                "rationale": {"type": "string"},
                "suggestedDiagnosticOperationIds": {
                    "type": "array",
                    "items": {"type": "string", "enum": DIAGNOSTIC_OPERATIONS},
                    "maxItems": 5,
                },
            },
            "required": [
                "priority",
                "category",
                "summary",
                "rationale",
                "suggestedDiagnosticOperationIds",
            ],
            "additionalProperties": False,
        }
    elif phase == "plan":
        schema = {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "rationale": {"type": "string"},
                "actions": {
                    "type": "array",
                    "maxItems": 1,
                    "items": {
                        "type": "object",
                        "properties": {
                            "operationId": {"type": "string", "enum": REMEDIATION_OPERATIONS},
                            "reason": {"type": "string"},
                        },
                        "required": ["operationId", "reason"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["summary", "rationale", "actions"],
            "additionalProperties": False,
        }
    else:
        raise ValueError("Unsupported OpenAI response phase")
    return {
        "type": "json_schema",
        "name": f"incident_{phase}",
        "description": "Bounded DenDenMushi incident analysis output.",
        "schema": schema,
        "strict": True,
    }


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


def _emit_openai_token_metrics(response: dict[str, Any], phase: str) -> None:
    usage = response.get("usage")
    if not isinstance(usage, dict):
        return
    for field, token_type in (
        ("input_tokens", "input"),
        ("output_tokens", "output"),
        ("total_tokens", "total"),
    ):
        value = usage.get(field)
        if isinstance(value, int | float) and value >= 0:
            emit_metric("OpenAITokens", float(value), "Count", phase=phase, tokenType=token_type)


def _openai_error_kind(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP{exc.response.status_code}"
    return type(exc).__name__


def _bounded(prompt: str, max_prompt_bytes: int) -> str:
    if max_prompt_bytes > 0 and len(prompt.encode("utf-8")) > max_prompt_bytes:
        raise ValueError("Planner prompt exceeds configured limit")
    return prompt


def _template_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""
