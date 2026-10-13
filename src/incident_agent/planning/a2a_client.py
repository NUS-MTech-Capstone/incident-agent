from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any

import httpx
from a2a.client import ClientConfig, create_client
from a2a.helpers import new_data_message
from a2a.types import Role, SendMessageRequest, TaskState
from google.protobuf.json_format import MessageToDict

from incident_agent.identity import read_workload_token
from incident_agent.models import ExplanationModel, Incident, OperationResult, Plan, TriageResult
from incident_agent.observability import emit_metric, log_event
from incident_agent.planning.planner import Planner
from incident_agent.redact import text as redact_text
from incident_agent.trace import TraceRecorder

logger = logging.getLogger(__name__)


class A2AAvailabilityError(RuntimeError):
    pass


class A2AProtocolError(RuntimeError):
    pass


class A2APlanner:
    """GoF Adapter from the local Planner contract to A2A messages and artifacts.

    Domain inputs are sanitized before transport; returned artifacts are validated
    as domain results. Protocol rejection remains distinct from availability fallback.
    """

    def __init__(
        self,
        base_url: str,
        workload_token_file: str,
        fallback: Planner,
        timeout_seconds: float,
        transient_retry_attempts: int,
        model_id: str,
        region: str,
        provider: str | None = None,
        gateway_route: str = "",
        trace_recorder: TraceRecorder | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.workload_token_file = workload_token_file
        self.fallback = fallback
        self.timeout_seconds = timeout_seconds
        self.transient_retry_attempts = max(1, transient_retry_attempts)
        self.model_id = model_id
        self.region = region
        self.provider = provider or "bedrock"
        self.gateway_route = gateway_route
        self.trace_recorder = trace_recorder

    def explain_model(self) -> ExplanationModel:
        return ExplanationModel(
            provider=f"a2a-{self.provider}",
            plannerType=f"a2a_{self.provider.replace('-', '_')}_reasoning_agent_with_rule_fallback",
            modelId=self.model_id,
            awsRegion=self.region,
            gatewayRoute=self.gateway_route,
        )

    async def triage(self, incident: Incident) -> TriageResult:
        started = time.monotonic()
        try:
            payload = await self._invoke(
                "triage",
                {"incident": _sanitized_incident(incident)},
                incident.id,
            )
            result = TriageResult.model_validate(payload)
        except A2AAvailabilityError:
            emit_metric("A2AFallbacks", 1, phase="triage")
            try:
                result = await self.fallback.triage(incident)
            except Exception:
                self._record_action(
                    incident.id,
                    "triage",
                    "FAILED",
                    "Reasoning Agent and deterministic triage fallback failed.",
                    started,
                    True,
                    "DETERMINISTIC",
                )
                raise
            self._record_action(
                incident.id,
                "triage",
                "FALLBACK",
                "Reasoning Agent was unavailable; deterministic triage fallback completed.",
                started,
                True,
                "DETERMINISTIC",
            )
            return result
        except Exception:
            self._record_action(
                incident.id,
                "triage",
                "FAILED",
                "Reasoning Agent rejected or failed the structured triage handoff.",
                started,
                False,
                "MODEL_ASSISTED",
            )
            raise
        self._record_action(
            incident.id,
            "triage",
            "SUCCEEDED",
            "Reasoning Agent completed structured incident triage.",
            started,
            False,
            "MODEL_ASSISTED",
        )
        return result

    async def plan(self, incident: Incident, evidence: list[OperationResult]) -> Plan:
        started = time.monotonic()
        try:
            payload = await self._invoke(
                "plan",
                {
                    "incident": _sanitized_incident(incident),
                    "evidence": [_sanitized_evidence(item) for item in evidence],
                },
                incident.id,
            )
            result = Plan.model_validate(payload)
        except A2AAvailabilityError:
            emit_metric("A2AFallbacks", 1, phase="plan")
            try:
                result = await self.fallback.plan(incident, evidence)
            except Exception:
                self._record_action(
                    incident.id,
                    "plan",
                    "FAILED",
                    "Reasoning Agent and deterministic plan fallback failed.",
                    started,
                    True,
                    "DETERMINISTIC",
                )
                raise
            self._record_action(
                incident.id,
                "plan",
                "FALLBACK",
                "Reasoning Agent was unavailable; deterministic plan fallback completed.",
                started,
                True,
                "DETERMINISTIC",
            )
            return result
        except Exception:
            self._record_action(
                incident.id,
                "plan",
                "FAILED",
                "Reasoning Agent rejected or failed the structured planning handoff.",
                started,
                False,
                "MODEL_ASSISTED",
            )
            raise
        self._record_action(
            incident.id,
            "plan",
            "SUCCEEDED",
            "Reasoning Agent completed the structured remediation proposal.",
            started,
            False,
            "MODEL_ASSISTED",
        )
        return result

    def _record_action(
        self,
        incident_id: str,
        stage: str,
        status: str,
        summary: str,
        started: float,
        fallback_used: bool,
        actor_type: str,
    ) -> None:
        if self.trace_recorder is None:
            return
        self.trace_recorder.agent_action(
            incident_id,
            stage,
            status,
            summary,
            (time.monotonic() - started) * 1000,
            fallback_used,
            actor_type,
        )

    async def _invoke(self, stage: str, data: dict[str, Any], incident_id: str) -> dict[str, Any]:
        request_started = time.monotonic()
        last_error: Exception | None = None
        for attempt in range(1, self.transient_retry_attempts + 1):
            started = time.monotonic()
            try:
                task_id, result = await self._send({"stage": stage, **data})
                emit_metric("A2ARequestLatencyMs", (time.monotonic() - started) * 1000, "Milliseconds", stage=stage)
                log_event(
                    logger,
                    "AgentDelegated",
                    incidentId=incident_id,
                    a2aTaskId=task_id,
                    stage=stage,
                    outcome="completed",
                    fallback=False,
                    durationMs=round((time.monotonic() - started) * 1000, 2),
                )
                return result
            except A2AProtocolError:
                raise
            except Exception as exc:  # noqa: BLE001 - SDK transport exceptions vary
                last_error = exc
                if _is_fail_closed_error(exc):
                    raise A2AProtocolError("A2A request was rejected") from exc
                if attempt >= self.transient_retry_attempts:
                    break
                await asyncio.sleep(0.1 * attempt)
        log_event(
            logger,
            "AgentDelegated",
            incidentId=incident_id,
            a2aTaskId="",
            stage=stage,
            outcome="fallback",
            fallback=True,
            durationMs=round((time.monotonic() - request_started) * 1000, 2),
            errorKind=type(last_error).__name__ if last_error else "Unknown",
        )
        raise A2AAvailabilityError("reasoning agent is unavailable") from last_error

    async def _send(self, payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        token = read_workload_token(self.workload_token_file)
        timeout = httpx.Timeout(self.timeout_seconds)
        async with httpx.AsyncClient(
            timeout=timeout,
            headers={"Authorization": f"Bearer {token}"},
        ) as http_client:
            config = ClientConfig(
                streaming=True,
                httpx_client=http_client,
                supported_protocol_bindings=["JSONRPC"],
            )
            client = await create_client(self.base_url, client_config=config)
            task_id = ""
            result: dict[str, Any] | None = None
            request = SendMessageRequest(
                message=new_data_message(payload, media_type="application/json", role=Role.ROLE_USER)
            )
            try:
                async for event in client.send_message(request):
                    if event.HasField("task"):
                        task_id = event.task.id
                    elif event.HasField("artifact_update"):
                        task_id = task_id or event.artifact_update.task_id
                        for part in event.artifact_update.artifact.parts:
                            if part.HasField("data"):
                                result = MessageToDict(part.data)
                    elif event.HasField("status_update"):
                        state = event.status_update.status.state
                        if state in {
                            TaskState.TASK_STATE_FAILED,
                            TaskState.TASK_STATE_REJECTED,
                            TaskState.TASK_STATE_CANCELED,
                        }:
                            raise A2AProtocolError("reasoning agent rejected the task")
            finally:
                await client.close()
        if result is None:
            raise A2AProtocolError("reasoning agent returned no structured artifact")
        return task_id or uuid.uuid4().hex, result


def _sanitized_incident(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "source_id": incident.source_id,
        "alarm_arn": incident.alarm_arn,
        "alarm_name": incident.alarm_name,
        "host_id": incident.host_id,
        "runbook_version": incident.runbook_version,
        "state": incident.state.value,
        "reason": redact_text(incident.reason, 4096),
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
    }


def _sanitized_evidence(result: OperationResult) -> dict[str, Any]:
    return {
        "operationId": result.operation_id,
        "stdout": redact_text(result.stdout, 262144),
        "stderr": redact_text(result.stderr, 262144),
        "exitCode": result.exit_code,
    }


def _is_fail_closed_error(exc: Exception) -> bool:
    message = str(exc).lower()
    failure_markers = ["http error 400", "http error 401", "http error 403", "invalid", "rejected"]
    return any(value in message for value in failure_markers)
