from __future__ import annotations

import hashlib
import json
from typing import Protocol

from incident_agent.models import IncidentEventType, OperationResult


class EventStore(Protocol):
    def create_event(
        self,
        incident_id: str,
        event_type: IncidentEventType,
        alert_id: str = "",
        actor: str = "",
        message: str = "",
        metadata: dict[str, object] | None = None,
    ) -> object: ...


class TraceRecorder(Protocol):
    def agent_action(
        self,
        incident_id: str,
        stage: str,
        status: str,
        summary: str,
        duration_ms: float,
        fallback_used: bool,
        actor_type: str,
    ) -> None: ...

    def tool_call(
        self,
        incident_id: str,
        operation_id: str,
        phase: str,
        selected_by: str,
        reason: str,
        result: OperationResult,
        duration_ms: float,
        output_truncated: bool,
    ) -> None: ...


class IncidentTraceRecorder:
    def __init__(self, store: EventStore):
        self.store = store

    def agent_action(
        self,
        incident_id: str,
        stage: str,
        status: str,
        summary: str,
        duration_ms: float,
        fallback_used: bool,
        actor_type: str,
    ) -> None:
        if fallback_used:
            to_agent = "Deterministic Fallback Planner"
            protocol = "local_fallback"
        else:
            to_agent = "Triage Agent" if stage == "triage" else "Action Plan Agent"
            protocol = "a2a"
        self.store.create_event(
            incident_id,
            IncidentEventType.AGENT_DELEGATED,
            message=summary,
            metadata={
                "stage": stage,
                "fromAgent": "Incident Manager Agent",
                "toAgent": to_agent,
                "protocol": protocol,
                "actorType": actor_type,
                "status": status,
                "durationMs": round(duration_ms, 2),
                "fallbackUsed": fallback_used,
            },
        )

    def tool_call(
        self,
        incident_id: str,
        operation_id: str,
        phase: str,
        selected_by: str,
        reason: str,
        result: OperationResult,
        duration_ms: float,
        output_truncated: bool,
    ) -> None:
        status = "SUCCEEDED" if result.exit_code == 0 else "FAILED"
        payload = json.dumps(
            result.model_dump(by_alias=True),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.store.create_event(
            incident_id,
            IncidentEventType.OPERATION_EXECUTED,
            message="Bounded diagnostic operation executed.",
            metadata={
                "operationId": operation_id,
                "phase": phase,
                "selectedBy": selected_by,
                "reason": reason,
                "status": status,
                "durationMs": round(duration_ms, 2),
                "exitCode": result.exit_code,
                "resultDigest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
                "outputTruncated": output_truncated,
            },
        )
