from __future__ import annotations

from typing import Any

from incident_agent.models import IncidentEventType, OperationResult
from incident_agent.trace import IncidentTraceRecorder


class RecordingEventStore:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def create_event(
        self,
        incident_id: str,
        event_type: IncidentEventType,
        alert_id: str = "",
        actor: str = "",
        message: str = "",
        metadata: dict[str, object] | None = None,
    ) -> object:
        event = {
            "incidentId": incident_id,
            "eventType": event_type,
            "alertId": alert_id,
            "actor": actor,
            "message": message,
            "metadata": metadata or {},
        }
        self.events.append(event)
        return event


def test_trace_recorder_persists_safe_success_failure_and_fallback_metadata() -> None:
    store = RecordingEventStore()
    recorder = IncidentTraceRecorder(store)

    recorder.agent_action("inc-1", "triage", "SUCCEEDED", "Structured triage completed.", 12.5, False, "MODEL_ASSISTED")
    recorder.agent_action(
        "inc-1", "plan", "FALLBACK", "Deterministic plan fallback completed.", 20, True, "DETERMINISTIC"
    )
    recorder.agent_action("inc-1", "plan", "FAILED", "Structured planning failed safely.", 8, False, "MODEL_ASSISTED")
    recorder.tool_call(
        "inc-1",
        "health_check",
        "diagnose",
        "policy",
        "Mandatory bounded diagnostic.",
        OperationResult(operationId="health_check", stdout="token=secret", stderr="password=hunter2", exitCode=1),
        4.5,
        True,
    )

    assert [event["eventType"] for event in store.events] == [
        IncidentEventType.AGENT_DELEGATED,
        IncidentEventType.AGENT_DELEGATED,
        IncidentEventType.AGENT_DELEGATED,
        IncidentEventType.OPERATION_EXECUTED,
    ]
    success, fallback, failed, tool = store.events
    assert success["metadata"]["protocol"] == "a2a"
    assert success["metadata"]["toAgent"] == "Triage Agent"
    assert fallback["metadata"]["protocol"] == "local_fallback"
    assert fallback["metadata"]["toAgent"] == "Deterministic Fallback Planner"
    assert failed["metadata"]["status"] == "FAILED"
    assert tool["metadata"]["status"] == "FAILED"
    assert tool["metadata"]["exitCode"] == 1
    assert str(tool["metadata"]["resultDigest"]).startswith("sha256:")

    serialized = str(store.events)
    assert "token=secret" not in serialized
    assert "hunter2" not in serialized
    assert "stdout" not in tool["metadata"]
    assert "stderr" not in tool["metadata"]
