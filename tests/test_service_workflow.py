from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from incident_agent.models import AlertStatus, ApprovalOutcome, IncidentEventType, IncidentState, OperationResult, Plan
from incident_agent.persistence.store import Conflict, IncidentStore, incidents
from incident_agent.planning.supervisor import plan_hash
from tests.conftest import FakeDDM, StaticPlanner, alert, make_service


@pytest.mark.asyncio
async def test_full_workflow_no_action_completes_and_closes(
    store: IncidentStore, capsys: pytest.CaptureFixture[str]
) -> None:
    ddm = FakeDDM()
    service = make_service(
        store,
        ddm,
        StaticPlanner(Plan(summary="No action", rationale="Evidence does not justify restart", actions=[])),
    )
    await service.handle_alert(alert())
    incident = store.list()[0]
    managed_alert = store.list_alerts()[0]
    assert incident.state == IncidentState.COMPLETED
    assert incident.triage is not None
    assert incident.triage.summary == "service unhealthy"
    assert managed_alert.status == AlertStatus.TRIAGED
    assert managed_alert.incident_id == incident.id
    assert incident.plan.actions == []
    assert ddm.started
    assert ddm.closed
    metrics = capsys.readouterr().out
    assert "IncidentReceived" in metrics
    assert "IncidentTriaged" in metrics
    assert "EvidenceCollected" in metrics
    assert "PlanProposed" in metrics
    events = store.list_events(incident.id)
    assert [event.event_type for event in events] == [
        IncidentEventType.ALERT_RECEIVED,
        IncidentEventType.INCIDENT_CREATED,
        IncidentEventType.AGENT_TRIAGED,
        IncidentEventType.EVIDENCE_COLLECTED,
        IncidentEventType.PLAN_PROPOSED,
    ]


@pytest.mark.asyncio
async def test_full_workflow_restart_approval_execution(
    store: IncidentStore, capsys: pytest.CaptureFixture[str]
) -> None:
    ddm = FakeDDM(
        {
            "service_status": OperationResult(operationId="service_status", stdout="active", exitCode=0),
            "health_check": OperationResult(operationId="health_check", stdout="ok", exitCode=0),
            "restart_service": OperationResult(operationId="restart_service", stdout="restarted", exitCode=0),
        }
    )
    plan = Plan(
        summary="Restart managed service",
        rationale="Service health is failed",
        actions=[{"operationId": "restart_service", "reason": "health_check failed"}],
    )
    service = make_service(store, ddm, StaticPlanner(plan))
    await service.handle_alert(alert())
    incident = store.list()[0]
    managed_alert = store.list_alerts()[0]
    assert incident.state == IncidentState.AWAITING_APPROVAL
    assert managed_alert.status == AlertStatus.PENDING_APPROVAL
    assert incident.plan_hash == plan_hash(plan)

    service.approve(incident.id, incident.plan_hash, "user-1")
    assert store.list_alerts()[0].status == AlertStatus.EXECUTING
    await service.execute(incident.id, incident.plan_hash)

    completed = store.get(incident.id)
    completed_alert = store.list_alerts()[0]
    assert completed.state == IncidentState.COMPLETED
    assert completed_alert.status == AlertStatus.RESOLVED
    assert completed.post_incident_report.final_state == IncidentState.COMPLETED.value
    assert completed.post_incident_report.action_taken == "restart_service exit=0"
    assert [item.outcome for item in store.list_approval_decisions(incident.id)] == [ApprovalOutcome.SUCCEEDED]
    event_types = [event.event_type for event in store.list_events(incident.id)]
    assert IncidentEventType.PLAN_APPROVED in event_types
    assert IncidentEventType.REMEDIATION_STARTED in event_types
    assert IncidentEventType.VERIFICATION_PASSED in event_types
    assert ("restart_service", incident.plan_hash) in ddm.executed
    assert ddm.closed[-1] == ("run-1", "verify-token")
    metrics = capsys.readouterr().out
    assert "PlanApproved" in metrics
    assert "RemediationExecuted" in metrics


def test_approval_hash_mismatch_is_conflict(store: IncidentStore) -> None:
    incident = store.create(alert())
    plan = Plan(
        summary="Restart managed service",
        rationale="Service health is failed",
        actions=[{"operationId": "restart_service", "reason": "health_check failed"}],
    )
    store.set_diagnosis(incident.id, "run-1", "http://dataplane", [], plan, plan_hash(plan))
    with pytest.raises(Conflict):
        store.approve(incident.id, "changed", "user-1")


@pytest.mark.asyncio
async def test_duplicate_active_alarm_groups_into_existing_incident(store: IncidentStore) -> None:
    ddm = FakeDDM()
    plan = Plan(
        summary="Restart managed service",
        rationale="Service health is failed",
        actions=[{"operationId": "restart_service", "reason": "health_check failed"}],
    )
    service = make_service(store, ddm, StaticPlanner(plan))

    await service.handle_alert(alert(source_id="alarm-state-1"))
    await service.handle_alert(alert(source_id="alarm-state-2"))

    incidents_list = store.list()
    alerts = store.list_alerts()
    assert len(incidents_list) == 1
    assert len(alerts) == 2
    assert any(item.grouped for item in alerts)
    assert all(item.incident_id == incidents_list[0].id for item in alerts)
    assert len(ddm.started) == 1
    assert IncidentEventType.ALERT_GROUPED in [event.event_type for event in store.list_events(incidents_list[0].id)]


@pytest.mark.asyncio
async def test_expired_plan_decision_is_conflict_and_audited(store: IncidentStore) -> None:
    ddm = FakeDDM()
    plan = Plan(
        summary="Restart managed service",
        rationale="Service health is failed",
        actions=[{"operationId": "restart_service", "reason": "health_check failed"}],
    )
    service = make_service(store, ddm, StaticPlanner(plan))
    await service.handle_alert(alert())
    incident = store.list()[0]
    with store.engine.begin() as conn:
        conn.execute(
            incidents.update()
            .where(incidents.c.id == incident.id)
            .values(plan_expires_at=datetime.now(UTC) - timedelta(minutes=1))
        )

    with pytest.raises(Conflict, match="plan expired"):
        service.approve(incident.id, incident.plan_hash, "manager-1")

    decisions = store.list_approval_decisions(incident.id)
    assert decisions[0].outcome == ApprovalOutcome.CONFLICT
    assert decisions[0].error_reason == "plan expired"
    assert IncidentEventType.PLAN_EXPIRED in [event.event_type for event in store.list_events(incident.id)]


@pytest.mark.asyncio
async def test_failed_diagnostic_becomes_bounded_evidence(
    store: IncidentStore, capsys: pytest.CaptureFixture[str]
) -> None:
    class FailingDDM(FakeDDM):
        async def execute(self, *args: object, **kwargs: object) -> OperationResult:
            raise RuntimeError("boom")

    ddm = FailingDDM()
    service = make_service(
        store,
        ddm,
        StaticPlanner(Plan(summary="No action", rationale="No reliable remediation evidence", actions=[])),
    )
    await service.handle_alert(alert())
    incident = store.list()[0]
    assert incident.evidence
    assert all(result.exit_code == -1 for result in incident.evidence)
    assert "boom" in incident.evidence[0].stderr
    assert "EvidenceCollected" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_reject_emits_metric(store: IncidentStore, capsys: pytest.CaptureFixture[str]) -> None:
    ddm = FakeDDM()
    plan = Plan(
        summary="Restart managed service",
        rationale="Service health is failed",
        actions=[{"operationId": "restart_service", "reason": "health_check failed"}],
    )
    service = make_service(store, ddm, StaticPlanner(plan))
    await service.handle_alert(alert())
    incident = store.list()[0]

    service.reject(incident.id, incident.plan_hash, "user-1")

    assert store.list_alerts()[0].status == AlertStatus.REJECTED
    assert "PlanRejected" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_remediation_failure_emits_metric(store: IncidentStore, capsys: pytest.CaptureFixture[str]) -> None:
    ddm = FakeDDM({"restart_service": OperationResult(operationId="restart_service", stderr="failed", exitCode=1)})
    plan = Plan(
        summary="Restart managed service",
        rationale="Service health is failed",
        actions=[{"operationId": "restart_service", "reason": "health_check failed"}],
    )
    service = make_service(store, ddm, StaticPlanner(plan))
    await service.handle_alert(alert())
    incident = store.list()[0]
    store.approve(incident.id, incident.plan_hash, "user-1")

    await service.execute(incident.id, incident.plan_hash)

    failed = store.get(incident.id)
    failed_alert = store.list_alerts()[0]
    assert failed.state == IncidentState.FAILED
    assert failed_alert.status == AlertStatus.FAILED
    assert "RemediationFailed" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_ok_alarm_marks_open_incident_and_alert_resolved(store: IncidentStore) -> None:
    ddm = FakeDDM()
    plan = Plan(
        summary="Restart managed service",
        rationale="Service health is failed",
        actions=[{"operationId": "restart_service", "reason": "health_check failed"}],
    )
    service = make_service(store, ddm, StaticPlanner(plan))
    await service.handle_alert(alert(source_id="alarm-state", state="ALARM"))
    incident = store.list()[0]

    await service.handle_alert(alert(source_id="ok-state", state="OK"))

    recovered = store.get(incident.id)
    alerts = store.list_alerts()
    assert recovered.state == IncidentState.RECOVERED
    assert recovered.post_incident_report.final_state == IncidentState.RECOVERED.value
    assert {item.status for item in alerts} == {AlertStatus.RESOLVED}
    assert any(item.incident_id == incident.id for item in alerts)
    assert IncidentEventType.INCIDENT_RECOVERED in [event.event_type for event in store.list_events(incident.id)]
