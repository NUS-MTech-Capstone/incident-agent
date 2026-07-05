from __future__ import annotations

import pytest

from incident_agent.models import IncidentState, OperationResult, Plan
from incident_agent.persistence.store import Conflict, IncidentStore
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
    assert incident.state == IncidentState.COMPLETED
    assert incident.plan.actions == []
    assert ddm.started
    assert ddm.closed
    metrics = capsys.readouterr().out
    assert "IncidentReceived" in metrics
    assert "IncidentTriaged" in metrics
    assert "EvidenceCollected" in metrics
    assert "PlanProposed" in metrics


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
    assert incident.state == IncidentState.AWAITING_APPROVAL
    assert incident.plan_hash == plan_hash(plan)

    service.approve(incident.id, incident.plan_hash, "user-1")
    await service.execute(incident.id, incident.plan_hash)

    completed = store.get(incident.id)
    assert completed.state == IncidentState.COMPLETED
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
    assert failed.state == IncidentState.FAILED
    assert "RemediationFailed" in capsys.readouterr().out
