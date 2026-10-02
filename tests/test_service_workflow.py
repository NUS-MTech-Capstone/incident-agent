from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from incident_agent.models import (
    AlertStatus,
    ApprovalOutcome,
    Incident,
    IncidentEventType,
    IncidentState,
    OperationResult,
    Plan,
)
from incident_agent.persistence.store import ClaimDisposition, Conflict, IncidentStore, incidents
from incident_agent.planning.agents import (
    ACTION_PLAN_AGENT,
    ACTION_PLAN_REVIEWER_AGENT,
    EVIDENCE_COLLECTOR_AGENT,
    INCIDENT_MANAGER_AGENT,
    REMEDIATION_EXECUTOR_AGENT,
    TRIAGE_AGENT,
)
from incident_agent.planning.catalog import REQUIRED_DIAGNOSTIC_OPERATIONS
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
    assert ddm.started[0][2] == REQUIRED_DIAGNOSTIC_OPERATIONS
    assert [item.operation_id for item in incident.evidence] == REQUIRED_DIAGNOSTIC_OPERATIONS
    assert incident.explanation.model.planner_type == "rule_based"
    assert incident.explanation.workflow.catalog_version == "v1"
    assert incident.explanation.workflow.diagnostic_operations == REQUIRED_DIAGNOSTIC_OPERATIONS
    assert [agent.name for agent in incident.explanation.agents] == [
        INCIDENT_MANAGER_AGENT,
        TRIAGE_AGENT,
        EVIDENCE_COLLECTOR_AGENT,
        ACTION_PLAN_AGENT,
        ACTION_PLAN_REVIEWER_AGENT,
        REMEDIATION_EXECUTOR_AGENT,
    ]
    assert all(agent.purpose and agent.reasoning_type and agent.memory for agent in incident.explanation.agents)
    assert any(agent.tools for agent in incident.explanation.agents)
    assert any(
        decision.operation_id == "service_status" and decision.chosen_by == "policy"
        for decision in incident.explanation.tool_decisions
    )
    explanation_json = incident.explanation.model_dump_json()
    assert "diagnose-token" not in explanation_json
    assert "SystemMessage" not in explanation_json
    assert "HumanMessage" not in explanation_json
    assert "terminal stream" not in explanation_json.lower()
    assert ddm.closed
    metrics = capsys.readouterr().out
    assert "IncidentReceived" in metrics
    assert "IncidentTriaged" in metrics
    assert "EvidenceCollected" in metrics
    assert "PlanProposed" in metrics
    events = store.list_events(incident.id)
    event_types = [event.event_type for event in events]
    assert event_types == [
        IncidentEventType.ALERT_RECEIVED,
        IncidentEventType.INCIDENT_CREATED,
        IncidentEventType.OPERATION_EXECUTED,
        IncidentEventType.OPERATION_EXECUTED,
        IncidentEventType.AGENT_TRIAGED,
        IncidentEventType.EVIDENCE_COLLECTED,
        IncidentEventType.PLAN_PROPOSED,
    ]
    tool_events = [event for event in events if event.event_type == IncidentEventType.OPERATION_EXECUTED]
    assert [event.metadata["operationId"] for event in tool_events] == REQUIRED_DIAGNOSTIC_OPERATIONS
    assert all(event.metadata["phase"] == "diagnose" for event in tool_events)
    assert all(event.metadata["status"] == "SUCCEEDED" for event in tool_events)
    assert all(str(event.metadata["resultDigest"]).startswith("sha256:") for event in tool_events)
    assert all("stdout" not in event.metadata and "stderr" not in event.metadata for event in tool_events)


@pytest.mark.asyncio
async def test_failed_diagnostic_attempt_keeps_sanitized_trace_metadata(store: IncidentStore) -> None:
    class FailingDiagnosticDDM(FakeDDM):
        async def execute(self, run_id: str, operation_id: str, plan_hash: str = "") -> OperationResult:
            if operation_id == "health_check":
                raise RuntimeError("token=secret unrestricted diagnostic failure")
            return await super().execute(run_id, operation_id, plan_hash)

    service = make_service(
        store,
        FailingDiagnosticDDM(),
        StaticPlanner(Plan(summary="No action", rationale="Diagnostic failure requires review", actions=[])),
    )

    await service.handle_alert(alert())

    incident = store.list()[0]
    events = store.list_events(incident.id)
    failed = next(
        event
        for event in events
        if event.event_type == IncidentEventType.OPERATION_EXECUTED and event.metadata["operationId"] == "health_check"
    )
    assert failed.metadata["status"] == "FAILED"
    assert failed.metadata["exitCode"] == -1
    assert str(failed.metadata["resultDigest"]).startswith("sha256:")
    assert failed.metadata["outputTruncated"] is False
    assert "stdout" not in failed.metadata and "stderr" not in failed.metadata
    assert "secret" not in failed.model_dump_json()


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
    assert ddm.closed[-1] == "run-1"
    metrics = capsys.readouterr().out
    assert "PlanApproved" in metrics
    assert "RemediationExecuted" in metrics


@pytest.mark.asyncio
async def test_execution_scopes_token_to_approved_catalog_operation(store: IncidentStore) -> None:
    ddm = FakeDDM(
        {
            "recover_demo_app": OperationResult(operationId="recover_demo_app", stdout="recovered", exitCode=0),
            "service_status": OperationResult(operationId="service_status", stdout="active", exitCode=0),
            "health_check": OperationResult(operationId="health_check", stdout="ok", exitCode=0),
        }
    )
    plan = Plan(
        summary="Recover demo app",
        rationale="Service is active but unhealthy",
        actions=[{"operationId": "recover_demo_app", "reason": "health_check failed"}],
    )
    service = make_service(store, ddm, StaticPlanner(plan))
    await service.handle_alert(alert())
    incident = store.list()[0]

    service.approve(incident.id, incident.plan_hash, "user-1")
    await service.execute(incident.id, incident.plan_hash)

    assert ("recover_demo_app", incident.plan_hash) in ddm.executed
    assert store.get(incident.id).post_incident_report.action_taken == "recover_demo_app exit=0"


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
async def test_concurrent_alerts_for_same_group_start_one_workflow(store: IncidentStore) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    class BlockingPlanner(StaticPlanner):
        async def triage(self, incident: Incident):  # type: ignore[no-untyped-def]
            entered.set()
            await release.wait()
            return await super().triage(incident)

    ddm = FakeDDM()
    planner = BlockingPlanner(Plan(summary="No action", rationale="No remediation required", actions=[]))
    service = make_service(store, ddm, planner)

    first = asyncio.create_task(service.handle_alert(alert(source_id="alarm-state-1")))
    await entered.wait()
    second_result = await service.handle_alert(alert(source_id="alarm-state-2"))
    release.set()
    first_result = await first

    assert first_result == ClaimDisposition.PROCESS
    assert second_result == ClaimDisposition.GROUPED
    assert len(store.list()) == 1
    assert len(store.list_alerts()) == 2
    assert len(ddm.started) == 1


def test_same_source_redelivery_waits_for_live_claim_and_reclaims_expired_claim(store: IncidentStore) -> None:
    source = alert()
    first = store.ingest_and_claim(source, "worker-1", timedelta(minutes=2))
    busy = store.ingest_and_claim(source, "worker-2", timedelta(minutes=2))

    assert first.disposition == ClaimDisposition.PROCESS
    assert busy.disposition == ClaimDisposition.RETRY_BUSY

    with store.engine.begin() as conn:
        conn.execute(
            incidents.update()
            .where(incidents.c.id == first.incident.id)
            .values(processing_lease_expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
    reclaimed = store.ingest_and_claim(source, "worker-2", timedelta(minutes=2))

    assert reclaimed.disposition == ClaimDisposition.PROCESS
    assert reclaimed.reclaimed
    assert reclaimed.claim_token != first.claim_token
    assert store.processing_attempt(first.incident.id) == 2
    assert not store.renew_claim(first.incident.id, first.claim_token, timedelta(minutes=2))
    with pytest.raises(Conflict):
        store.set_diagnosis(
            first.incident.id,
            "run-stale",
            "http://dataplane",
            [],
            Plan(summary="No action", rationale="stale", actions=[]),
            "stale-hash",
            claim_token=first.claim_token,
        )


def test_recovery_invalidates_diagnosis_claim(store: IncidentStore) -> None:
    source = alert()
    claim = store.ingest_and_claim(source, "worker-1", timedelta(minutes=2))

    recovered = store.recover_by_alarm(source.alarm_arn, source.group_key)

    assert recovered[0].state == IncidentState.RECOVERED
    assert not store.renew_claim(claim.incident.id, claim.claim_token, timedelta(minutes=2))
    with pytest.raises(Conflict):
        store.set_diagnosis(
            claim.incident.id,
            "run-stale",
            "http://dataplane",
            [],
            Plan(summary="No action", rationale="stale", actions=[]),
            "stale-hash",
            claim_token=claim.claim_token,
        )


@pytest.mark.asyncio
async def test_terminal_incident_releases_group_for_new_alarm(store: IncidentStore) -> None:
    ddm = FakeDDM()
    service = make_service(
        store,
        ddm,
        StaticPlanner(Plan(summary="No action", rationale="No remediation required", actions=[])),
    )

    await service.handle_alert(alert(source_id="alarm-state-1"))
    await service.handle_alert(alert(source_id="alarm-state-2"))

    assert len(store.list()) == 2
    assert len(ddm.started) == 2


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
async def test_plan_validation_failure_is_timeline_metadata_only(store: IncidentStore) -> None:
    class InvalidPlanner(StaticPlanner):
        async def plan(self, incident: Incident, evidence: list[OperationResult]) -> Plan:
            raise ValueError("unsupported action from model output")

    ddm = FakeDDM()
    service = make_service(
        store,
        ddm,
        InvalidPlanner(Plan(summary="unused", rationale="unused", actions=[])),
    )

    with pytest.raises(ValueError):
        await service.handle_alert(alert())

    incident = store.list()[0]
    events = store.list_events(incident.id)
    failed = [event for event in events if event.event_type == IncidentEventType.PLAN_VALIDATION_FAILED]
    assert failed
    assert len([event for event in events if event.event_type == IncidentEventType.OPERATION_EXECUTED]) == len(
        REQUIRED_DIAGNOSTIC_OPERATIONS
    )
    assert failed[0].metadata == {"errorKind": "ValueError"}
    assert "unsupported action from model output" not in failed[0].model_dump_json()


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
