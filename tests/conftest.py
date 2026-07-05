from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from incident_agent.automation.ddm import DDMClient
from incident_agent.models import Alert, Incident, OperationResult, Plan, Priority, Run, TriageResult
from incident_agent.persistence.store import IncidentStore
from incident_agent.planning.planner import RuleBasedPlanner
from incident_agent.planning.workflow import IncidentWorkflow
from incident_agent.service import IncidentService


class FakeDDM(DDMClient):
    def __init__(self, results: dict[str, OperationResult] | None = None):
        self.results = results or {}
        self.started: list[tuple[str, str, list[str]]] = []
        self.tokens: list[tuple[str, str, list[str], str]] = []
        self.executed: list[tuple[str, str]] = []
        self.closed: list[tuple[str, str]] = []

    async def start_run(self, incident_id: str, host_id: str, operations: list[str]) -> Run:
        self.started.append((incident_id, host_id, operations))
        return Run(
            runId="run-1",
            incidentId=incident_id,
            hostId=host_id,
            operationsUrl="http://dataplane:8083",
            capabilityToken="diagnose-token",
        )

    async def issue_token(self, run_id: str, phase: str, operations: list[str], plan_hash: str = "") -> Run:
        self.tokens.append((run_id, phase, operations, plan_hash))
        return Run(
            runId=run_id,
            incidentId="inc-1",
            hostId="host-1",
            operationsUrl="http://dataplane:8083",
            capabilityToken=f"{phase}-token",
        )

    async def execute(
        self,
        operations_url: str,
        run_id: str,
        capability_token: str,
        operation_id: str,
        plan_hash: str = "",
    ) -> OperationResult:
        self.executed.append((operation_id, plan_hash))
        return self.results.get(operation_id) or OperationResult(operationId=operation_id, stdout="ok", exitCode=0)

    async def close_run(self, run_id: str, capability_token: str) -> None:
        self.closed.append((run_id, capability_token))


class StaticPlanner(RuleBasedPlanner):
    def __init__(self, plan: Plan):
        self._plan = plan

    async def triage(self, incident: Incident) -> TriageResult:
        return TriageResult(
            priority=Priority.HIGH,
            category="availability",
            summary="service unhealthy",
            rationale="alarm is in ALARM",
        )

    async def plan(self, incident: Incident, evidence: list[OperationResult]) -> Plan:
        return self._plan


@pytest.fixture
def store() -> IncidentStore:
    engine = create_engine(
        "sqlite+pysqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    return IncidentStore.from_engine(engine)


def make_service(store: IncidentStore, ddm: FakeDDM, planner: RuleBasedPlanner) -> IncidentService:
    workflow = IncidentWorkflow(planner, ddm, 1, 4096)
    return IncidentService(store, workflow, ddm, 1, 4096, task_runner=lambda coro: coro.close())


def alert(source_id: str = "source-1", state: str = "ALARM") -> Alert:
    return Alert(
        source_id=source_id,
        alarm_arn="arn:alarm",
        alarm_name="High 5xx",
        state=state,  # type: ignore[arg-type]
        reason="service unhealthy",
        host_id="host-1",
        occurred_at=datetime.now(UTC),
    )
