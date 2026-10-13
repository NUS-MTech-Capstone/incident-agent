from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from incident_agent.automation.ddm import DDMClient
from incident_agent.models import Alert, Incident, OperationResult, Plan, Run
from incident_agent.persistence.store import IncidentStore, metadata
from incident_agent.planning.planner import RuleBasedPlanner
from incident_agent.planning.workflow import IncidentWorkflow
from incident_agent.service import IncidentService
from incident_agent.trace import IncidentTraceRecorder


def memory_store() -> IncidentStore:
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    metadata.create_all(engine)
    return IncidentStore.from_engine(engine)


def alert(case_id: str = "r12") -> Alert:
    return Alert(
        source_id=case_id,
        alarm_arn=f"arn:evaluation:{case_id}",
        alarm_name="R12 synthetic alarm",
        state="ALARM",
        reason="service anomaly",
        host_id="eval-host",
        group_key=f"evaluation-{case_id}",
    )


def incident(case_id: str = "r12") -> Incident:
    from incident_agent.models import IncidentState

    now = datetime.now(UTC)
    return Incident(
        id=case_id,
        source_id=case_id,
        alarm_arn=f"arn:evaluation:{case_id}",
        alarm_name="R12 synthetic alarm",
        host_id="eval-host",
        reason="service anomaly",
        state=IncidentState.DIAGNOSING,
        created_at=now,
        updated_at=now,
    )


class FixtureTools(DDMClient):
    """Implements the real client boundary without credentials or network access."""

    def __init__(self, results: dict[str, OperationResult] | None = None, denied: set[str] | None = None):
        self.results = results or {}
        self.denied = denied or set()
        self.started: list[list[str]] = []
        self.executed: list[str] = []
        self.closed: list[str] = []

    async def start_run(self, incident_id: str, host_id: str, operations: list[str]) -> Run:
        self.started.append(operations)
        return Run(
            runId="eval-run",
            incidentId=incident_id,
            hostId=host_id,
            operationsUrl="http://fixture.invalid",
            capabilityToken="",
        )

    async def execute(self, run_id: str, operation_id: str, plan_hash: str = "") -> OperationResult:
        self.executed.append(operation_id)
        if operation_id in self.denied:
            raise PermissionError("fixture diagnostic denied")
        return self.results.get(operation_id, OperationResult(operationId=operation_id, stdout="healthy", exitCode=0))

    async def close_run(self, run_id: str) -> None:
        self.closed.append(run_id)


class ControlledPlanner(RuleBasedPlanner):
    def __init__(self, plan: Plan | None = None):
        self.candidate = plan or Plan(summary="No action", rationale="No supported repair is justified")

    async def plan(self, incident: Incident, evidence: list[OperationResult]) -> Plan:
        return self.candidate


def service(store: IncidentStore, tools: FixtureTools, planner=None) -> IncidentService:
    workflow = IncidentWorkflow(planner or ControlledPlanner(), tools, 1, 4096, IncidentTraceRecorder(store))
    return IncidentService(store, workflow, tools, 1, 4096, task_runner=lambda coro: coro.close())
