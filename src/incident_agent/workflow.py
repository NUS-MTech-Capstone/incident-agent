from __future__ import annotations

from typing import Any, TypedDict, cast

from langgraph.graph import END, START, StateGraph

from incident_agent.ddm import DDMClient
from incident_agent.models import Incident, OperationResult
from incident_agent.planner import Planner
from incident_agent.redact import text as redact_text
from incident_agent.supervisor import DIAGNOSTIC_OPERATIONS, plan_hash


class WorkflowState(TypedDict, total=False):
    incident: Incident
    triage: dict[str, Any]
    evidence: list[OperationResult]
    plan: dict[str, Any]
    plan_hash: str


class IncidentWorkflow:
    def __init__(self, planner: Planner, ddm: DDMClient, operation_timeout: float, max_operation_output: int):
        self.planner = planner
        self.ddm = ddm
        self.operation_timeout = operation_timeout
        self.max_operation_output = max_operation_output
        self.graph = self._build_graph()

    async def diagnose(self, incident: Incident) -> WorkflowState:
        return cast(WorkflowState, await self.graph.ainvoke({"incident": incident}))

    def _build_graph(self) -> Any:
        graph = StateGraph(WorkflowState)
        graph.add_node("ingest", self._ingest)
        graph.add_node("triage", self._triage)
        graph.add_node("gather_evidence", self._gather_evidence)
        graph.add_node("propose_plan", self._propose_plan)
        graph.add_node("await_approval", self._await_approval)
        graph.add_edge(START, "ingest")
        graph.add_edge("ingest", "triage")
        graph.add_edge("triage", "gather_evidence")
        graph.add_edge("gather_evidence", "propose_plan")
        graph.add_edge("propose_plan", "await_approval")
        graph.add_edge("await_approval", END)
        return graph.compile()

    async def _ingest(self, state: WorkflowState) -> WorkflowState:
        return state

    async def _triage(self, state: WorkflowState) -> WorkflowState:
        triage = await self.planner.triage(state["incident"])
        return {"triage": triage.model_dump()}

    async def _gather_evidence(self, state: WorkflowState) -> WorkflowState:
        incident = state["incident"]
        run = await self.ddm.start_run(incident.id, incident.host_id, DIAGNOSTIC_OPERATIONS)
        incident.run_id = run.run_id
        incident.operations_url = run.operations_url
        evidence: list[OperationResult] = []
        for operation in DIAGNOSTIC_OPERATIONS:
            try:
                result = await self.ddm.execute(
                    run.operations_url,
                    run.run_id,
                    run.capability_token,
                    operation,
                    "",
                )
            except Exception as exc:  # noqa: BLE001 - diagnostic failures are evidence
                result = OperationResult(operationId=operation, stderr=str(exc), exitCode=-1)
            result.stdout = redact_text(result.stdout, self.max_operation_output)
            result.stderr = redact_text(result.stderr, self.max_operation_output)
            evidence.append(result)
        return {"incident": incident, "evidence": evidence}

    async def _propose_plan(self, state: WorkflowState) -> WorkflowState:
        plan = await self.planner.plan(state["incident"], state.get("evidence", []))
        return {"plan": plan.model_dump(by_alias=True), "plan_hash": plan_hash(plan)}

    async def _await_approval(self, state: WorkflowState) -> WorkflowState:
        return state
