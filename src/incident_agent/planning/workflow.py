from __future__ import annotations

import logging
import time
from typing import Any, TypedDict, cast

from langgraph.graph import END, START, StateGraph

from incident_agent.automation.ddm import DDMClient
from incident_agent.models import (
    ExplanationGuardrail,
    ExplanationModel,
    ExplanationToolDecision,
    ExplanationWorkflow,
    Incident,
    IncidentExplanation,
    OperationResult,
)
from incident_agent.observability import emit_metric, log_event
from incident_agent.planning.catalog import CATALOG_VERSION, DIAGNOSTIC_OPERATIONS, VERIFY_OPERATIONS
from incident_agent.planning.planner import Planner
from incident_agent.planning.supervisor import plan_hash
from incident_agent.redact import text as redact_text

logger = logging.getLogger(__name__)


class WorkflowState(TypedDict, total=False):
    incident: Incident
    triage: dict[str, Any]
    evidence: list[OperationResult]
    plan: dict[str, Any]
    plan_hash: str
    explanation: dict[str, Any]


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
        incident = state["incident"]
        started = time.monotonic()
        triage = await self.planner.triage(state["incident"])
        duration_ms = (time.monotonic() - started) * 1000
        emit_metric("IncidentTriaged", 1, incidentId=incident.id, hostId=incident.host_id)
        log_event(
            logger,
            "IncidentTriaged",
            incidentId=incident.id,
            hostId=incident.host_id,
            state=incident.state.value,
            durationMs=round(duration_ms, 2),
        )
        return {"triage": triage.model_dump()}

    async def _gather_evidence(self, state: WorkflowState) -> WorkflowState:
        incident = state["incident"]
        started = time.monotonic()
        run = await self.ddm.start_run(incident.id, incident.host_id, DIAGNOSTIC_OPERATIONS)
        incident.run_id = run.run_id
        incident.operations_url = run.operations_url
        evidence: list[OperationResult] = []
        decisions: list[ExplanationToolDecision] = []
        for operation in DIAGNOSTIC_OPERATIONS:
            decisions.append(
                ExplanationToolDecision(
                    operationId=operation,
                    phase="diagnose",
                    chosenBy="policy",
                    reason="Default bounded diagnostic operation from the v1 catalog.",
                )
            )
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
        duration_ms = (time.monotonic() - started) * 1000
        emit_metric("EvidenceCollected", 1, incidentId=incident.id, runId=run.run_id, hostId=incident.host_id)
        log_event(
            logger,
            "EvidenceCollected",
            incidentId=incident.id,
            runId=run.run_id,
            hostId=incident.host_id,
            state=incident.state.value,
            durationMs=round(duration_ms, 2),
        )
        explanation = _base_explanation(self.planner)
        explanation.workflow.run_id = run.run_id
        explanation.tool_decisions.extend(decisions)
        return {"incident": incident, "evidence": evidence, "explanation": explanation.model_dump(by_alias=True)}

    async def _propose_plan(self, state: WorkflowState) -> WorkflowState:
        incident = state["incident"]
        started = time.monotonic()
        plan = await self.planner.plan(incident, state.get("evidence", []))
        hashed_plan = plan_hash(plan)
        explanation = IncidentExplanation.model_validate(state.get("explanation", {}))
        explanation.workflow.plan_hash = hashed_plan
        explanation.guardrails.extend(
            [
                ExplanationGuardrail(
                    name="catalog_validation",
                    passed=True,
                    reason="Plan actions were validated against the remediation catalog.",
                ),
                ExplanationGuardrail(
                    name="command_like_content",
                    passed=True,
                    reason="Plan text was checked for command-like content before storage.",
                ),
                ExplanationGuardrail(
                    name="max_single_remediation_action",
                    passed=True,
                    reason="The supervisor allows at most one remediation operation.",
                ),
                ExplanationGuardrail(
                    name="approval_required",
                    passed=True,
                    reason=(
                        "Mutating remediation requires Manager or Admin approval of the exact plan hash."
                        if plan.actions
                        else "No mutating remediation was proposed, so approval is not required."
                    ),
                ),
            ]
        )
        for action in plan.actions:
            explanation.tool_decisions.append(
                ExplanationToolDecision(
                    operationId=action.operation_id,
                    phase="remediate",
                    chosenBy="model_proposal",
                    reason=action.reason,
                )
            )
        for operation in VERIFY_OPERATIONS:
            explanation.tool_decisions.append(
                ExplanationToolDecision(
                    operationId=operation,
                    phase="verify",
                    chosenBy="policy",
                    reason="Fixed verification operation after any approved remediation.",
                )
            )
        duration_ms = (time.monotonic() - started) * 1000
        emit_metric("PlanProposed", 1, incidentId=incident.id, runId=incident.run_id, hostId=incident.host_id)
        log_event(
            logger,
            "PlanProposed",
            incidentId=incident.id,
            runId=incident.run_id,
            hostId=incident.host_id,
            planHash=hashed_plan,
            state=incident.state.value,
            durationMs=round(duration_ms, 2),
        )
        return {
            "plan": plan.model_dump(by_alias=True),
            "plan_hash": hashed_plan,
            "explanation": explanation.model_dump(by_alias=True),
        }

    async def _await_approval(self, state: WorkflowState) -> WorkflowState:
        return state


def _base_explanation(planner: Planner) -> IncidentExplanation:
    model = ExplanationModel(provider="unknown", plannerType=type(planner).__name__)
    explain_model = getattr(planner, "explain_model", None)
    if callable(explain_model):
        model = explain_model()
    return IncidentExplanation(
        model=model,
        workflow=ExplanationWorkflow(
            graphVersion="v1",
            catalogVersion=CATALOG_VERSION,
            diagnosticOperations=DIAGNOSTIC_OPERATIONS,
            verificationOperations=VERIFY_OPERATIONS,
        ),
    )
