from __future__ import annotations

import logging
import time
from typing import Any, TypedDict, cast

from langgraph.graph import END, START, StateGraph

from incident_agent.automation.ddm import DDMClient
from incident_agent.models import (
    ExplanationModel,
    ExplanationToolDecision,
    ExplanationWorkflow,
    Incident,
    IncidentExplanation,
    OperationResult,
    TriageResult,
)
from incident_agent.observability import emit_metric, log_event
from incident_agent.planning.agents import (
    ActionPlanAgent,
    ActionPlanReviewerAgent,
    EvidenceCollectorAgent,
    TriageAgent,
    agent_definitions,
)
from incident_agent.planning.catalog import CATALOG_VERSION, DIAGNOSTIC_OPERATIONS, VERIFY_OPERATIONS
from incident_agent.planning.planner import Planner

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
        self.triage_agent = TriageAgent(planner)
        self.evidence_collector_agent = EvidenceCollectorAgent(ddm, max_operation_output)
        self.action_plan_agent = ActionPlanAgent(planner)
        self.action_plan_reviewer_agent = ActionPlanReviewerAgent()
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
        triage = await self.triage_agent.run(state["incident"])
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
        triage = TriageResult.model_validate(state["triage"])
        collected = await self.evidence_collector_agent.run(incident, triage.suggested_diagnostic_operation_ids)
        duration_ms = (time.monotonic() - started) * 1000
        emit_metric(
            "EvidenceCollected",
            1,
            incidentId=collected.incident.id,
            runId=collected.incident.run_id,
            hostId=collected.incident.host_id,
        )
        log_event(
            logger,
            "EvidenceCollected",
            incidentId=collected.incident.id,
            runId=collected.incident.run_id,
            hostId=collected.incident.host_id,
            state=collected.incident.state.value,
            durationMs=round(duration_ms, 2),
        )
        explanation = _base_explanation(self.planner)
        explanation.workflow.run_id = collected.incident.run_id
        explanation.workflow.diagnostic_operations = [decision.operation_id for decision in collected.decisions]
        explanation.tool_decisions.extend(collected.decisions)
        return {
            "incident": collected.incident,
            "evidence": collected.evidence,
            "explanation": explanation.model_dump(by_alias=True),
        }

    async def _propose_plan(self, state: WorkflowState) -> WorkflowState:
        incident = state["incident"]
        started = time.monotonic()
        candidate_plan = await self.action_plan_agent.run(incident, state.get("evidence", []))
        reviewed = self.action_plan_reviewer_agent.run(candidate_plan)
        explanation = IncidentExplanation.model_validate(state.get("explanation", {}))
        explanation.workflow.plan_hash = reviewed.plan_hash
        explanation.guardrails.extend(reviewed.guardrails)
        for action in reviewed.plan.actions:
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
            planHash=reviewed.plan_hash,
            state=incident.state.value,
            durationMs=round(duration_ms, 2),
        )
        return {
            "plan": reviewed.plan.model_dump(by_alias=True),
            "plan_hash": reviewed.plan_hash,
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
        agents=agent_definitions(model.planner_type),
        workflow=ExplanationWorkflow(
            graphVersion="v1",
            catalogVersion=CATALOG_VERSION,
            diagnosticOperations=DIAGNOSTIC_OPERATIONS,
            verificationOperations=VERIFY_OPERATIONS,
        ),
    )
