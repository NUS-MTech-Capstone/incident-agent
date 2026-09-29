from __future__ import annotations

from dataclasses import dataclass

from incident_agent.automation.ddm import DDMClient
from incident_agent.models import (
    ExplanationAgent,
    ExplanationGuardrail,
    ExplanationToolDecision,
    Incident,
    OperationResult,
    Plan,
    TriageResult,
)
from incident_agent.planning.catalog import select_diagnostic_operations
from incident_agent.planning.planner import Planner
from incident_agent.planning.supervisor import plan_hash, validate_execution, validate_plan
from incident_agent.redact import text as redact_text

INCIDENT_MANAGER_AGENT = "Incident Manager Agent"
TRIAGE_AGENT = "Triage Agent"
EVIDENCE_COLLECTOR_AGENT = "Evidence Collector Agent"
ACTION_PLAN_AGENT = "Action Plan Agent"
ACTION_PLAN_REVIEWER_AGENT = "Action Plan Reviewer Agent"
REMEDIATION_EXECUTOR_AGENT = "Remediation Executor Agent"


def agent_definitions(planner_type: str) -> list[ExplanationAgent]:
    uses_a2a = planner_type.startswith("a2a_")
    uses_bedrock = planner_type.startswith("bedrock")
    uses_openai = planner_type.startswith("openai")
    if uses_a2a:
        model_reasoning = "Bedrock LLM structured reasoning over authenticated A2A with deterministic fallback"
        planner_tool = "Incident Reasoning Agent over A2A"
    elif uses_bedrock:
        model_reasoning = "Bedrock LLM structured reasoning"
        planner_tool = "Bedrock via LangChain"
    elif uses_openai:
        model_reasoning = "OpenAI LLM structured reasoning"
        planner_tool = "OpenAI Responses API"
    else:
        model_reasoning = "deterministic rules"
        planner_tool = "RuleBasedPlanner"
    if planner_type == "bedrock_with_rule_fallback":
        model_reasoning = "Bedrock LLM structured reasoning with deterministic fallback"
        planner_tool = "Bedrock via LangChain, RuleBasedPlanner"
    if planner_type == "openai_with_rule_fallback":
        model_reasoning = "OpenAI LLM structured reasoning with deterministic fallback"
        planner_tool = "OpenAI Responses API, RuleBasedPlanner"
    return [
        ExplanationAgent(
            name=INCIDENT_MANAGER_AGENT,
            purpose="Coordinate the bounded incident workflow and preserve handoff order.",
            responsibilities=[
                "Run the LangGraph workflow nodes in order.",
                "Pass sanitized state between specialist agents.",
                "Keep terminal traffic outside the agent workflow.",
            ],
            reasoningType="deterministic LangGraph state machine",
            memory="short-term workflow state for one incident",
            tools=["LangGraph"],
            inputs=["managed-server alert record"],
            outputs=["workflow state transitions"],
            handoffTo=TRIAGE_AGENT,
        ),
        ExplanationAgent(
            name=TRIAGE_AGENT,
            purpose="Classify the incident and produce an operator-readable triage summary.",
            responsibilities=[
                "Use sanitized alert context only.",
                "Assign priority and category.",
                "Explain the suspected issue without exposing secrets.",
            ],
            reasoningType=model_reasoning,
            memory="incident-local prompt context only; no cross-incident memory",
            tools=[planner_tool],
            inputs=["alarm name", "host ID", "sanitized alarm reason"],
            outputs=["TriageResult", "suggested diagnostic operation IDs"],
            handoffTo=EVIDENCE_COLLECTOR_AGENT,
        ),
        ExplanationAgent(
            name=EVIDENCE_COLLECTOR_AGENT,
            purpose="Collect bounded diagnostic evidence from approved operation IDs.",
            responsibilities=[
                "Start a bounded automation run.",
                "Execute diagnostic operation IDs from the v1 catalog.",
                "Redact and truncate outputs before storage.",
            ],
            reasoningType="deterministic policy",
            memory="incident-local operation results",
            tools=["MCP Tool Gateway", "Agent Control Plane automation API", "STS capability tokens"],
            inputs=["incident ID", "host ID", "diagnostic operation catalog"],
            outputs=["bounded OperationResult list"],
            handoffTo=ACTION_PLAN_AGENT,
        ),
        ExplanationAgent(
            name=ACTION_PLAN_AGENT,
            purpose="Propose a structured remediation plan from triage and bounded evidence.",
            responsibilities=[
                "Generate plan summary and rationale.",
                "Suggest only operation IDs in structured plan output.",
                "Leave all authority decisions to deterministic review and human approval.",
            ],
            reasoningType=model_reasoning,
            memory="incident-local evidence context only; no long-term memory",
            tools=[planner_tool],
            inputs=["incident metadata", "bounded diagnostic evidence"],
            outputs=["candidate Plan"],
            handoffTo=ACTION_PLAN_REVIEWER_AGENT,
        ),
        ExplanationAgent(
            name=ACTION_PLAN_REVIEWER_AGENT,
            purpose="Validate the proposed plan before it can be stored or approved.",
            responsibilities=[
                "Reject unsupported operation IDs.",
                "Reject command-like content and multiple remediation actions.",
                "Compute the canonical plan hash for approval binding.",
            ],
            reasoningType="deterministic safety rules",
            memory="none beyond the candidate plan",
            tools=["operation catalog", "plan hash function", "prompt-injection guardrails"],
            inputs=["candidate Plan"],
            outputs=["validated Plan", "planHash", "guardrail outcomes"],
            handoffTo="Manager/Admin approval",
        ),
        ExplanationAgent(
            name=REMEDIATION_EXECUTOR_AGENT,
            purpose="Execute approved remediation and fixed verification after human approval.",
            responsibilities=[
                "Require exact plan-hash approval before execution.",
                "Issue scoped remediation and verification tokens.",
                "Run only approved catalog operations and close the automation run.",
            ],
            reasoningType="deterministic execution policy",
            memory="incident execution state and verification results",
            tools=["MCP Tool Gateway", "Agent Control Plane automation API", "STS capability tokens"],
            inputs=["approved incident", "approved plan hash"],
            outputs=["remediation result", "verification result", "post-incident report"],
            handoffTo="Post-incident audit and operator review",
        ),
    ]


class TriageAgent:
    def __init__(self, planner: Planner):
        self.planner = planner

    async def run(self, incident: Incident) -> TriageResult:
        return await self.planner.triage(incident)


class EvidenceCollectorAgent:
    def __init__(self, ddm: DDMClient, max_operation_output: int):
        self.ddm = ddm
        self.max_operation_output = max_operation_output

    async def run(self, incident: Incident, suggested_operations: list[str]) -> EvidenceCollection:
        operations = select_diagnostic_operations(suggested_operations)
        run = await self.ddm.start_run(incident.id, incident.host_id, operations)
        incident.run_id = run.run_id
        incident.operations_url = run.operations_url
        evidence: list[OperationResult] = []
        decisions: list[ExplanationToolDecision] = []
        for operation in operations:
            decisions.append(
                ExplanationToolDecision(
                    operationId=operation,
                    phase="diagnose",
                    chosenBy="policy",
                    reason="Default bounded diagnostic operation from the v1 catalog.",
                )
            )
            try:
                result = await self.ddm.execute(run.run_id, operation)
            except Exception as exc:  # noqa: BLE001 - diagnostic failures are evidence
                result = OperationResult(operationId=operation, stderr=str(exc), exitCode=-1)
            result.stdout = redact_text(result.stdout, self.max_operation_output)
            result.stderr = redact_text(result.stderr, self.max_operation_output)
            evidence.append(result)
        return EvidenceCollection(incident=incident, evidence=evidence, decisions=decisions)


class ActionPlanAgent:
    def __init__(self, planner: Planner):
        self.planner = planner

    async def run(self, incident: Incident, evidence: list[OperationResult]) -> Plan:
        return await self.planner.plan(incident, evidence)


class ActionPlanReviewerAgent:
    def run(self, plan: Plan) -> ReviewedPlan:
        validated = validate_plan(plan)
        hashed_plan = plan_hash(validated)
        guardrails = [
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
                reason="The reviewer allows at most one remediation operation.",
            ),
            ExplanationGuardrail(
                name="approval_required",
                passed=True,
                reason=(
                    "Mutating remediation requires Manager or Admin approval of the exact plan hash."
                    if validated.actions
                    else "No mutating remediation was proposed, so approval is not required."
                ),
            ),
        ]
        return ReviewedPlan(plan=validated, plan_hash=hashed_plan, guardrails=guardrails)


class RemediationExecutorAgent:
    def validate(self, incident: Incident, approved_plan_hash: str) -> None:
        validate_execution(incident, approved_plan_hash)


@dataclass(frozen=True)
class EvidenceCollection:
    incident: Incident
    evidence: list[OperationResult]
    decisions: list[ExplanationToolDecision]


@dataclass(frozen=True)
class ReviewedPlan:
    plan: Plan
    plan_hash: str
    guardrails: list[ExplanationGuardrail]
