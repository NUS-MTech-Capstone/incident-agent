from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IncidentState(StrEnum):
    DIAGNOSING = "DIAGNOSING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    RECOVERED = "RECOVERED"
    FAILED = "FAILED"


class AlertStatus(StrEnum):
    RECEIVED = "RECEIVED"
    TRIAGING = "TRIAGING"
    TRIAGED = "TRIAGED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    EXECUTING = "EXECUTING"
    RESOLVED = "RESOLVED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


class IncidentEventType(StrEnum):
    ALERT_RECEIVED = "AlertReceived"
    ALERT_GROUPED = "AlertGrouped"
    INCIDENT_CREATED = "IncidentCreated"
    AGENT_TRIAGED = "AgentTriaged"
    EVIDENCE_COLLECTED = "EvidenceCollected"
    PLAN_PROPOSED = "PlanProposed"
    PLAN_VALIDATION_FAILED = "PlanValidationFailed"
    PLAN_EXPIRED = "PlanExpired"
    PLAN_APPROVED = "PlanApproved"
    PLAN_REJECTED = "PlanRejected"
    REMEDIATION_STARTED = "RemediationStarted"
    AUTOMATION_TOKEN_ISSUED = "AutomationTokenIssued"  # noqa: S105 - event type, not a secret
    OPERATION_EXECUTED = "OperationExecuted"
    REMEDIATION_EXECUTED = "RemediationExecuted"
    REMEDIATION_FAILED = "RemediationFailed"
    VERIFICATION_OPERATION_EXECUTED = "VerificationOperationExecuted"
    AUTOMATION_RUN_CLOSED = "AutomationRunClosed"
    VERIFICATION_PASSED = "VerificationPassed"
    VERIFICATION_FAILED = "VerificationFailed"
    INCIDENT_RECOVERED = "IncidentRecovered"


class ApprovalOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    DENIED = "DENIED"
    CONFLICT = "CONFLICT"
    NOT_FOUND = "NOT_FOUND"


class Priority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Alert(BaseModel):
    source_id: str
    source_type: str = "managed-server"
    alarm_arn: str
    alarm_name: str
    state: Literal["ALARM", "OK"]
    reason: str = ""
    host_id: str
    runbook_version: str = ""
    group_key: str = ""
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TriageResult(BaseModel):
    priority: Priority
    category: str
    summary: str
    rationale: str

    @field_validator("category", "summary", "rationale")
    @classmethod
    def not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value is required")
        return value


class Action(BaseModel):
    operation_id: str = Field(alias="operationId")
    reason: str

    model_config = ConfigDict(populate_by_name=True)


class Plan(BaseModel):
    summary: str = ""
    rationale: str = ""
    actions: list[Action] = Field(default_factory=list)


class OperationResult(BaseModel):
    operation_id: str = Field(alias="operationId")
    stdout: str = ""
    stderr: str = ""
    exit_code: int = Field(alias="exitCode", default=0)

    model_config = ConfigDict(populate_by_name=True)


class Run(BaseModel):
    run_id: str = Field(alias="runId")
    incident_id: str = Field(alias="incidentId")
    host_id: str = Field(alias="hostId")
    operations_url: str = Field(alias="operationsUrl")
    capability_token: str = Field(alias="capabilityToken")
    token_expires_at: datetime | None = Field(alias="tokenExpiresAt", default=None)

    model_config = ConfigDict(populate_by_name=True)


class ExplanationModel(BaseModel):
    provider: str = ""
    planner_type: str = Field(alias="plannerType", default="")
    model_id: str = Field(alias="modelId", default="")
    aws_region: str = Field(alias="awsRegion", default="")
    temperature: float | None = None
    max_prompt_bytes: int = Field(alias="maxPromptBytes", default=0)
    prompt_templates: dict[str, str] = Field(alias="promptTemplates", default_factory=dict)

    model_config = ConfigDict(populate_by_name=True)


class ExplanationWorkflow(BaseModel):
    graph_version: str = Field(alias="graphVersion", default="v1")
    catalog_version: str = Field(alias="catalogVersion", default="")
    diagnostic_operations: list[str] = Field(alias="diagnosticOperations", default_factory=list)
    verification_operations: list[str] = Field(alias="verificationOperations", default_factory=list)
    run_id: str = Field(alias="runId", default="")
    plan_hash: str = Field(alias="planHash", default="")

    model_config = ConfigDict(populate_by_name=True)


class ExplanationToolDecision(BaseModel):
    operation_id: str = Field(alias="operationId")
    phase: str
    chosen_by: str = Field(alias="chosenBy")
    reason: str

    model_config = ConfigDict(populate_by_name=True)


class ExplanationGuardrail(BaseModel):
    name: str
    passed: bool
    reason: str = ""


class ExplanationResponsibility(BaseModel):
    model_advisory: bool = Field(alias="modelAdvisory", default=True)
    human_approval_required: bool = Field(alias="humanApprovalRequired", default=True)
    execution_owner: str = Field(alias="executionOwner", default="agent-controlplane")
    token_issuer: str = Field(alias="tokenIssuer", default="sts")
    terminal_traffic: str = Field(
        alias="terminalTraffic",
        default="not handled by incident-agent or agent-controlplane",
    )

    model_config = ConfigDict(populate_by_name=True)


class ExplanationAgent(BaseModel):
    name: str
    purpose: str
    responsibilities: list[str] = Field(default_factory=list)
    reasoning_type: str = Field(alias="reasoningType", default="")
    memory: str = ""
    tools: list[str] = Field(default_factory=list)
    inputs: list[str] = Field(default_factory=list)
    outputs: list[str] = Field(default_factory=list)
    handoff_to: str = Field(alias="handoffTo", default="")

    model_config = ConfigDict(populate_by_name=True)


class IncidentExplanation(BaseModel):
    model: ExplanationModel = Field(default_factory=ExplanationModel)
    workflow: ExplanationWorkflow = Field(default_factory=ExplanationWorkflow)
    agents: list[ExplanationAgent] = Field(default_factory=list)
    tool_decisions: list[ExplanationToolDecision] = Field(alias="toolDecisions", default_factory=list)
    guardrails: list[ExplanationGuardrail] = Field(default_factory=list)
    responsibility: ExplanationResponsibility = Field(default_factory=ExplanationResponsibility)

    model_config = ConfigDict(populate_by_name=True)


class Incident(BaseModel):
    id: str
    source_id: str
    alarm_arn: str
    alarm_name: str
    host_id: str
    runbook_version: str = ""
    state: IncidentState
    reason: str = ""
    run_id: str = ""
    operations_url: str = ""
    evidence: list[OperationResult] = Field(default_factory=list)
    triage: TriageResult | None = None
    plan: Plan = Field(default_factory=Plan)
    plan_hash: str = ""
    explanation: IncidentExplanation = Field(default_factory=IncidentExplanation)
    plan_expires_at: datetime | None = None
    approver_subject: str = ""
    approval_decision: str = ""
    approval_at: datetime | None = None
    report: str = ""
    post_incident_report: PostIncidentReport = Field(default_factory=lambda: PostIncidentReport())
    error_message: str = ""
    created_at: datetime
    updated_at: datetime


class ManagedAlert(BaseModel):
    id: str
    source_id: str
    source_type: str
    alarm_arn: str
    alarm_name: str
    cloudwatch_state: Literal["ALARM", "OK"]
    host_id: str
    reason: str = ""
    status: AlertStatus
    group_key: str
    incident_id: str = ""
    grouped: bool = False
    error_summary: str = ""
    occurred_at: datetime
    created_at: datetime
    updated_at: datetime


class PostIncidentReport(BaseModel):
    root_cause_summary: str = ""
    action_taken: str = ""
    verification_summary: str = ""
    final_state: str = ""
    started_at: datetime | None = None
    resolved_at: datetime | None = None
    duration_seconds: float | None = None


class IncidentEvent(BaseModel):
    id: str
    incident_id: str
    alert_id: str = ""
    event_type: IncidentEventType
    actor: str = ""
    message: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class ApprovalDecisionAudit(BaseModel):
    id: str
    incident_id: str
    actor: str
    decision: str
    submitted_plan_hash: str
    outcome: ApprovalOutcome
    error_reason: str = ""
    created_at: datetime


class AgentHealth(BaseModel):
    database_ready: bool
    queue_consumer_configured: bool
    queue_consumer_running: bool
    last_alert_processed_at: datetime | None = None
    last_error_summary: str = ""
    active_incident_count: int
    failed_incident_count: int


class ApprovalDecision(BaseModel):
    incident_id: str
    plan_hash: str
    subject: str
