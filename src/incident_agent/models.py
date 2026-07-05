from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

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
    approver_subject: str = ""
    approval_decision: str = ""
    approval_at: datetime | None = None
    report: str = ""
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
    error_summary: str = ""
    occurred_at: datetime
    created_at: datetime
    updated_at: datetime


class ApprovalDecision(BaseModel):
    incident_id: str
    plan_hash: str
    subject: str
