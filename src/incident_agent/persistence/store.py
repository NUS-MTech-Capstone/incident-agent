from __future__ import annotations

import builtins
import json
import secrets
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Column, DateTime, MetaData, String, Table, Text, create_engine, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import func

from incident_agent.models import (
    Alert,
    AlertStatus,
    ApprovalDecisionAudit,
    ApprovalOutcome,
    Incident,
    IncidentEvent,
    IncidentEventType,
    IncidentExplanation,
    IncidentState,
    ManagedAlert,
    OperationResult,
    Plan,
    PostIncidentReport,
    TriageResult,
)


class StoreError(Exception):
    pass


class NotFound(StoreError):
    pass


class Conflict(StoreError):
    pass


class Duplicate(StoreError):
    pass


metadata = MetaData()

alerts = Table(
    "alerts",
    metadata,
    Column("id", String, primary_key=True),
    Column("source_id", String, nullable=False, unique=True),
    Column("source_type", Text, nullable=False, default="managed-server"),
    Column("alarm_arn", Text, nullable=False),
    Column("alarm_name", Text, nullable=False),
    Column("cloudwatch_state", Text, nullable=False),
    Column("host_id", Text, nullable=False),
    Column("reason", Text, nullable=False, default=""),
    Column("status", Text, nullable=False),
    Column("group_key", Text, nullable=False, default=""),
    Column("incident_id", Text, nullable=False, default=""),
    Column("grouped", Boolean, nullable=False, default=False),
    Column("error_summary", Text, nullable=False, default=""),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

incidents = Table(
    "incidents",
    metadata,
    Column("id", String, primary_key=True),
    Column("source_id", String, nullable=False, unique=True),
    Column("alarm_arn", Text, nullable=False),
    Column("alarm_name", Text, nullable=False),
    Column("host_id", Text, nullable=False),
    Column("runbook_version", Text, nullable=False, default=""),
    Column("state", Text, nullable=False),
    Column("reason", Text, nullable=False, default=""),
    Column("run_id", Text, nullable=False, default=""),
    Column("operations_url", Text, nullable=False, default=""),
    Column("evidence_json", JSON().with_variant(JSONB, "postgresql"), nullable=False, default=[]),
    Column("triage_json", JSON().with_variant(JSONB, "postgresql"), nullable=False, default={}),
    Column("plan_json", JSON().with_variant(JSONB, "postgresql"), nullable=False, default={}),
    Column("plan_hash", Text, nullable=False, default=""),
    Column("explanation_json", JSON().with_variant(JSONB, "postgresql"), nullable=False, default={}),
    Column("plan_expires_at", DateTime(timezone=True), nullable=True),
    Column("approver_subject", Text, nullable=False, default=""),
    Column("approval_decision", Text, nullable=False, default=""),
    Column("approval_at", DateTime(timezone=True), nullable=True),
    Column("report", Text, nullable=False, default=""),
    Column("report_json", JSON().with_variant(JSONB, "postgresql"), nullable=False, default={}),
    Column("error_message", Text, nullable=False, default=""),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

incident_events = Table(
    "incident_events",
    metadata,
    Column("id", String, primary_key=True),
    Column("incident_id", String, nullable=False),
    Column("alert_id", String, nullable=False, default=""),
    Column("event_type", Text, nullable=False),
    Column("actor", Text, nullable=False, default=""),
    Column("message", Text, nullable=False, default=""),
    Column("metadata_json", JSON().with_variant(JSONB, "postgresql"), nullable=False, default={}),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

approval_decisions = Table(
    "approval_decisions",
    metadata,
    Column("id", String, primary_key=True),
    Column("incident_id", String, nullable=False),
    Column("actor", Text, nullable=False, default=""),
    Column("decision", Text, nullable=False),
    Column("submitted_plan_hash", Text, nullable=False, default=""),
    Column("outcome", Text, nullable=False),
    Column("error_reason", Text, nullable=False, default=""),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)


def normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgres://"):
        return "postgresql+psycopg://" + database_url.removeprefix("postgres://")
    if database_url.startswith("postgresql://"):
        return "postgresql+psycopg://" + database_url.removeprefix("postgresql://")
    return database_url


class IncidentStore:
    def __init__(self, database_url: str):
        self.engine = create_engine(normalize_database_url(database_url), future=True)
        metadata.create_all(self.engine)

    @classmethod
    def from_engine(cls, engine: Engine) -> IncidentStore:
        obj = cls.__new__(cls)
        obj.engine = engine
        metadata.create_all(engine)
        return obj

    def close(self) -> None:
        self.engine.dispose()

    def ping(self) -> None:
        with self.engine.begin() as conn:
            conn.execute(select(1))

    def create_event(
        self,
        incident_id: str,
        event_type: IncidentEventType,
        alert_id: str = "",
        actor: str = "",
        message: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> IncidentEvent:
        now = _utcnow()
        event_id = "evt-" + secrets.token_hex(16)
        row: dict[str, Any] = {
            "id": event_id,
            "incident_id": incident_id,
            "alert_id": alert_id,
            "event_type": event_type.value,
            "actor": actor,
            "message": message,
            "metadata_json": metadata or {},
            "created_at": now,
        }
        with self.engine.begin() as conn:
            conn.execute(incident_events.insert().values(**row))
        return self.get_event(event_id)

    def get_event(self, event_id: str) -> IncidentEvent:
        with self.engine.begin() as conn:
            row = conn.execute(select(incident_events).where(incident_events.c.id == event_id)).mappings().first()
        if row is None:
            raise NotFound("incident event not found")
        return _event_from_row(row)

    def list_events(self, incident_id: str) -> builtins.list[IncidentEvent]:
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(incident_events)
                .where(incident_events.c.incident_id == incident_id)
                .order_by(incident_events.c.created_at.asc())
            ).mappings()
            return [_event_from_row(row) for row in rows]

    def create_approval_decision(
        self,
        incident_id: str,
        decision: str,
        submitted_plan_hash: str,
        actor: str,
        outcome: ApprovalOutcome,
        error_reason: str = "",
    ) -> ApprovalDecisionAudit:
        now = _utcnow()
        decision_id = "appr-" + secrets.token_hex(16)
        row: dict[str, Any] = {
            "id": decision_id,
            "incident_id": incident_id,
            "actor": actor,
            "decision": decision,
            "submitted_plan_hash": submitted_plan_hash,
            "outcome": outcome.value,
            "error_reason": error_reason,
            "created_at": now,
        }
        with self.engine.begin() as conn:
            conn.execute(approval_decisions.insert().values(**row))
        return self.get_approval_decision(decision_id)

    def get_approval_decision(self, decision_id: str) -> ApprovalDecisionAudit:
        with self.engine.begin() as conn:
            row = (
                conn.execute(select(approval_decisions).where(approval_decisions.c.id == decision_id))
                .mappings()
                .first()
            )
        if row is None:
            raise NotFound("approval decision not found")
        return _approval_decision_from_row(row)

    def list_approval_decisions(self, incident_id: str) -> builtins.list[ApprovalDecisionAudit]:
        with self.engine.begin() as conn:
            rows = conn.execute(
                select(approval_decisions)
                .where(approval_decisions.c.incident_id == incident_id)
                .order_by(approval_decisions.c.created_at.asc())
            ).mappings()
            return [_approval_decision_from_row(row) for row in rows]

    def create_alert(self, alert: Alert) -> ManagedAlert:
        now = _utcnow()
        alert_id = "alert-" + secrets.token_hex(16)
        row: dict[str, Any] = {
            "id": alert_id,
            "source_id": alert.source_id,
            "source_type": alert.source_type,
            "alarm_arn": alert.alarm_arn,
            "alarm_name": alert.alarm_name,
            "cloudwatch_state": alert.state,
            "host_id": alert.host_id,
            "reason": alert.reason,
            "status": AlertStatus.RECEIVED.value,
            "group_key": alert.group_key,
            "incident_id": "",
            "grouped": False,
            "error_summary": "",
            "occurred_at": alert.occurred_at,
            "created_at": now,
            "updated_at": now,
        }
        try:
            with self.engine.begin() as conn:
                conn.execute(alerts.insert().values(**row))
        except IntegrityError as exc:
            raise Duplicate("alert source already exists") from exc
        return self.get_alert(alert_id)

    def get_alert(self, alert_id: str) -> ManagedAlert:
        with self.engine.begin() as conn:
            row = conn.execute(select(alerts).where(alerts.c.id == alert_id)).mappings().first()
        if row is None:
            raise NotFound("alert not found")
        return _alert_from_row(row)

    def list_alerts(self, limit: int = 100) -> builtins.list[ManagedAlert]:
        limit = 100 if limit <= 0 or limit > 200 else limit
        with self.engine.begin() as conn:
            rows = conn.execute(select(alerts).order_by(alerts.c.occurred_at.desc()).limit(limit)).mappings()
            return [_alert_from_row(row) for row in rows]

    def link_alert(self, alert_id: str, incident_id: str) -> None:
        self._update_alert(alert_id, {"incident_id": incident_id})

    def mark_alert_grouped(self, alert_id: str, incident_id: str, status: AlertStatus) -> None:
        self._update_alert(alert_id, {"incident_id": incident_id, "grouped": True, "status": status.value})

    def set_alert_status(
        self,
        alert_id: str,
        status: AlertStatus,
        error_summary: str = "",
        incident_id: str = "",
    ) -> None:
        values = {"status": status.value, "error_summary": error_summary}
        if incident_id:
            values["incident_id"] = incident_id
        self._update_alert(alert_id, values)

    def set_alert_status_for_incident(
        self,
        incident_id: str,
        status: AlertStatus,
        error_summary: str = "",
    ) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                alerts.update()
                .where(alerts.c.incident_id == incident_id)
                .values(status=status.value, error_summary=error_summary, updated_at=_utcnow())
            )

    def find_active_incident_by_group(self, group_key: str) -> Incident | None:
        if not group_key:
            return None
        active_states = [
            IncidentState.DIAGNOSING.value,
            IncidentState.AWAITING_APPROVAL.value,
            IncidentState.EXECUTING.value,
        ]
        with self.engine.begin() as conn:
            row = (
                conn.execute(
                    select(incidents)
                    .join(alerts, alerts.c.incident_id == incidents.c.id)
                    .where(alerts.c.group_key == group_key, incidents.c.state.in_(active_states))
                    .order_by(incidents.c.created_at.desc())
                    .limit(1)
                )
                .mappings()
                .first()
            )
        return _incident_from_row(row) if row else None

    def incident_counts(self) -> tuple[int, int]:
        active_states = {
            IncidentState.DIAGNOSING.value,
            IncidentState.AWAITING_APPROVAL.value,
            IncidentState.EXECUTING.value,
        }
        active = 0
        failed = 0
        with self.engine.begin() as conn:
            rows = conn.execute(select(incidents.c.state)).all()
        for (state,) in rows:
            if state in active_states:
                active += 1
            if state == IncidentState.FAILED.value:
                failed += 1
        return active, failed

    def last_alert_processed_at(self) -> datetime | None:
        with self.engine.begin() as conn:
            row = conn.execute(select(alerts.c.updated_at).order_by(alerts.c.updated_at.desc()).limit(1)).first()
        return row[0] if row else None

    def create(self, alert: Alert) -> Incident:
        now = _utcnow()
        incident_id = "inc-" + secrets.token_hex(16)
        row: dict[str, Any] = {
            "id": incident_id,
            "source_id": alert.source_id,
            "alarm_arn": alert.alarm_arn,
            "alarm_name": alert.alarm_name,
            "host_id": alert.host_id,
            "runbook_version": alert.runbook_version,
            "state": IncidentState.DIAGNOSING.value,
            "reason": alert.reason,
            "run_id": "",
            "operations_url": "",
            "evidence_json": [],
            "triage_json": {},
            "plan_json": {},
            "plan_hash": "",
            "explanation_json": {},
            "plan_expires_at": None,
            "approver_subject": "",
            "approval_decision": "",
            "approval_at": None,
            "report": "",
            "report_json": {},
            "error_message": "",
            "created_at": now,
            "updated_at": now,
        }
        try:
            with self.engine.begin() as conn:
                conn.execute(incidents.insert().values(**row))
        except IntegrityError as exc:
            raise Duplicate("incident source already exists") from exc
        return self.get(incident_id)

    def get(self, incident_id: str) -> Incident:
        with self.engine.begin() as conn:
            row = conn.execute(select(incidents).where(incidents.c.id == incident_id)).mappings().first()
        if row is None:
            raise NotFound("incident not found")
        return _incident_from_row(row)

    def list(self, limit: int = 100) -> builtins.list[Incident]:
        limit = 100 if limit <= 0 or limit > 200 else limit
        with self.engine.begin() as conn:
            rows = conn.execute(select(incidents).order_by(incidents.c.created_at.desc()).limit(limit)).mappings()
            return [_incident_from_row(row) for row in rows]

    def set_diagnosis(
        self,
        incident_id: str,
        run_id: str,
        operations_url: str,
        evidence: builtins.list[OperationResult],
        plan: Plan,
        plan_hash: str,
        triage: TriageResult | None = None,
        plan_expires_at: datetime | None = None,
        explanation: IncidentExplanation | None = None,
    ) -> None:
        state = IncidentState.AWAITING_APPROVAL
        report = ""
        report_json: dict[str, Any] = {}
        if not plan.actions:
            state = IncidentState.COMPLETED
            report = "Diagnosis completed. No remediation action was proposed."
            report_json = PostIncidentReport(
                root_cause_summary=triage.summary if triage else "No bounded remediation required.",
                action_taken="No remediation action proposed.",
                verification_summary="Diagnostic evidence did not justify remediation.",
                final_state=state.value,
                resolved_at=_utcnow(),
            ).model_dump(mode="json")
            plan_expires_at = None
        self._update_state(
            incident_id,
            IncidentState.DIAGNOSING,
            {
                "run_id": run_id,
                "operations_url": operations_url,
                "evidence_json": [item.model_dump(by_alias=True) for item in evidence],
                "triage_json": triage.model_dump() if triage else {},
                "plan_json": plan.model_dump(by_alias=True),
                "plan_hash": plan_hash,
                "explanation_json": explanation.model_dump(by_alias=True) if explanation else {},
                "plan_expires_at": plan_expires_at,
                "state": state.value,
                "report": report,
                "report_json": report_json,
            },
        )

    def set_failure(self, incident_id: str, message: str) -> None:
        with self.engine.begin() as conn:
            result = conn.execute(
                incidents.update()
                .where(
                    incidents.c.id == incident_id,
                    incidents.c.state.in_([IncidentState.DIAGNOSING.value, IncidentState.EXECUTING.value]),
                )
                .values(state=IncidentState.FAILED.value, error_message=message, updated_at=_utcnow())
            )
        if result.rowcount == 0:
            raise Conflict("incident state conflict")

    def recover_by_alarm(self, alarm_arn: str, group_key: str = "") -> builtins.list[Incident]:
        with self.engine.begin() as conn:
            group_incident_ids: set[str] = set()
            if group_key:
                group_incident_ids = {
                    str(row[0])
                    for row in conn.execute(
                        select(alerts.c.incident_id).where(alerts.c.group_key == group_key, alerts.c.incident_id != "")
                    )
                }
            rows = list(
                conn.execute(
                    select(incidents).where(
                        (incidents.c.alarm_arn == alarm_arn) | (incidents.c.id.in_(group_incident_ids)),
                        incidents.c.state.in_([IncidentState.DIAGNOSING.value, IncidentState.AWAITING_APPROVAL.value]),
                    )
                ).mappings()
            )
            for row in rows:
                conn.execute(
                    incidents.update()
                    .where(incidents.c.id == row["id"])
                    .values(
                        state=IncidentState.RECOVERED.value,
                        report="CloudWatch returned to OK before remediation approval.",
                        report_json=PostIncidentReport(
                            root_cause_summary="CloudWatch alarm returned to OK before remediation approval.",
                            action_taken="No remediation executed.",
                            verification_summary="Alarm recovery was reported by CloudWatch.",
                            final_state=IncidentState.RECOVERED.value,
                            resolved_at=_utcnow(),
                        ).model_dump(mode="json"),
                        updated_at=_utcnow(),
                    )
                )
                conn.execute(
                    alerts.update()
                    .where(alerts.c.incident_id == row["id"])
                    .values(status=AlertStatus.RESOLVED.value, updated_at=_utcnow())
                )
        return [self.get(row["id"]) for row in rows]

    def approve(self, incident_id: str, plan_hash: str, subject: str) -> None:
        self._decision(incident_id, plan_hash, subject, "APPROVED", IncidentState.EXECUTING)

    def reject(self, incident_id: str, plan_hash: str, subject: str) -> None:
        self._decision(incident_id, plan_hash, subject, "REJECTED", IncidentState.REJECTED)

    def set_executing(self, incident_id: str) -> None:
        self._update_state(incident_id, IncidentState.EXECUTING, {})

    def set_report(
        self,
        incident_id: str,
        state: IncidentState,
        report: str,
        error_message: str = "",
        structured_report: PostIncidentReport | None = None,
    ) -> None:
        values: dict[str, Any] = {
            "state": state.value,
            "report": report,
            "error_message": error_message,
            "updated_at": _utcnow(),
        }
        if structured_report is not None:
            values["report_json"] = structured_report.model_dump(mode="json")
        with self.engine.begin() as conn:
            conn.execute(incidents.update().where(incidents.c.id == incident_id).values(**values))

    def _update_alert(self, alert_id: str, values: dict[str, Any]) -> None:
        values["updated_at"] = _utcnow()
        with self.engine.begin() as conn:
            result = conn.execute(alerts.update().where(alerts.c.id == alert_id).values(**values))
        if result.rowcount == 0:
            raise NotFound("alert not found")

    def _decision(
        self,
        incident_id: str,
        plan_hash: str,
        subject: str,
        decision: str,
        state: IncidentState,
    ) -> None:
        now = _utcnow()
        with self.engine.begin() as conn:
            result = conn.execute(
                incidents.update()
                .where(
                    incidents.c.id == incident_id,
                    incidents.c.state == IncidentState.AWAITING_APPROVAL.value,
                    incidents.c.plan_hash == plan_hash,
                )
                .values(
                    state=state.value,
                    approver_subject=subject,
                    approval_decision=decision,
                    approval_at=now,
                    updated_at=now,
                )
            )
        if result.rowcount == 0:
            raise Conflict("incident changed; reload before deciding")

    def _update_state(self, incident_id: str, expected: IncidentState, values: dict[str, Any]) -> None:
        values["updated_at"] = _utcnow()
        with self.engine.begin() as conn:
            result = conn.execute(
                incidents.update()
                .where(incidents.c.id == incident_id, incidents.c.state == expected.value)
                .values(**values)
            )
        if result.rowcount == 0:
            raise Conflict("incident state conflict")


def _incident_from_row(row: Any) -> Incident:
    evidence_json = _load_json(row["evidence_json"], [])
    triage_json = _load_json(row["triage_json"], {})
    plan_json = _load_json(row["plan_json"], {})
    explanation_json = _load_json(row["explanation_json"], {})
    report_json = _load_json(row["report_json"], {})
    return Incident(
        id=row["id"],
        source_id=row["source_id"],
        alarm_arn=row["alarm_arn"],
        alarm_name=row["alarm_name"],
        host_id=row["host_id"],
        runbook_version=row["runbook_version"] or "",
        state=IncidentState(row["state"]),
        reason=row["reason"] or "",
        run_id=row["run_id"] or "",
        operations_url=row["operations_url"] or "",
        evidence=[OperationResult.model_validate(item) for item in evidence_json],
        triage=TriageResult.model_validate(triage_json) if triage_json else None,
        plan=Plan.model_validate(plan_json) if plan_json else Plan(),
        plan_hash=row["plan_hash"] or "",
        explanation=IncidentExplanation.model_validate(explanation_json) if explanation_json else IncidentExplanation(),
        plan_expires_at=row["plan_expires_at"],
        approver_subject=row["approver_subject"] or "",
        approval_decision=row["approval_decision"] or "",
        approval_at=row["approval_at"],
        report=row["report"] or "",
        post_incident_report=PostIncidentReport.model_validate(report_json) if report_json else PostIncidentReport(),
        error_message=row["error_message"] or "",
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _alert_from_row(row: Any) -> ManagedAlert:
    return ManagedAlert(
        id=row["id"],
        source_id=row["source_id"],
        source_type=row["source_type"],
        alarm_arn=row["alarm_arn"],
        alarm_name=row["alarm_name"],
        cloudwatch_state=row["cloudwatch_state"],
        host_id=row["host_id"],
        reason=row["reason"] or "",
        status=AlertStatus(row["status"]),
        group_key=row["group_key"] or "",
        incident_id=row["incident_id"] or "",
        grouped=bool(row["grouped"]),
        error_summary=row["error_summary"] or "",
        occurred_at=row["occurred_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _event_from_row(row: Any) -> IncidentEvent:
    return IncidentEvent(
        id=row["id"],
        incident_id=row["incident_id"],
        alert_id=row["alert_id"] or "",
        event_type=IncidentEventType(row["event_type"]),
        actor=row["actor"] or "",
        message=row["message"] or "",
        metadata=_load_json(row["metadata_json"], {}),
        created_at=row["created_at"],
    )


def _approval_decision_from_row(row: Any) -> ApprovalDecisionAudit:
    return ApprovalDecisionAudit(
        id=row["id"],
        incident_id=row["incident_id"],
        actor=row["actor"] or "",
        decision=row["decision"],
        submitted_plan_hash=row["submitted_plan_hash"] or "",
        outcome=ApprovalOutcome(row["outcome"]),
        error_reason=row["error_reason"] or "",
        created_at=row["created_at"],
    )


def _load_json(value: Any, fallback: Any) -> Any:
    if value in (None, ""):
        return fallback
    if isinstance(value, str):
        return json.loads(value)
    return value


def _utcnow() -> datetime:
    return datetime.now(UTC)
