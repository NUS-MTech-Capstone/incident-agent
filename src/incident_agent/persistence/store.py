from __future__ import annotations

import builtins
import json
import secrets
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, Text, create_engine, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import func

from incident_agent.models import (
    Alert,
    AlertStatus,
    Incident,
    IncidentState,
    ManagedAlert,
    OperationResult,
    Plan,
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
    Column("approver_subject", Text, nullable=False, default=""),
    Column("approval_decision", Text, nullable=False, default=""),
    Column("approval_at", DateTime(timezone=True), nullable=True),
    Column("report", Text, nullable=False, default=""),
    Column("error_message", Text, nullable=False, default=""),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)


class IncidentStore:
    def __init__(self, database_url: str):
        self.engine = create_engine(database_url, future=True)
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
            "approver_subject": "",
            "approval_decision": "",
            "approval_at": None,
            "report": "",
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
    ) -> None:
        state = IncidentState.AWAITING_APPROVAL
        report = ""
        if not plan.actions:
            state = IncidentState.COMPLETED
            report = "Diagnosis completed. No remediation action was proposed."
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
                "state": state.value,
                "report": report,
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

    def recover_by_alarm(self, alarm_arn: str) -> builtins.list[Incident]:
        with self.engine.begin() as conn:
            rows = list(
                conn.execute(
                    select(incidents).where(
                        incidents.c.alarm_arn == alarm_arn,
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

    def set_report(self, incident_id: str, state: IncidentState, report: str, error_message: str = "") -> None:
        with self.engine.begin() as conn:
            conn.execute(
                incidents.update()
                .where(incidents.c.id == incident_id)
                .values(state=state.value, report=report, error_message=error_message, updated_at=_utcnow())
            )

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
        approver_subject=row["approver_subject"] or "",
        approval_decision=row["approval_decision"] or "",
        approval_at=row["approval_at"],
        report=row["report"] or "",
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
        error_summary=row["error_summary"] or "",
        occurred_at=row["occurred_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _load_json(value: Any, fallback: Any) -> Any:
    if value in (None, ""):
        return fallback
    if isinstance(value, str):
        return json.loads(value)
    return value


def _utcnow() -> datetime:
    return datetime.now(UTC)
