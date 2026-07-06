from __future__ import annotations

import asyncio
import builtins
import logging
import time
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from typing import Any

from incident_agent.automation.ddm import DDMClient
from incident_agent.models import (
    AgentHealth,
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
from incident_agent.observability import emit_metric, log_event
from incident_agent.persistence.store import Conflict, Duplicate, IncidentStore, NotFound
from incident_agent.planning.agents import RemediationExecutorAgent
from incident_agent.planning.catalog import VERIFY_OPERATIONS
from incident_agent.planning.workflow import IncidentWorkflow
from incident_agent.redact import text as redact_text

logger = logging.getLogger(__name__)
PLAN_APPROVAL_TTL = timedelta(minutes=30)


class IncidentService:
    def __init__(
        self,
        store: IncidentStore,
        workflow: IncidentWorkflow,
        ddm: DDMClient,
        operation_timeout: float,
        max_operation_output: int,
        task_runner: Callable[[Coroutine[Any, Any, None]], None] | None = None,
    ):
        self.store = store
        self.workflow = workflow
        self.ddm = ddm
        self.operation_timeout = operation_timeout
        self.max_operation_output = max_operation_output
        self.task_runner: Callable[[Coroutine[Any, Any, None]], None] = task_runner or _schedule_task
        self.remediation_executor_agent = RemediationExecutorAgent()
        self.queue_consumer_configured = False
        self.queue_consumer_running = False
        self.last_error_summary = ""

    async def handle_alert(self, alert: Alert) -> None:
        emit_metric("IncidentReceived", 1, hostId=alert.host_id)
        alert.reason = redact_text(alert.reason, 4096)
        try:
            managed_alert = self.store.create_alert(alert)
        except Duplicate:
            return
        self.last_error_summary = ""
        if alert.state == "OK":
            recovered = self.store.recover_by_alarm(alert.alarm_arn, alert.group_key)
            if recovered:
                self.store.link_alert(managed_alert.id, recovered[0].id)
            self.store.set_alert_status(managed_alert.id, AlertStatus.RESOLVED)
            for incident in recovered:
                self.store.create_event(
                    incident.id,
                    IncidentEventType.ALERT_RECEIVED,
                    alert_id=managed_alert.id,
                    message="CloudWatch alarm returned to OK.",
                )
                self.store.create_event(
                    incident.id,
                    IncidentEventType.INCIDENT_RECOVERED,
                    alert_id=managed_alert.id,
                    message="Incident recovered before remediation approval.",
                )
                if incident.run_id:
                    try:
                        token = await self.ddm.issue_token(incident.run_id, "verify", ["health_check"], "")
                        await self.ddm.close_run(incident.run_id, token.capability_token)
                    except Exception as exc:  # noqa: BLE001 - close is best effort during recovery
                        logger.warning("incident run close after recovery failed: %s", exc)
            return
        active = self.store.find_active_incident_by_group(alert.group_key)
        if active is not None:
            self.store.mark_alert_grouped(managed_alert.id, active.id, _alert_status_for_incident(active.state))
            self.store.create_event(
                active.id,
                IncidentEventType.ALERT_RECEIVED,
                alert_id=managed_alert.id,
                message="Duplicate managed-server alert received.",
            )
            self.store.create_event(
                active.id,
                IncidentEventType.ALERT_GROUPED,
                alert_id=managed_alert.id,
                message="Alert grouped into existing active incident.",
                metadata={"groupKey": alert.group_key},
            )
            return
        try:
            self.store.set_alert_status(managed_alert.id, AlertStatus.TRIAGING)
            incident = self.store.create(alert)
        except Duplicate:
            return
        self.store.link_alert(managed_alert.id, incident.id)
        self.store.create_event(
            incident.id,
            IncidentEventType.ALERT_RECEIVED,
            alert_id=managed_alert.id,
            message="Managed-server alert received.",
        )
        self.store.create_event(
            incident.id,
            IncidentEventType.INCIDENT_CREATED,
            alert_id=managed_alert.id,
            message="Incident created for managed-server alert.",
        )
        log_event(
            logger,
            "IncidentReceived",
            incidentId=incident.id,
            hostId=incident.host_id,
            state=incident.state.value,
        )
        try:
            result = await self.workflow.diagnose(incident)
            updated_incident = result["incident"]
            plan = Plan.model_validate(result["plan"])
            triage = TriageResult.model_validate(result["triage"]) if result.get("triage") else None
            explanation = IncidentExplanation.model_validate(result.get("explanation", {}))
            plan_expires_at = datetime.now(UTC) + PLAN_APPROVAL_TTL if plan.actions else None
            self.store.set_diagnosis(
                incident.id,
                updated_incident.run_id,
                updated_incident.operations_url,
                result.get("evidence", []),
                plan,
                result["plan_hash"],
                triage,
                plan_expires_at,
                explanation,
            )
            self.store.create_event(
                incident.id,
                IncidentEventType.AGENT_TRIAGED,
                alert_id=managed_alert.id,
                message=triage.summary if triage else "Agent triage completed.",
                metadata=triage.model_dump() if triage else {},
            )
            self.store.create_event(
                incident.id,
                IncidentEventType.EVIDENCE_COLLECTED,
                alert_id=managed_alert.id,
                message="Bounded diagnostic evidence collected.",
                metadata={"operationCount": len(result.get("evidence", []))},
            )
            self.store.create_event(
                incident.id,
                IncidentEventType.PLAN_PROPOSED,
                alert_id=managed_alert.id,
                message=plan.summary or "Plan proposed.",
                metadata={
                    "planHash": result["plan_hash"],
                    "planExpiresAt": plan_expires_at.isoformat() if plan_expires_at else "",
                },
            )
            self.store.set_alert_status(
                managed_alert.id,
                AlertStatus.PENDING_APPROVAL if plan.actions else AlertStatus.TRIAGED,
                incident_id=incident.id,
            )
            if not plan.actions and updated_incident.run_id:
                await self.ddm.close_run(updated_incident.run_id, await self._best_effort_close_token(updated_incident))
        except Exception as exc:  # noqa: BLE001 - execution failures are persisted as incident state
            try:
                current = self.store.get(incident.id)
                if current.state != IncidentState.RECOVERED:
                    self.store.set_failure(incident.id, redact_text(str(exc), 2048))
                    self.store.set_alert_status(managed_alert.id, AlertStatus.FAILED, redact_text(str(exc), 2048))
                    if isinstance(exc, ValueError):
                        self.store.create_event(
                            incident.id,
                            IncidentEventType.PLAN_VALIDATION_FAILED,
                            alert_id=managed_alert.id,
                            message="Model plan output failed deterministic validation.",
                            metadata={"errorKind": type(exc).__name__},
                        )
                    self.store.create_event(
                        incident.id,
                        IncidentEventType.REMEDIATION_FAILED,
                        alert_id=managed_alert.id,
                        message="Agent workflow failed before approval.",
                        metadata={"errorKind": type(exc).__name__},
                    )
            except (Conflict, NotFound):
                pass
            self.record_processing_error(str(exc))
            raise

    def list(self) -> list[Incident]:
        return self.store.list(100)

    def list_alerts(self) -> builtins.list[ManagedAlert]:
        return self.store.list_alerts(100)

    def get_alert(self, alert_id: str) -> ManagedAlert:
        return self.store.get_alert(alert_id)

    def get(self, incident_id: str) -> Incident:
        return self.store.get(incident_id)

    def timeline(self, incident_id: str) -> builtins.list[IncidentEvent]:
        return self.store.list_events(incident_id)

    def approval_decisions(self, incident_id: str) -> builtins.list[ApprovalDecisionAudit]:
        return self.store.list_approval_decisions(incident_id)

    def ready(self) -> None:
        self.store.ping()

    def set_consumer_configured(self, configured: bool) -> None:
        self.queue_consumer_configured = configured

    def set_consumer_running(self, running: bool) -> None:
        self.queue_consumer_running = running

    def record_processing_error(self, summary: str) -> None:
        self.last_error_summary = redact_text(summary, 512)

    def record_denied_decision(
        self,
        incident_id: str,
        decision: str,
        plan_hash: str,
        subject: str,
        reason: str,
    ) -> None:
        self.store.create_approval_decision(
            incident_id,
            decision.upper(),
            plan_hash,
            subject,
            ApprovalOutcome.DENIED,
            redact_text(reason, 512),
        )

    def health(self) -> AgentHealth:
        database_ready = True
        try:
            self.store.ping()
        except Exception as exc:  # noqa: BLE001 - endpoint returns a safe summary
            database_ready = False
            self.record_processing_error(f"database readiness failed: {type(exc).__name__}")
        active_count, failed_count = self.store.incident_counts()
        return AgentHealth(
            database_ready=database_ready,
            queue_consumer_configured=self.queue_consumer_configured,
            queue_consumer_running=self.queue_consumer_running,
            last_alert_processed_at=self.store.last_alert_processed_at(),
            last_error_summary=self.last_error_summary,
            active_incident_count=active_count,
            failed_incident_count=failed_count,
        )

    def approve(self, incident_id: str, plan_hash: str, subject: str) -> None:
        incident = self._load_for_decision(incident_id, "APPROVE", plan_hash, subject)
        if _is_plan_expired(incident):
            self._record_decision_conflict(incident_id, "APPROVE", plan_hash, subject, "plan expired")
            self.store.create_event(
                incident_id,
                IncidentEventType.PLAN_EXPIRED,
                actor=subject,
                message="Plan expired before approval.",
                metadata={"planHash": incident.plan_hash},
            )
            raise Conflict("plan expired; reload before deciding")
        try:
            self.store.approve(incident_id, plan_hash, subject)
        except Conflict:
            self._record_decision_conflict(incident_id, "APPROVE", plan_hash, subject, "incident changed")
            raise
        self.store.create_approval_decision(incident_id, "APPROVE", plan_hash, subject, ApprovalOutcome.SUCCEEDED)
        self.store.set_alert_status_for_incident(incident_id, AlertStatus.EXECUTING)
        self.store.create_event(
            incident_id,
            IncidentEventType.PLAN_APPROVED,
            actor=subject,
            message="Manager approved exact remediation plan.",
            metadata={"planHash": plan_hash},
        )
        emit_metric("PlanApproved", 1, incidentId=incident_id)
        log_event(
            logger, "PlanApproved", incidentId=incident_id, planHash=plan_hash, state=IncidentState.EXECUTING.value
        )
        self.task_runner(self.execute(incident_id, plan_hash))

    def reject(self, incident_id: str, plan_hash: str, subject: str) -> None:
        incident = self._load_for_decision(incident_id, "REJECT", plan_hash, subject)
        if _is_plan_expired(incident):
            self._record_decision_conflict(incident_id, "REJECT", plan_hash, subject, "plan expired")
            self.store.create_event(
                incident_id,
                IncidentEventType.PLAN_EXPIRED,
                actor=subject,
                message="Plan expired before rejection.",
                metadata={"planHash": incident.plan_hash},
            )
            raise Conflict("plan expired; reload before deciding")
        try:
            self.store.reject(incident_id, plan_hash, subject)
        except Conflict:
            self._record_decision_conflict(incident_id, "REJECT", plan_hash, subject, "incident changed")
            raise
        self.store.create_approval_decision(incident_id, "REJECT", plan_hash, subject, ApprovalOutcome.SUCCEEDED)
        self.store.set_alert_status_for_incident(incident_id, AlertStatus.REJECTED)
        self.store.set_report(
            incident_id,
            IncidentState.REJECTED,
            "Remediation plan was rejected by a manager.",
            "",
            PostIncidentReport(
                root_cause_summary=incident.triage.summary if incident.triage else incident.reason,
                action_taken="Plan rejected before remediation.",
                verification_summary="No remediation was executed.",
                final_state=IncidentState.REJECTED.value,
                resolved_at=datetime.now(UTC),
            ),
        )
        self.store.create_event(
            incident_id,
            IncidentEventType.PLAN_REJECTED,
            actor=subject,
            message="Manager rejected exact remediation plan.",
            metadata={"planHash": plan_hash},
        )
        emit_metric("PlanRejected", 1, incidentId=incident_id)
        log_event(
            logger, "PlanRejected", incidentId=incident_id, planHash=plan_hash, state=IncidentState.REJECTED.value
        )
        incident = self.store.get(incident_id)
        if incident.run_id:
            self.task_runner(self._close_after_reject(incident))

    async def execute(self, incident_id: str, approved_plan_hash: str) -> None:
        incident = self.store.get(incident_id)
        started = time.monotonic()
        started_at = datetime.now(UTC)
        try:
            self.store.set_executing(incident_id)
            self.store.create_event(
                incident_id,
                IncidentEventType.REMEDIATION_STARTED,
                message="Approved remediation execution started.",
                metadata={"planHash": approved_plan_hash},
            )
            self.remediation_executor_agent.validate(incident, approved_plan_hash)
            remediation_operation = incident.plan.actions[0].operation_id
            token = await self.ddm.issue_token(
                incident.run_id,
                "remediate",
                [remediation_operation],
                incident.plan_hash,
            )
            remediation = await self.ddm.execute(
                incident.operations_url,
                incident.run_id,
                token.capability_token,
                remediation_operation,
                incident.plan_hash,
            )
            if remediation.exit_code != 0:
                raise RuntimeError(
                    f"{remediation_operation} failed with exit code {remediation.exit_code}: {remediation.stderr}"
                )
            verify_token = await self.ddm.issue_token(incident.run_id, "verify", VERIFY_OPERATIONS, "")
            verification = []
            success = True
            for operation in VERIFY_OPERATIONS:
                try:
                    result = await self.ddm.execute(
                        incident.operations_url,
                        incident.run_id,
                        verify_token.capability_token,
                        operation,
                        "",
                    )
                except Exception as exc:  # noqa: BLE001 - verification failures become report data
                    result = OperationResult(operationId=operation, stderr=str(exc), exitCode=-1)
                result.stdout = redact_text(result.stdout, self.max_operation_output)
                result.stderr = redact_text(result.stderr, self.max_operation_output)
                verification.append(result)
                success = success and result.exit_code == 0
            state = IncidentState.COMPLETED if success else IncidentState.FAILED
            error = "" if success else "post-remediation verification failed"
            structured_report = _build_structured_report(incident, remediation, verification, state, started_at)
            self.store.set_report(
                incident_id,
                state,
                _build_report(incident, remediation, verification),
                error,
                structured_report,
            )
            self.store.set_alert_status_for_incident(
                incident_id,
                AlertStatus.RESOLVED if success else AlertStatus.FAILED,
                error,
            )
            self.store.create_event(
                incident_id,
                IncidentEventType.REMEDIATION_EXECUTED if success else IncidentEventType.REMEDIATION_FAILED,
                message="Remediation completed." if success else "Remediation verification failed.",
                metadata={"planHash": incident.plan_hash},
            )
            self.store.create_event(
                incident_id,
                IncidentEventType.VERIFICATION_PASSED if success else IncidentEventType.VERIFICATION_FAILED,
                message="Post-remediation verification passed." if success else "Post-remediation verification failed.",
                metadata={"operationCount": len(verification)},
            )
            await self.ddm.close_run(incident.run_id, verify_token.capability_token)
            duration_ms = (time.monotonic() - started) * 1000
            if success:
                emit_metric(
                    "RemediationExecuted", 1, incidentId=incident.id, runId=incident.run_id, hostId=incident.host_id
                )
                log_event(
                    logger,
                    "RemediationExecuted",
                    incidentId=incident.id,
                    runId=incident.run_id,
                    hostId=incident.host_id,
                    planHash=incident.plan_hash,
                    state=state.value,
                    durationMs=round(duration_ms, 2),
                )
            else:
                emit_metric(
                    "RemediationFailed", 1, incidentId=incident.id, runId=incident.run_id, hostId=incident.host_id
                )
                log_event(
                    logger,
                    "RemediationFailed",
                    incidentId=incident.id,
                    runId=incident.run_id,
                    hostId=incident.host_id,
                    planHash=incident.plan_hash,
                    state=state.value,
                    durationMs=round(duration_ms, 2),
                    errorKind="VerificationFailed",
                )
        except Exception as exc:  # noqa: BLE001 - execution failures are persisted as incident state
            self.store.set_report(
                incident_id,
                IncidentState.FAILED,
                "Approved remediation could not be completed.",
                redact_text(str(exc), 2048),
                PostIncidentReport(
                    root_cause_summary=incident.triage.summary if incident.triage else incident.reason,
                    action_taken="Approved remediation could not be completed.",
                    verification_summary=redact_text(str(exc), 2048),
                    final_state=IncidentState.FAILED.value,
                    started_at=started_at,
                    resolved_at=datetime.now(UTC),
                    duration_seconds=round(time.monotonic() - started, 3),
                ),
            )
            self.store.set_alert_status_for_incident(incident_id, AlertStatus.FAILED, redact_text(str(exc), 2048))
            self.store.create_event(
                incident_id,
                IncidentEventType.REMEDIATION_FAILED,
                message="Approved remediation failed.",
                metadata={"errorKind": type(exc).__name__},
            )
            emit_metric("RemediationFailed", 1, incidentId=incident.id, runId=incident.run_id, hostId=incident.host_id)
            log_event(
                logger,
                "RemediationFailed",
                incidentId=incident.id,
                runId=incident.run_id,
                hostId=incident.host_id,
                planHash=incident.plan_hash,
                state=IncidentState.FAILED.value,
                durationMs=round((time.monotonic() - started) * 1000, 2),
                errorKind=type(exc).__name__,
            )

    def _load_for_decision(self, incident_id: str, decision: str, plan_hash: str, subject: str) -> Incident:
        try:
            return self.store.get(incident_id)
        except NotFound:
            self.store.create_approval_decision(
                incident_id,
                decision,
                plan_hash,
                subject,
                ApprovalOutcome.NOT_FOUND,
                "incident not found",
            )
            raise

    def _record_decision_conflict(
        self,
        incident_id: str,
        decision: str,
        plan_hash: str,
        subject: str,
        reason: str,
    ) -> None:
        self.store.create_approval_decision(
            incident_id,
            decision,
            plan_hash,
            subject,
            ApprovalOutcome.CONFLICT,
            reason,
        )

    async def _best_effort_close_token(self, incident: Incident) -> str:
        token = await self.ddm.issue_token(incident.run_id, "verify", ["health_check"], "")
        return token.capability_token

    async def _close_after_reject(self, incident: Incident) -> None:
        try:
            token = await self.ddm.issue_token(incident.run_id, "verify", ["health_check"], "")
            await self.ddm.close_run(incident.run_id, token.capability_token)
        except Exception as exc:  # noqa: BLE001 - reject close is best effort
            logger.warning("incident run close after rejection failed: %s", exc)


def _build_report(
    incident: Incident,
    remediation: OperationResult,
    verification: builtins.list[OperationResult],
) -> str:
    lines = [
        f"Incident {incident.id} on host {incident.host_id}",
        "",
        f"Approved plan: {incident.plan.summary}",
        f"Remediation: {remediation.operation_id} exit={remediation.exit_code}",
    ]
    lines.extend(f"Verification: {result.operation_id} exit={result.exit_code}" for result in verification)
    return "\n".join(lines)


def _build_structured_report(
    incident: Incident,
    remediation: OperationResult,
    verification: builtins.list[OperationResult],
    state: IncidentState,
    started_at: datetime,
) -> PostIncidentReport:
    resolved_at = datetime.now(UTC)
    verification_summary = ", ".join(f"{result.operation_id} exit={result.exit_code}" for result in verification)
    return PostIncidentReport(
        root_cause_summary=incident.triage.summary if incident.triage else incident.reason,
        action_taken=f"{remediation.operation_id} exit={remediation.exit_code}",
        verification_summary=verification_summary,
        final_state=state.value,
        started_at=started_at,
        resolved_at=resolved_at,
        duration_seconds=round((resolved_at - started_at).total_seconds(), 3),
    )


def _is_plan_expired(incident: Incident) -> bool:
    if not incident.plan_expires_at:
        return False
    expires_at = incident.plan_expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at <= datetime.now(UTC)


def _alert_status_for_incident(state: IncidentState) -> AlertStatus:
    if state == IncidentState.DIAGNOSING:
        return AlertStatus.TRIAGING
    if state == IncidentState.AWAITING_APPROVAL:
        return AlertStatus.PENDING_APPROVAL
    if state == IncidentState.EXECUTING:
        return AlertStatus.EXECUTING
    if state == IncidentState.REJECTED:
        return AlertStatus.REJECTED
    if state in {IncidentState.COMPLETED, IncidentState.RECOVERED}:
        return AlertStatus.RESOLVED
    return AlertStatus.FAILED


def _schedule_task(coro: Coroutine[Any, Any, None]) -> None:
    asyncio.create_task(coro)
