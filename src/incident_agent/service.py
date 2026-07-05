from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Coroutine
from typing import Any

from incident_agent.automation.ddm import DDMClient
from incident_agent.models import Alert, Incident, IncidentState, OperationResult, Plan
from incident_agent.observability import emit_metric, log_event
from incident_agent.persistence.store import Conflict, Duplicate, IncidentStore, NotFound
from incident_agent.planning.supervisor import REMEDIATION_OPERATIONS, VERIFY_OPERATIONS, validate_execution
from incident_agent.planning.workflow import IncidentWorkflow
from incident_agent.redact import text as redact_text

logger = logging.getLogger(__name__)


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

    async def handle_alert(self, alert: Alert) -> None:
        emit_metric("IncidentReceived", 1, hostId=alert.host_id)
        if alert.state == "OK":
            recovered = self.store.recover_by_alarm(alert.alarm_arn)
            for incident in recovered:
                if incident.run_id:
                    try:
                        token = await self.ddm.issue_token(incident.run_id, "verify", ["health_check"], "")
                        await self.ddm.close_run(incident.run_id, token.capability_token)
                    except Exception as exc:  # noqa: BLE001 - close is best effort during recovery
                        logger.warning("incident run close after recovery failed: %s", exc)
            return
        alert.reason = redact_text(alert.reason, 4096)
        try:
            incident = self.store.create(alert)
        except Duplicate:
            return
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
            self.store.set_diagnosis(
                incident.id,
                updated_incident.run_id,
                updated_incident.operations_url,
                result.get("evidence", []),
                plan,
                result["plan_hash"],
            )
            if not plan.actions and updated_incident.run_id:
                await self.ddm.close_run(updated_incident.run_id, await self._best_effort_close_token(updated_incident))
        except Exception as exc:  # noqa: BLE001 - execution failures are persisted as incident state
            try:
                current = self.store.get(incident.id)
                if current.state != IncidentState.RECOVERED:
                    self.store.set_failure(incident.id, redact_text(str(exc), 2048))
            except (Conflict, NotFound):
                pass
            raise

    def list(self) -> list[Incident]:
        return self.store.list(100)

    def get(self, incident_id: str) -> Incident:
        return self.store.get(incident_id)

    def ready(self) -> None:
        self.store.ping()

    def approve(self, incident_id: str, plan_hash: str, subject: str) -> None:
        self.store.approve(incident_id, plan_hash, subject)
        emit_metric("PlanApproved", 1, incidentId=incident_id)
        log_event(
            logger, "PlanApproved", incidentId=incident_id, planHash=plan_hash, state=IncidentState.EXECUTING.value
        )
        self.task_runner(self.execute(incident_id, plan_hash))

    def reject(self, incident_id: str, plan_hash: str, subject: str) -> None:
        self.store.reject(incident_id, plan_hash, subject)
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
        try:
            self.store.set_executing(incident_id)
            validate_execution(incident, approved_plan_hash)
            token = await self.ddm.issue_token(incident.run_id, "remediate", REMEDIATION_OPERATIONS, incident.plan_hash)
            restart = await self.ddm.execute(
                incident.operations_url,
                incident.run_id,
                token.capability_token,
                "restart_service",
                incident.plan_hash,
            )
            if restart.exit_code != 0:
                raise RuntimeError(f"restart_service failed with exit code {restart.exit_code}: {restart.stderr}")
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
            self.store.set_report(incident_id, state, _build_report(incident, restart, verification), error)
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

    async def _best_effort_close_token(self, incident: Incident) -> str:
        token = await self.ddm.issue_token(incident.run_id, "verify", ["health_check"], "")
        return token.capability_token

    async def _close_after_reject(self, incident: Incident) -> None:
        try:
            token = await self.ddm.issue_token(incident.run_id, "verify", ["health_check"], "")
            await self.ddm.close_run(incident.run_id, token.capability_token)
        except Exception as exc:  # noqa: BLE001 - reject close is best effort
            logger.warning("incident run close after rejection failed: %s", exc)


def _build_report(incident: Incident, restart: OperationResult, verification: list[OperationResult]) -> str:
    lines = [
        f"Incident {incident.id} on host {incident.host_id}",
        "",
        f"Approved plan: {incident.plan.summary}",
        f"Remediation: restart_service exit={restart.exit_code}",
    ]
    lines.extend(f"Verification: {result.operation_id} exit={result.exit_code}" for result in verification)
    return "\n".join(lines)


def _schedule_task(coro: Coroutine[Any, Any, None]) -> None:
    asyncio.create_task(coro)
