from __future__ import annotations

import hashlib
import json
import re

from incident_agent.models import Incident, IncidentState, Plan
from incident_agent.planning.catalog import REMEDIATION_OPERATIONS

_SHELL_PATTERN = re.compile(r"(^|\s)(sudo|bash|sh|curl|wget|nc|python|perl|ruby|rm|chmod|chown)\b|[`$|&><]")


def plan_hash(plan: Plan) -> str:
    encoded = json.dumps(plan.model_dump(by_alias=True), separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_plan(plan: Plan) -> Plan:
    if not plan.summary.strip() or not plan.rationale.strip():
        raise ValueError("plan summary and rationale are required")
    if len(plan.actions) > 1:
        raise ValueError("only one remediation action is supported")
    for action in plan.actions:
        if action.operation_id not in REMEDIATION_OPERATIONS:
            raise ValueError("unsupported action")
        if not action.reason.strip():
            raise ValueError("action reason is required")
        if _SHELL_PATTERN.search(action.reason):
            raise ValueError("action reason contains command-like content")
    for value in [plan.summary, plan.rationale]:
        if _SHELL_PATTERN.search(value):
            raise ValueError("plan contains command-like content")
    return plan


def validate_execution(incident: Incident, approved_plan_hash: str) -> None:
    if incident.state != IncidentState.EXECUTING:
        raise ValueError("incident is not approved for execution")
    if not incident.run_id or not incident.operations_url:
        raise ValueError("incident run metadata is incomplete")
    if incident.plan_hash != approved_plan_hash:
        raise ValueError("approved plan hash mismatch")
    if incident.plan_hash != plan_hash(incident.plan):
        raise ValueError("stored plan hash does not match plan body")
    validate_plan(incident.plan)
    if len(incident.plan.actions) != 1 or incident.plan.actions[0].operation_id not in REMEDIATION_OPERATIONS:
        raise ValueError("approved operation is not in the remediation catalog")
