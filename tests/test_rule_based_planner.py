from __future__ import annotations

from datetime import UTC, datetime

import pytest

from incident_agent.models import Alert, Incident, IncidentState, OperationResult
from incident_agent.planning.planner import RuleBasedPlanner
from tests.conftest import alert


@pytest.mark.asyncio
async def test_rule_based_planner_recovers_active_unhealthy_demo_app() -> None:
    source = alert()
    planner = RuleBasedPlanner()
    plan = await planner.plan(
        _incident_from_alert(source),
        [
            OperationResult(operationId="service_status", stdout="active", exitCode=0),
            OperationResult(operationId="health_check", stdout="unhealthy", exitCode=1),
        ],
    )

    assert [action.operation_id for action in plan.actions] == ["recover_demo_app"]


def _incident_from_alert(source: Alert) -> Incident:
    now = datetime.now(UTC)
    return Incident(
        id="inc-1",
        source_id=source.source_id,
        alarm_arn=source.alarm_arn,
        alarm_name=source.alarm_name,
        host_id=source.host_id,
        state=IncidentState.DIAGNOSING,
        reason=source.reason,
        created_at=now,
        updated_at=now,
    )
