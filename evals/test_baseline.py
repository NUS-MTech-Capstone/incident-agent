from __future__ import annotations

import json
from pathlib import Path

import pytest

from incident_agent.models import IncidentState, OperationResult, Plan
from incident_agent.persistence.store import IncidentStore
from incident_agent.planning.planner import RuleBasedPlanner
from incident_agent.planning.supervisor import validate_plan
from tests.conftest import alert


@pytest.mark.asyncio
async def test_baseline_deterministic_evals(store: IncidentStore) -> None:
    planner = RuleBasedPlanner()
    cases = json.loads((Path(__file__).parent / "fixtures" / "baseline.json").read_text())
    for idx, case in enumerate(cases):
        incident = store.create(alert(source_id=f"eval-{idx}"))
        incident.reason = case["reason"]
        incident.state = IncidentState.DIAGNOSING
        evidence = [OperationResult.model_validate(item) for item in case["evidence"]]
        triage = await planner.triage(incident)
        plan = await planner.plan(incident, evidence)
        validate_plan(plan)
        assert triage.priority.value == case["expected_priority"]
        assert ([action.operation_id for action in plan.actions] or [""])[0] == case["expect_action"]


def test_eval_guardrail_rejects_command_plan() -> None:
    with pytest.raises(ValueError):
        validate_plan(Plan(summary="run bash", rationale="bad", actions=[]))
