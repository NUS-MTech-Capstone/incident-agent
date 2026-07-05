from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from incident_agent.models import Incident, IncidentState, OperationResult
from incident_agent.planning.planner import BedrockPlanner
from incident_agent.planning.prompt_loader import PromptLoader
from tests.conftest import alert


class FakeChatModel:
    def __init__(self, responses: list[str]):
        self.responses = responses
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        self.calls.append(messages)
        return AIMessage(content=self.responses.pop(0))


@pytest.fixture
def prompts_dir(tmp_path: Path) -> Path:
    (tmp_path / "triage_system.md.j2").write_text("triage system")
    (tmp_path / "triage_user.md.j2").write_text("triage {{ alarm_name }} {{ host_id }} {{ reason }}")
    (tmp_path / "plan_system.md.j2").write_text("plan system")
    (tmp_path / "plan_user.md.j2").write_text("plan {{ alarm_name }} {{ host_id }} {{ reason }} {{ evidence_json }}")
    return tmp_path


@pytest.mark.asyncio
async def test_bedrock_planner_sends_system_and_human_triage_messages(prompts_dir: Path) -> None:
    model = FakeChatModel(
        ['{"priority":"high","category":"availability","summary":"service unhealthy","rationale":"alarm"}']
    )
    planner = _planner(model, prompts_dir)

    result = await planner.triage(_incident())

    assert result.priority.value == "high"
    assert len(model.calls) == 1
    assert isinstance(model.calls[0][0], SystemMessage)
    assert isinstance(model.calls[0][1], HumanMessage)
    assert model.calls[0][0].content == "triage system"
    assert "High 5xx host-1 service unhealthy" in str(model.calls[0][1].content)


@pytest.mark.asyncio
async def test_bedrock_planner_sends_system_and_human_plan_messages(prompts_dir: Path) -> None:
    model = FakeChatModel(['{"summary":"No remediation proposed.","rationale":"No action needed.","actions":[]}'])
    planner = _planner(model, prompts_dir)

    result = await planner.plan(_incident(), [OperationResult(operationId="health_check", stdout="ok", exitCode=0)])

    assert result.actions == []
    assert len(model.calls) == 1
    assert isinstance(model.calls[0][0], SystemMessage)
    assert isinstance(model.calls[0][1], HumanMessage)
    assert model.calls[0][0].content == "plan system"
    assert '"operationId": "health_check"' in str(model.calls[0][1].content)


def _planner(model: FakeChatModel, prompts_dir: Path) -> BedrockPlanner:
    planner = BedrockPlanner.__new__(BedrockPlanner)
    planner.model = model
    planner.max_prompt_bytes = 4096
    planner.prompts = PromptLoader(prompts_dir)
    planner.transient_retry_attempts = 1
    return planner


def _incident() -> Incident:
    source = alert()
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
