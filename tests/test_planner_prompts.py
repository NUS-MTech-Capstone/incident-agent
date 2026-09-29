from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from botocore.credentials import Credentials
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from incident_agent.models import ExplanationModel, Incident, IncidentState, OperationResult
from incident_agent.planning.agents import agent_definitions
from incident_agent.planning.planner import (
    BedrockInvocationError,
    BedrockPlanner,
    FallbackPlanner,
    OpenAIPlanner,
    RuleBasedPlanner,
    _extract_openai_text,
)
from incident_agent.planning.prompt_loader import PromptLoader
from tests.conftest import alert


class FakeChatModel:
    def __init__(self, responses: list[str]):
        self.responses = responses
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        self.calls.append(messages)
        return AIMessage(content=self.responses.pop(0))


class FailingPlanner:
    def explain_model(self):
        return ExplanationModel(provider="bedrock", plannerType="bedrock", modelId="test-model")

    async def triage(self, incident: Incident):
        raise BedrockInvocationError("quota exhausted")

    async def plan(self, incident: Incident, evidence: list[OperationResult]):
        raise BedrockInvocationError("quota exhausted")


class FakeAWSSession:
    def __init__(self) -> None:
        self.calls = 0

    def get_credentials(self) -> Credentials:
        self.calls += 1
        return Credentials("access-key", "secret-key", "session-token")


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


@pytest.mark.asyncio
async def test_fallback_planner_uses_rules_when_bedrock_invocation_fails() -> None:
    planner = FallbackPlanner(FailingPlanner(), RuleBasedPlanner())
    incident = _incident()

    triage = await planner.triage(incident)
    plan = await planner.plan(
        incident,
        [
            OperationResult(operationId="service_status", stdout="active", exitCode=0),
            OperationResult(operationId="health_check", stdout="unhealthy", exitCode=1),
        ],
    )

    assert triage.rationale == "Deterministic fallback triage based on alarm reason."
    assert [action.operation_id for action in plan.actions] == ["recover_demo_app"]


def test_openai_planner_explain_model_identifies_provider(prompts_dir: Path) -> None:
    planner = OpenAIPlanner("test-key", "gpt-5.5", 4096, prompts_dir)

    model = planner.explain_model()

    assert model.provider == "openai"
    assert model.planner_type == "openai"
    assert model.model_id == "gpt-5.5"


def test_a2a_openai_explanation_identifies_agentcore_path() -> None:
    agents = agent_definitions("a2a_openai_agentcore_reasoning_agent_with_rule_fallback")

    assert agents[1].reasoning_type.startswith("OpenAI LLM")
    assert agents[1].tools == ["Incident Reasoning Agent over A2A and AgentCore"]


@pytest.mark.asyncio
async def test_openai_api_key_request_uses_responses_payload_limits(prompts_dir: Path) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"output_text": "ok", "usage": {"total_tokens": 7}})

    planner = OpenAIPlanner(
        "test-key",
        "gpt-5.4-2026-03-05",
        4096,
        prompts_dir,
        transport=httpx.MockTransport(handler),
    )

    assert await planner._invoke("system", "user", "triage") == "ok"
    payload = json.loads(requests[0].content)
    assert requests[0].url == "https://api.openai.com/v1/responses"
    assert requests[0].headers["Authorization"] == "Bearer test-key"
    assert payload["model"] == "gpt-5.4-2026-03-05"
    assert payload["reasoning"] == {"effort": "low"}
    assert payload["text"] == {"verbosity": "low"}
    assert payload["max_output_tokens"] == 4096
    assert payload["store"] is False


@pytest.mark.asyncio
async def test_openai_iam_request_is_sigv4_signed_and_refreshes_credentials(prompts_dir: Path) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(503, json={"error": "unavailable"})
        return httpx.Response(200, json={"output_text": "ok"})

    session = FakeAWSSession()
    planner = OpenAIPlanner(
        "",
        "gpt-5.4-2026-03-05",
        4096,
        prompts_dir,
        transient_retry_attempts=2,
        auth_mode="aws_iam",
        gateway_url="https://gateway.example.com/mcp",
        aws_region="ap-southeast-1",
        aws_session=session,  # type: ignore[arg-type]
        transport=httpx.MockTransport(handler),
    )

    assert await planner._invoke("system", "user", "plan") == "ok"
    payload = json.loads(requests[-1].content)
    assert session.calls == 2
    assert str(requests[-1].url) == "https://gateway.example.com/inference/v1/responses"
    assert requests[-1].headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=access-key/")
    assert requests[-1].headers["X-Amz-Security-Token"] == "session-token"
    assert "bedrock-agentcore" in requests[-1].headers["Authorization"]
    assert payload["model"] == "openai/gpt-5.4-2026-03-05"


@pytest.mark.asyncio
async def test_openai_gateway_failure_falls_back_after_bounded_attempts(prompts_dir: Path) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503, json={"error": "unavailable"})

    primary = OpenAIPlanner(
        "test-key",
        "gpt-5.4-2026-03-05",
        4096,
        prompts_dir,
        transient_retry_attempts=2,
        transport=httpx.MockTransport(handler),
    )
    planner = FallbackPlanner(primary, RuleBasedPlanner())

    triage = await planner.triage(_incident())

    assert attempts == 2
    assert triage.rationale == "Deterministic fallback triage based on alarm reason."


def test_extract_openai_text_supports_output_text() -> None:
    assert _extract_openai_text({"output_text": "hello"}) == "hello"


def test_extract_openai_text_supports_output_content_parts() -> None:
    assert (
        _extract_openai_text(
            {
                "output": [
                    {
                        "content": [
                            {"type": "output_text", "text": "hello"},
                            {"type": "output_text", "text": " world"},
                        ]
                    }
                ]
            }
        )
        == "hello world"
    )


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
