from __future__ import annotations

import importlib

import pytest

from incident_agent.config import Settings
from incident_agent.planning.planner import FallbackPlanner, OpenAIPlanner, RuleBasedPlanner


def test_main_module_import_does_not_create_runtime_app() -> None:
    module = importlib.import_module("incident_agent.main")

    assert callable(module.create_runtime_app)
    assert not hasattr(module, "app")


def test_build_planner_rule_based_mode_does_not_construct_bedrock() -> None:
    module = importlib.import_module("incident_agent.main")

    planner = module._build_planner(Settings(PLANNER_MODE="rule_based"))

    assert isinstance(planner, RuleBasedPlanner)


def test_build_planner_openai_mode_uses_openai_key() -> None:
    module = importlib.import_module("incident_agent.main")

    planner = module._build_planner(Settings(PLANNER_MODE="openai", OPENAI_API_KEY="test-key"))

    assert isinstance(planner, OpenAIPlanner)
    assert planner.api_key == "test-key"


def test_build_planner_openai_with_fallback_wraps_openai() -> None:
    module = importlib.import_module("incident_agent.main")

    planner = module._build_planner(Settings(PLANNER_MODE="openai_with_fallback", OPENAI_API_KEY="test-key"))

    assert isinstance(planner, FallbackPlanner)
    assert isinstance(planner.primary, OpenAIPlanner)


def test_build_planner_openai_iam_mode_uses_gateway_without_api_key() -> None:
    module = importlib.import_module("incident_agent.main")

    planner = module._build_planner(
        Settings(
            PLANNER_MODE="openai_with_fallback",
            OPENAI_AUTH_MODE="aws_iam",
            OPENAI_GATEWAY_URL="https://gateway.example.com",
            OPENAI_MODEL="gpt-5.4-2026-03-05",
        )
    )

    assert isinstance(planner, FallbackPlanner)
    assert isinstance(planner.primary, OpenAIPlanner)
    assert planner.primary.api_key == ""
    assert planner.primary.route == "openai/gpt-5.4-2026-03-05"


def test_build_planner_openai_mode_requires_key() -> None:
    module = importlib.import_module("incident_agent.main")

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        module._build_planner(Settings(PLANNER_MODE="openai"))


def test_build_planner_openai_iam_mode_requires_gateway_url() -> None:
    module = importlib.import_module("incident_agent.main")

    with pytest.raises(RuntimeError, match="OPENAI_GATEWAY_URL"):
        module._build_planner(Settings(PLANNER_MODE="openai", OPENAI_AUTH_MODE="aws_iam"))


def test_build_planner_rejects_unknown_mode() -> None:
    module = importlib.import_module("incident_agent.main")

    with pytest.raises(ValueError, match="PLANNER_MODE"):
        module._build_planner(Settings(PLANNER_MODE="bad"))


def test_build_planner_rejects_models_outside_reviewed_allowlists() -> None:
    module = importlib.import_module("incident_agent.main")
    with pytest.raises(RuntimeError, match="BEDROCK_MODEL_ID"):
        module._build_planner(Settings(BEDROCK_MODEL_ID="unreviewed.model"))
    with pytest.raises(RuntimeError, match="OPENAI_MODEL"):
        module._build_planner(
            Settings(PLANNER_MODE="openai", OPENAI_API_KEY="test-key", OPENAI_MODEL="unreviewed-model")
        )


def test_settings_require_claim_renewal_before_expiry() -> None:
    with pytest.raises(ValueError, match="INCIDENT_CLAIM_RENEW_SECONDS"):
        Settings(INCIDENT_CLAIM_LEASE_SECONDS=30, INCIDENT_CLAIM_RENEW_SECONDS=30)
