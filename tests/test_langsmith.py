from __future__ import annotations

import logging
import os

from incident_agent.config import Settings
from incident_agent.langsmith import configure_langsmith


def test_tracing_disabled_does_not_fetch_secret(monkeypatch) -> None:
    fetched = False
    resource_id = "resource-id"

    def fetch_secret(secret_id: str, region_name: str) -> str:
        nonlocal fetched
        fetched = True
        return "secret"

    monkeypatch.setenv("LANGSMITH_API_KEY", "existing")
    settings = Settings(langsmith_tracing=False, langsmith_api_key_secret_id=resource_id)

    configure_langsmith(settings, fetch_secret)

    assert fetched is False
    assert os.environ["LANGSMITH_TRACING"] == "false"
    assert os.environ["LANGSMITH_API_KEY"] == "existing"


def test_tracing_enabled_fetches_secret_and_sets_langsmith_env(monkeypatch) -> None:
    monkeypatch.delenv("LANGSMITH_API_KEY", raising=False)
    resource_id = "resource-id"
    settings = Settings(
        langsmith_tracing=True,
        langsmith_api_key_secret_id=resource_id,
        langsmith_project="dendenmushi-incident-agent-dev",
        langsmith_endpoint="https://api.smith.langchain.com",
        langsmith_workspace_id="workspace-id",
    )

    def fetch_secret(secret_id: str, region_name: str) -> str:
        assert secret_id == resource_id
        assert region_name == "ap-southeast-1"
        return "lsv2-key"

    configure_langsmith(settings, fetch_secret)

    assert os.environ["LANGSMITH_TRACING"] == "true"
    assert os.environ["LANGSMITH_API_KEY"] == "lsv2-key"
    assert os.environ["LANGSMITH_PROJECT"] == "dendenmushi-incident-agent-dev"
    assert os.environ["LANGSMITH_ENDPOINT"] == "https://api.smith.langchain.com"
    assert os.environ["LANGSMITH_WORKSPACE_ID"] == "workspace-id"


def test_missing_key_disables_tracing_without_logging_secret_material(monkeypatch, caplog) -> None:
    monkeypatch.delenv("LANGSMITH_API_KEY", raising=False)
    caplog.set_level(logging.WARNING)
    resource_id = "resource-id"
    settings = Settings(langsmith_tracing=True, langsmith_api_key_secret_id=resource_id)

    configure_langsmith(settings, lambda _secret_id, _region_name: "")

    assert os.environ["LANGSMITH_TRACING"] == "false"
    assert resource_id not in caplog.text
    assert "LANGSMITH_API_KEY" not in caplog.text


def test_secret_fetch_error_disables_tracing_without_logging_secret_material(monkeypatch, caplog) -> None:
    monkeypatch.delenv("LANGSMITH_API_KEY", raising=False)
    caplog.set_level(logging.WARNING)
    resource_id = "resource-id"
    settings = Settings(langsmith_tracing=True, langsmith_api_key_secret_id=resource_id)

    def fetch_secret(_secret_id: str, _region_name: str) -> str:
        raise RuntimeError("backend failure")

    configure_langsmith(settings, fetch_secret)

    assert os.environ["LANGSMITH_TRACING"] == "false"
    assert resource_id not in caplog.text
    assert "backend failure" not in caplog.text
    assert "LANGSMITH_API_KEY" not in caplog.text
