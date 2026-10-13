from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import jsonschema
import pytest
import yaml
from fastapi.testclient import TestClient

from incident_agent.api.web import create_app
from incident_agent.models import Plan
from incident_agent.persistence.store import IncidentStore
from tests.conftest import FakeDDM, StaticPlanner, make_service

SPEC_PATH = Path(__file__).resolve().parents[1] / "api/openapi.yaml"


def assert_response(path: str, status: int, payload: Any) -> None:
    doc = yaml.safe_load(SPEC_PATH.read_text())
    response = doc["paths"][path]["get"]["responses"][str(status)]
    if "$ref" in response:
        response = doc["components"]["responses"][response["$ref"].split("/")[-1]]
    schema = {**response["content"]["application/json"]["schema"], "components": doc["components"]}
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(payload)


def test_actual_worker_responses_conform_and_served_spec_is_exact(store: IncidentStore) -> None:
    service = make_service(store, FakeDDM(), StaticPlanner(Plan(summary="No action", rationale="none", actions=[])))
    client = TestClient(create_app(service))
    assert client.get("/openapi.yaml").content == SPEC_PATH.read_bytes()
    for path in ("/healthz", "/readyz", "/internal/worker/health"):
        response = client.get(path, headers={"x-api-version": "1"})
        assert response.status_code == 200
        assert_response(path, response.status_code, response.json())
    with patch.object(service, "ready", side_effect=RuntimeError("isolated database failure")):
        response = client.get("/readyz")
        assert response.status_code == 503
        assert_response("/readyz", 503, response.json())


@pytest.mark.parametrize("version", [None, "unsupported"])
def test_worker_version_errors_conform(store: IncidentStore, version: str | None) -> None:
    service = make_service(store, FakeDDM(), StaticPlanner(Plan(summary="No action", rationale="none", actions=[])))
    client = TestClient(create_app(service))
    response = client.get("/internal/worker/health", headers={} if version is None else {"x-api-version": version})
    assert response.status_code == 400
    assert_response("/internal/worker/health", 400, response.json())
