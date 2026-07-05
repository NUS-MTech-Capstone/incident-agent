from __future__ import annotations

import base64
import json

from fastapi.testclient import TestClient

from incident_agent.api.web import create_app
from incident_agent.models import Plan
from incident_agent.persistence.store import IncidentStore
from incident_agent.planning.supervisor import plan_hash
from tests.conftest import FakeDDM, StaticPlanner, alert, make_service


def _oidc() -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "user-1", "email": "u@example.com"}).encode()).decode()
    return f"header.{payload.rstrip('=')}.sig"


def test_routes_preserve_openapi_and_incident_pages(store: IncidentStore) -> None:
    ddm = FakeDDM()
    service = make_service(store, ddm, StaticPlanner(Plan(summary="No action", rationale="none", actions=[])))
    incident = store.create(alert())
    plan = Plan(
        summary="Restart",
        rationale="failed",
        actions=[{"operationId": "restart_service", "reason": "health_check failed"}],
    )
    store.set_diagnosis(incident.id, "run-1", "http://dataplane", [], plan, plan_hash(plan))
    client = TestClient(create_app(service))

    assert client.get("/healthz").json() == {"status": "ok"}
    ready = client.get("/readyz", headers={"X-Request-ID": "req-1"})
    assert ready.json() == {"status": "ready"}
    assert ready.headers["X-Request-ID"] == "req-1"
    assert "DenDenMushi Incident Agent API" in client.get("/openapi.yaml").text
    response = client.get("/incidents", headers={"x-amzn-oidc-data": _oidc()})
    assert response.status_code == 200
    assert "High 5xx" in response.text
    detail = client.get(f"/incidents/{incident.id}", headers={"x-amzn-oidc-data": _oidc()})
    assert detail.status_code == 200
    assert "Approve exact plan" in detail.text
