from __future__ import annotations

import base64
import json

from fastapi.testclient import TestClient

from incident_agent.api.web import create_app
from incident_agent.models import IncidentState, Plan
from incident_agent.persistence.store import IncidentStore
from incident_agent.planning.supervisor import plan_hash
from tests.conftest import FakeDDM, StaticPlanner, alert, make_service


def _oidc(groups: list[str] | None = None) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "user-1", "email": "u@example.com", "cognito:groups": groups or ["Manager"]}).encode()
    ).decode()
    return f"header.{payload.rstrip('=')}.sig"


def _client_with_incident(store: IncidentStore) -> tuple[TestClient, str, str]:
    ddm = FakeDDM()
    service = make_service(store, ddm, StaticPlanner(Plan(summary="No action", rationale="none", actions=[])))
    incident = store.create(alert())
    plan = Plan(
        summary="Restart",
        rationale="failed",
        actions=[{"operationId": "restart_service", "reason": "health_check failed"}],
    )
    hashed_plan = plan_hash(plan)
    store.set_diagnosis(incident.id, "run-1", "http://dataplane", [], plan, hashed_plan)
    return TestClient(create_app(service)), incident.id, hashed_plan


def test_routes_preserve_openapi_and_incident_pages(store: IncidentStore) -> None:
    client, incident_id, _ = _client_with_incident(store)

    assert client.get("/healthz").json() == {"status": "ok"}
    ready = client.get("/readyz", headers={"X-Request-ID": "req-1"})
    assert ready.json() == {"status": "ready"}
    assert ready.headers["X-Request-ID"] == "req-1"
    assert "DenDenMushi Incident Agent API" in client.get("/openapi.yaml").text
    response = client.get("/incidents", headers={"x-amzn-oidc-data": _oidc()})
    assert response.status_code == 200
    assert "High 5xx" in response.text
    detail = client.get(f"/incidents/{incident_id}", headers={"x-amzn-oidc-data": _oidc()})
    assert detail.status_code == 200
    assert "Approve exact plan" in detail.text


def test_json_routes_return_safe_incident_payloads(store: IncidentStore) -> None:
    client, incident_id, hashed_plan = _client_with_incident(store)
    headers = {"x-amzn-oidc-data": _oidc(["SecurityAnalyst"]), "Accept": "application/json"}

    listing = client.get("/incidents", headers=headers)
    assert listing.status_code == 200
    incident = listing.json()["incidents"][0]
    assert incident["id"] == incident_id
    assert incident["alarmName"] == "High 5xx"
    assert incident["planHash"] == hashed_plan
    assert "operationsUrl" not in incident

    detail = client.get(f"/incidents/{incident_id}", headers=headers)
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["id"] == incident_id
    assert payload["plan"]["actions"][0]["operationId"] == "restart_service"
    assert "operationsUrl" not in payload
    assert "capabilityToken" not in payload


def test_json_decisions_require_manager_or_admin_group(store: IncidentStore) -> None:
    client, incident_id, hashed_plan = _client_with_incident(store)

    forbidden = client.post(
        f"/incidents/{incident_id}/approve",
        headers={"x-amzn-oidc-data": _oidc(["SecurityAnalyst"]), "Accept": "application/json"},
        json={"planHash": hashed_plan},
    )
    assert forbidden.status_code == 403
    assert store.get(incident_id).state == IncidentState.AWAITING_APPROVAL

    approved = client.post(
        f"/incidents/{incident_id}/approve",
        headers={"x-amzn-oidc-data": _oidc(["Admin"]), "Accept": "application/json"},
        json={"planHash": hashed_plan},
    )
    assert approved.status_code == 200
    assert approved.json()["state"] == IncidentState.EXECUTING.value
    assert approved.json()["approverSubject"] == "user-1"


def test_json_decision_plan_hash_drift_returns_conflict(store: IncidentStore) -> None:
    client, incident_id, _ = _client_with_incident(store)

    response = client.post(
        f"/incidents/{incident_id}/reject",
        headers={"x-amzn-oidc-data": _oidc(["Manager"]), "Accept": "application/json"},
        json={"planHash": "changed"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "incident changed; reload before deciding"


def test_incident_routes_require_valid_identity(store: IncidentStore) -> None:
    client, incident_id, hashed_plan = _client_with_incident(store)

    assert client.get("/incidents", headers={"Accept": "application/json"}).status_code == 401
    assert client.get(f"/incidents/{incident_id}", headers={"Accept": "application/json"}).status_code == 401
    assert (
        client.post(
            f"/incidents/{incident_id}/approve",
            headers={"Accept": "application/json"},
            json={"planHash": hashed_plan},
        ).status_code
        == 401
    )
