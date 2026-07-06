from __future__ import annotations

from fastapi.testclient import TestClient

from incident_agent.api.web import create_app
from incident_agent.models import Plan
from incident_agent.persistence.store import IncidentStore
from tests.conftest import FakeDDM, StaticPlanner, make_service


def test_worker_routes_preserve_health_ready_openapi_and_request_id(store: IncidentStore) -> None:
    service = make_service(store, FakeDDM(), StaticPlanner(Plan(summary="No action", rationale="none", actions=[])))
    client = TestClient(create_app(service))

    assert client.get("/healthz").json() == {"status": "ok"}
    ready = client.get("/readyz", headers={"X-Request-ID": "req-1"})
    assert ready.json() == {"status": "ready"}
    assert ready.headers["X-Request-ID"] == "req-1"
    assert "DenDenMushi Incident Agent" in client.get("/openapi.yaml").text


def test_internal_worker_health_returns_safe_status(store: IncidentStore) -> None:
    service = make_service(store, FakeDDM(), StaticPlanner(Plan(summary="No action", rationale="none", actions=[])))
    service.set_consumer_configured(True)
    service.set_consumer_running(True)
    client = TestClient(create_app(service))

    response = client.get("/internal/worker/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["databaseReady"] is True
    assert payload["queueConsumerConfigured"] is True
    assert payload["queueConsumerRunning"] is True
    assert payload["activeIncidentCount"] == 0
    assert "queueUrl" not in payload


def test_public_agentic_routes_are_no_longer_served_by_worker(store: IncidentStore) -> None:
    service = make_service(store, FakeDDM(), StaticPlanner(Plan(summary="No action", rationale="none", actions=[])))
    client = TestClient(create_app(service))

    assert client.get("/agentic-ai/health").status_code == 404
    assert client.get("/alerts").status_code == 404
    assert client.get("/incidents").status_code == 404

