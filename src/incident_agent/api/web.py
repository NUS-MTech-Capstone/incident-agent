from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response

from incident_agent.models import AgentHealth
from incident_agent.observability import REQUEST_ID_HEADER, new_request_id, use_request_id
from incident_agent.service import IncidentService


def create_app(service: IncidentService) -> FastAPI:
    app = FastAPI(title="DenDenMushi Incident Agent Worker API", version="0.1.0")

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = request.headers.get(REQUEST_ID_HEADER) or new_request_id()
        with use_request_id(request_id):
            response = await call_next(request)
            response.headers[REQUEST_ID_HEADER] = request_id
            return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, str]:
        try:
            service.ready()
        except Exception as exc:
            raise HTTPException(status_code=503, detail="service is not ready") from exc
        return {"status": "ready"}

    @app.get("/internal/worker/health")
    async def worker_health() -> JSONResponse:
        return _json(_health(service.health()))

    @app.get("/openapi.yaml")
    async def openapi_yaml() -> Response:
        path = Path(__file__).resolve().parents[3] / "api" / "openapi.yaml"
        return Response(path.read_text(encoding="utf-8"), media_type="application/yaml; charset=utf-8")

    return app


def _json(payload: dict[str, object]) -> JSONResponse:
    return JSONResponse(jsonable_encoder(payload))


def _health(health: AgentHealth) -> dict[str, object]:
    return {
        "databaseReady": health.database_ready,
        "queueConsumerConfigured": health.queue_consumer_configured,
        "queueConsumerRunning": health.queue_consumer_running,
        "lastAlertProcessedAt": health.last_alert_processed_at,
        "lastErrorSummary": health.last_error_summary,
        "activeIncidentCount": health.active_incident_count,
        "failedIncidentCount": health.failed_incident_count,
    }
