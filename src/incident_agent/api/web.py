from __future__ import annotations

from collections.abc import Awaitable, Callable
from importlib.resources import files
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response

from incident_agent.models import AgentHealth
from incident_agent.observability import REQUEST_ID_HEADER, new_request_id, use_request_id
from incident_agent.service import IncidentService

API_VERSION_HEADER = "x-api-version"
SUPPORTED_API_VERSION = "1"
API_VERSION_EXEMPT_PATHS = {"/healthz", "/readyz", "/openapi.yaml", "/asyncapi.yaml"}


def create_app(service: IncidentService) -> FastAPI:
    app = FastAPI(title="DenDenMushi Incident Agent Worker API", version="0.1.0")

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = request.headers.get(REQUEST_ID_HEADER) or new_request_id()
        with use_request_id(request_id):
            response = await call_next(request)
            response.headers[REQUEST_ID_HEADER] = request_id
            return response

    @app.middleware("http")
    async def api_version_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.url.path in API_VERSION_EXEMPT_PATHS:
            return await call_next(request)
        if request.headers.get(API_VERSION_HEADER) != SUPPORTED_API_VERSION:
            return JSONResponse(
                {"error": f'missing or unsupported {API_VERSION_HEADER}, expected "{SUPPORTED_API_VERSION}"'},
                status_code=400,
            )
        return await call_next(request)

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
        packaged = files("incident_agent").joinpath("openapi.yaml")
        # Wheels carry their own contract; editable checkouts use the owning API file.
        content = (
            packaged.read_bytes()
            if packaged.is_file()
            else (Path(__file__).resolve().parents[3] / "api" / "openapi.yaml").read_bytes()
        )
        return Response(content, media_type="application/yaml; charset=utf-8")

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
