from __future__ import annotations

import logging
from typing import Any, Literal

from a2a.helpers import (
    new_data_artifact_update_event,
    new_task_from_user_message,
    new_text_status_update_event,
)
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill, TaskState
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from google.protobuf.json_format import MessageToDict
from pydantic import BaseModel, Field

from incident_agent.identity import WorkloadIdentityClient
from incident_agent.models import Incident, OperationResult
from incident_agent.observability import log_event
from incident_agent.planning.planner import Planner

logger = logging.getLogger(__name__)


class AnalyzeIncidentRequest(BaseModel):
    stage: Literal["triage", "plan"]
    incident: Incident
    evidence: list[OperationResult] = Field(default_factory=list)


class ReasoningAgentExecutor(AgentExecutor):
    def __init__(self, planner: Planner):
        self.planner = planner

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        message = context.message
        if message is None:
            return
        task = new_task_from_user_message(message)
        await event_queue.enqueue_event(task)
        try:
            payload = _message_data(message)
            request = AnalyzeIncidentRequest.model_validate(payload)
            if request.stage == "triage":
                result = (await self.planner.triage(request.incident)).model_dump(by_alias=True, mode="json")
            else:
                result = (await self.planner.plan(request.incident, request.evidence)).model_dump(
                    by_alias=True, mode="json"
                )
            await event_queue.enqueue_event(
                new_data_artifact_update_event(
                    task.id,
                    task.context_id,
                    "analysis",
                    result,
                    media_type="application/json",
                    last_chunk=True,
                )
            )
            await event_queue.enqueue_event(
                new_text_status_update_event(
                    task.id,
                    task.context_id,
                    TaskState.TASK_STATE_COMPLETED,
                    "Structured analysis completed.",
                )
            )
        except Exception as exc:  # noqa: BLE001 - errors become a bounded A2A failure
            log_event(logger, "AgentDelegationFailed", stage="unknown", errorKind=type(exc).__name__)
            await event_queue.enqueue_event(
                new_text_status_update_event(
                    task.id,
                    task.context_id,
                    TaskState.TASK_STATE_FAILED,
                    "Structured analysis failed.",
                )
            )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.task_id and context.context_id:
            await event_queue.enqueue_event(
                new_text_status_update_event(
                    context.task_id,
                    context.context_id,
                    TaskState.TASK_STATE_CANCELED,
                    "Analysis canceled.",
                )
            )


def create_reasoning_app(
    planner: Planner,
    identity_client: WorkloadIdentityClient,
    interface_url: str,
) -> FastAPI:
    card = AgentCard(
        name="DenDenMushi Incident Reasoning Agent",
        description="Stateless bounded incident triage and plan generation.",
        version="1.0.0",
        capabilities=AgentCapabilities(streaming=True, push_notifications=False),
        default_input_modes=["application/json"],
        default_output_modes=["application/json", "task-status"],
        skills=[
            AgentSkill(
                id="analyze_incident",
                name="Analyze Incident",
                description="Triage an incident or propose one bounded remediation plan.",
                tags=["incident", "triage", "planning"],
                examples=["triage", "plan"],
                input_modes=["application/json"],
                output_modes=["application/json", "task-status"],
            )
        ],
        supported_interfaces=[
            AgentInterface(
                protocol_binding="JSONRPC",
                protocol_version="1.0",
                url=interface_url.rstrip("/") + "/",
            )
        ],
    )
    handler = DefaultRequestHandler(
        agent_executor=ReasoningAgentExecutor(planner),
        task_store=InMemoryTaskStore(),
        agent_card=card,
    )
    app = FastAPI(routes=[*create_agent_card_routes(card), *create_jsonrpc_routes(handler, rpc_url="/")])

    @app.middleware("http")
    async def authenticate_a2a(request: Request, call_next: Any) -> Any:
        if request.url.path not in {"/healthz", "/readyz"}:
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return JSONResponse({"error": "workload identity is required"}, status_code=401)
            try:
                identity = await identity_client.validate(header.removeprefix("Bearer ").strip())
            except Exception:  # noqa: BLE001 - never expose token validation details
                return JSONResponse({"error": "workload identity is not authorized"}, status_code=403)
            if identity.service_account != "incident-agent" or identity.namespace != "dendenmushi-agentic":
                return JSONResponse({"error": "workload identity is not authorized"}, status_code=403)
        return await call_next(request)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, str]:
        return {"status": "ready"}

    return app


def _message_data(message: Any) -> dict[str, Any]:
    for part in message.parts:
        if part.HasField("data"):
            value = MessageToDict(part.data)
            if isinstance(value, dict):
                return value
    raise ValueError("A2A message requires one structured data part")
