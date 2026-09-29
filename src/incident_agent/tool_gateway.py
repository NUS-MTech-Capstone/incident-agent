from __future__ import annotations

import contextlib
import json
import logging
import re
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
from mcp import types
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware, get_access_token
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, RequireAuthMiddleware
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, Field
from starlette.applications import Starlette
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from incident_agent.identity import WorkloadIdentityClient, read_workload_token
from incident_agent.models import OperationResult, Run
from incident_agent.observability import emit_metric, log_event
from incident_agent.planning.catalog import (
    DIAGNOSTIC_OPERATIONS,
    REMEDIATION_OPERATIONS,
    VERIFY_OPERATIONS,
)
from incident_agent.redact import text as redact_text

logger = logging.getLogger(__name__)


class CallerPolicy(BaseModel):
    phases: dict[str, list[str]] = Field(default_factory=dict)


class GatewayPolicy(BaseModel):
    version: str
    default: str
    callers: dict[str, CallerPolicy]

    @classmethod
    def load(cls, path: str) -> GatewayPolicy:
        if not path:
            raise RuntimeError("TOOL_POLICY_FILE is required")
        policy = cls.model_validate_json(Path(path).read_text(encoding="utf-8"))
        if policy.version != "v1" or policy.default != "deny":
            raise RuntimeError("tool policy must be version v1 with default deny")
        return policy

    def allows(self, subject: str, phase: str, operation: str) -> bool:
        caller = self.callers.get(subject)
        if caller is None:
            return False
        return operation in caller.phases.get(phase, [])

    def tools_for(self, subject: str) -> list[tuple[str, str]]:
        caller = self.callers.get(subject)
        if caller is None:
            return []
        tools: list[tuple[str, str]] = []
        for phase, operations in caller.phases.items():
            tools.extend((operation, phase) for operation in operations)
        return tools

    def validate_catalog(self) -> None:
        catalogs = {
            "diagnose": DIAGNOSTIC_OPERATIONS,
            "remediate": REMEDIATION_OPERATIONS,
            "verify": VERIFY_OPERATIONS,
        }
        for caller in self.callers.values():
            for phase, operations in caller.phases.items():
                if phase not in catalogs or any(operation not in catalogs[phase] for operation in operations):
                    raise RuntimeError("tool policy contains an unsupported phase or operation")


class STSWorkloadTokenVerifier(TokenVerifier):
    def __init__(self, identities: WorkloadIdentityClient):
        self.identities = identities

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            identity = await self.identities.validate(token)
        except Exception:  # noqa: BLE001 - authentication failures are intentionally uniform
            return None
        return AccessToken(
            token=token,
            client_id=identity.service_account,
            scopes=["tools"],
            subject=identity.subject,
            claims={"namespace": identity.namespace, "serviceAccount": identity.service_account},
        )


class GatewayBackend:
    def __init__(
        self,
        control_plane_url: str,
        workload_token_file: str,
        timeout_seconds: float,
        max_output_bytes: int,
    ):
        self.control_plane_url = control_plane_url.rstrip("/")
        self.workload_token_file = workload_token_file
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    async def execute(self, run_id: str, phase: str, operation: str, plan_hash: str) -> OperationResult:
        run = await self._issue_token(run_id, phase, operation, plan_hash)
        attempts = 1 if phase == "remediate" else 2
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    response = await client.post(
                        f"{run.operations_url.rstrip('/')}/automation/runs/{run_id}/operations",
                        headers={"Authorization": f"Bearer {run.capability_token}", "x-api-version": "1"},
                        json={"operationId": operation, "planHash": plan_hash},
                    )
                    response.raise_for_status()
                result = OperationResult.model_validate(response.json())
                result.stdout = redact_text(result.stdout, self.max_output_bytes)
                result.stderr = redact_text(result.stderr, self.max_output_bytes)
                return result
            except Exception as exc:  # noqa: BLE001 - provider exceptions vary
                last_error = exc
                if attempt >= attempts or not _is_transient(exc):
                    raise RuntimeError("bounded operation failed") from exc
        raise RuntimeError("bounded operation failed") from last_error

    async def _issue_token(self, run_id: str, phase: str, operation: str, plan_hash: str) -> Run:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(
                f"{self.control_plane_url}/automation/runs/{run_id}/token",
                headers={
                    "Authorization": f"Bearer {read_workload_token(self.workload_token_file)}",
                    "x-api-version": "1",
                },
                json={"phase": phase, "allowedOperations": [operation], "planHash": plan_hash},
            )
            response.raise_for_status()
        return Run.model_validate(response.json())


def create_tool_gateway_app(
    policy: GatewayPolicy,
    backend: GatewayBackend,
    identity_client: WorkloadIdentityClient,
) -> Starlette:
    policy.validate_catalog()

    async def list_tools(
        _ctx: ServerRequestContext[Any], _params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        subject = _subject()
        tools = [_tool(operation, phase) for operation, phase in policy.tools_for(subject)]
        return types.ListToolsResult(tools=tools, cache_scope="private")

    async def call_tool(_ctx: ServerRequestContext[Any], params: types.CallToolRequestParams) -> types.CallToolResult:
        subject = _subject()
        operation = params.name
        phase = _phase_for(subject, operation)
        arguments = params.arguments or {}
        run_id = arguments.get("runId")
        plan_hash = arguments.get("planHash", "")
        allowed_arguments = {"runId", "planHash"} if phase in {"remediate", "verify"} else {"runId"}
        if set(arguments) - allowed_arguments or not isinstance(run_id, str) or not run_id.strip():
            log_event(logger, "ToolCallDenied", operation=operation, caller=subject, phase=phase, reason="arguments")
            return _tool_error("tool arguments are invalid")
        if phase in {"remediate", "verify"} and (
            not isinstance(plan_hash, str) or re.fullmatch(r"[0-9a-f]{64}", plan_hash) is None
        ):
            log_event(
                logger,
                "ToolCallDenied",
                runId=run_id,
                operation=operation,
                caller=subject,
                phase=phase,
                reason="plan_hash",
            )
            return _tool_error("planHash is required")
        if phase == "" or not policy.allows(subject, phase, operation):
            log_event(logger, "ToolCallDenied", runId=run_id, operation=operation, caller=subject, phase=phase)
            return _tool_error("tool call is not allowed")
        started = time.monotonic()
        log_event(logger, "ToolCallAllowed", runId=run_id, operation=operation, caller=subject, phase=phase)
        try:
            result = await backend.execute(run_id, phase, operation, str(plan_hash))
        except Exception as exc:  # noqa: BLE001 - never expose capability or upstream details
            emit_metric("ToolCallFailures", 1, phase=phase, operation=operation)
            log_event(
                logger,
                "ToolCallFailed",
                runId=run_id,
                operation=operation,
                caller=subject,
                phase=phase,
                errorKind=type(exc).__name__,
            )
            return _tool_error("bounded tool execution failed")
        payload = result.model_dump(by_alias=True)
        log_event(
            logger,
            "ToolCallCompleted",
            runId=run_id,
            operation=operation,
            caller=subject,
            phase=phase,
            exitCode=result.exit_code,
            durationMs=round((time.monotonic() - started) * 1000, 2),
        )
        return types.CallToolResult(
            content=[types.TextContent(text=json.dumps(payload, separators=(",", ":")))],
            structured_content=payload,
        )

    server = Server("dendenmushi-tool-gateway", version="1.0.0", on_list_tools=list_tools, on_call_tool=call_tool)
    manager = StreamableHTTPSessionManager(
        server,
        json_response=True,
        stateless=True,
        security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        max_request_body_size=65536,
    )
    verifier = STSWorkloadTokenVerifier(identity_client)
    protected = AuthenticationMiddleware(
        AuthContextMiddleware(RequireAuthMiddleware(manager.handle_request, required_scopes=["tools"])),
        backend=BearerAuthBackend(verifier),
    )

    async def healthz(_request: Any) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    async def readyz(_request: Any) -> JSONResponse:
        return JSONResponse({"status": "ready", "policyVersion": policy.version})

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            yield

    return Starlette(
        routes=[
            Route("/healthz", healthz),
            Route("/readyz", readyz),
            Route("/mcp", protected, methods=["GET", "POST", "DELETE"]),
        ],
        lifespan=lifespan,
    )


def _subject() -> str:
    token = get_access_token()
    if token is None or not token.subject:
        return ""
    return token.subject


def _phase_for(subject: str, operation: str) -> str:
    if subject.endswith(":incident-agent") and operation in DIAGNOSTIC_OPERATIONS:
        return "diagnose"
    if subject.endswith(":agent-controlplane") and operation in REMEDIATION_OPERATIONS:
        return "remediate"
    if subject.endswith(":agent-controlplane") and operation in VERIFY_OPERATIONS:
        return "verify"
    return ""


def _tool(operation: str, phase: str) -> types.Tool:
    properties: dict[str, Any] = {"runId": {"type": "string", "minLength": 1}}
    required = ["runId"]
    if phase in {"remediate", "verify"}:
        properties["planHash"] = {"type": "string", "minLength": 64, "maxLength": 64}
        required.append("planHash")
    return types.Tool(
        name=operation,
        title=operation.replace("_", " ").title(),
        description=f"Run the bounded {phase} operation {operation}.",
        input_schema={
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
    )


def _tool_error(message: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(text=message)], is_error=True)


def _is_transient(exc: Exception) -> bool:
    if isinstance(exc, httpx.TimeoutException | httpx.NetworkError):
        return True
    return isinstance(exc, httpx.HTTPStatusError) and (
        exc.response.status_code == 429 or 500 <= exc.response.status_code < 600
    )
