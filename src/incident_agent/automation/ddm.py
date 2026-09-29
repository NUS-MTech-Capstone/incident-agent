from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TypeVar

import httpx
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from incident_agent.models import OperationResult, Run
from incident_agent.observability import emit_metric

API_VERSION_HEADER = "x-api-version"
SUPPORTED_API_VERSION = "1"

T = TypeVar("T")


class DDMClient:
    def __init__(
        self,
        control_plane_url: str,
        workload_token_file: str,
        timeout: float = 10.0,
        transient_retry_attempts: int = 2,
        tool_gateway_url: str = "http://localhost:8094/mcp",
    ):
        self.control_plane_url = control_plane_url.rstrip("/")
        self.tool_gateway_url = tool_gateway_url
        self.workload_token_file = Path(workload_token_file)
        self.timeout = timeout
        self.transient_retry_attempts = max(1, transient_retry_attempts)

    async def start_run(self, incident_id: str, host_id: str, operations: list[str]) -> Run:
        return await self._control_request(
            "/automation/runs/start",
            {
                "incidentId": incident_id,
                "hostId": host_id,
                "phase": "diagnose",
                "allowedOperations": operations,
            },
        )

    async def close_run(self, run_id: str) -> None:
        token = self._workload_token()

        async def call() -> None:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.control_plane_url}/automation/runs/{run_id}/close",
                    headers={
                        "Authorization": f"Bearer {token}",
                        API_VERSION_HEADER: SUPPORTED_API_VERSION,
                    },
                    json={},
                )
                response.raise_for_status()

        await self._with_retry("close_run", call)

    async def execute(
        self,
        run_id: str,
        operation_id: str,
        plan_hash: str = "",
    ) -> OperationResult:
        arguments: dict[str, str] = {"runId": run_id}
        if plan_hash:
            arguments["planHash"] = plan_hash
        async with httpx2.AsyncClient(
            headers={"Authorization": f"Bearer {self._workload_token()}"},
            timeout=self.timeout,
        ) as http_client:
            transport = streamable_http_client(self.tool_gateway_url, http_client=http_client)
            async with Client(transport, read_timeout_seconds=self.timeout) as client:
                await client.list_tools()
                response = await client.call_tool(operation_id, arguments)
        if response.is_error:
            raise RuntimeError("tool gateway denied or failed the operation")
        if response.structured_content:
            return OperationResult.model_validate(response.structured_content)
        for content in response.content:
            text = getattr(content, "text", "")
            if text:
                return OperationResult.model_validate(json.loads(text))
        raise RuntimeError("tool gateway returned no operation result")

    async def _control_request(self, path: str, payload: dict[str, object]) -> Run:
        token = self._workload_token()

        async def call() -> Run:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.control_plane_url}{path}",
                    headers={
                        "Authorization": f"Bearer {token}",
                        API_VERSION_HEADER: SUPPORTED_API_VERSION,
                    },
                    json=payload,
                )
                response.raise_for_status()
                return Run.model_validate(response.json())

        operation = str(payload.get("phase") or path.rsplit("/", 1)[-1])
        return await self._with_retry(operation, call)

    def _workload_token(self) -> str:
        token = self.workload_token_file.read_text(encoding="utf-8").strip()
        if not token:
            raise RuntimeError("projected workload token is empty")
        return token

    async def _with_retry(self, operation: str, call: Callable[[], Awaitable[T]]) -> T:
        last_error: Exception | None = None
        for attempt in range(1, self.transient_retry_attempts + 1):
            started = time.monotonic()
            try:
                result = await call()
                emit_metric(
                    "DDMOperationLatencyMs", (time.monotonic() - started) * 1000, "Milliseconds", operation=operation
                )
                return result
            except Exception as exc:  # noqa: BLE001 - httpx/provider exceptions vary
                last_error = exc
                if not _is_transient(exc):
                    emit_metric("DDMOperationErrors", 1, operation=operation, errorKind=type(exc).__name__)
                    raise
                emit_metric("DDMOperationErrors", 1, operation=operation, errorKind=type(exc).__name__)
                if attempt >= self.transient_retry_attempts:
                    raise
                await asyncio.sleep(0.1 * attempt)
        raise RuntimeError("DDM operation failed") from last_error


def _is_transient(exc: Exception) -> bool:
    if isinstance(exc, httpx.TimeoutException | httpx.NetworkError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return 500 <= exc.response.status_code < 600 or exc.response.status_code == 429
    return False
