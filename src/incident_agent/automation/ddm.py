from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TypeVar

import httpx

from incident_agent.models import OperationResult, Run
from incident_agent.observability import emit_metric

T = TypeVar("T")


class DDMClient:
    def __init__(
        self,
        control_plane_url: str,
        workload_token_file: str,
        timeout: float = 10.0,
        transient_retry_attempts: int = 2,
    ):
        self.control_plane_url = control_plane_url.rstrip("/")
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

    async def issue_token(self, run_id: str, phase: str, operations: list[str], plan_hash: str = "") -> Run:
        return await self._control_request(
            f"/automation/runs/{run_id}/token",
            {"phase": phase, "allowedOperations": operations, "planHash": plan_hash},
        )

    async def close_run(self, run_id: str, capability_token: str) -> None:
        async def call() -> None:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.control_plane_url}/automation/runs/{run_id}/close",
                    headers={"Authorization": f"Bearer {capability_token}"},
                    json={},
                )
                response.raise_for_status()

        await self._with_retry("close_run", call)

    async def execute(
        self,
        operations_url: str,
        run_id: str,
        capability_token: str,
        operation_id: str,
        plan_hash: str = "",
    ) -> OperationResult:
        async def call() -> OperationResult:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{operations_url.rstrip('/')}/automation/runs/{run_id}/operations",
                    headers={"Authorization": f"Bearer {capability_token}"},
                    json={"operationId": operation_id, "planHash": plan_hash},
                )
                response.raise_for_status()
                return OperationResult.model_validate(response.json())

        return await self._with_retry(operation_id, call)

    async def _control_request(self, path: str, payload: dict[str, object]) -> Run:
        token = self.workload_token_file.read_text(encoding="utf-8").strip()
        if not token:
            raise RuntimeError("projected workload token is empty")

        async def call() -> Run:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.control_plane_url}{path}",
                    headers={"Authorization": f"Bearer {token}"},
                    json=payload,
                )
                response.raise_for_status()
                return Run.model_validate(response.json())

        operation = str(payload.get("phase") or path.rsplit("/", 1)[-1])
        return await self._with_retry(operation, call)

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
