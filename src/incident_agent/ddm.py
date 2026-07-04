from __future__ import annotations

from pathlib import Path

import httpx

from incident_agent.models import OperationResult, Run


class DDMClient:
    def __init__(self, control_plane_url: str, workload_token_file: str, timeout: float = 10.0):
        self.control_plane_url = control_plane_url.rstrip("/")
        self.workload_token_file = Path(workload_token_file)
        self.timeout = timeout

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
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.control_plane_url}/automation/runs/{run_id}/close",
                headers={"Authorization": f"Bearer {capability_token}"},
                json={},
            )
            response.raise_for_status()

    async def execute(
        self,
        operations_url: str,
        run_id: str,
        capability_token: str,
        operation_id: str,
        plan_hash: str = "",
    ) -> OperationResult:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{operations_url.rstrip('/')}/automation/runs/{run_id}/operations",
                headers={"Authorization": f"Bearer {capability_token}"},
                json={"operationId": operation_id, "planHash": plan_hash},
            )
            response.raise_for_status()
            return OperationResult.model_validate(response.json())

    async def _control_request(self, path: str, payload: dict[str, object]) -> Run:
        token = self.workload_token_file.read_text(encoding="utf-8").strip()
        if not token:
            raise RuntimeError("projected workload token is empty")
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.control_plane_url}{path}",
                headers={"Authorization": f"Bearer {token}"},
                json=payload,
            )
            response.raise_for_status()
            return Run.model_validate(response.json())
