from __future__ import annotations

from pathlib import Path

import httpx
from pydantic import BaseModel


class WorkloadIdentity(BaseModel):
    subject: str
    namespace: str
    service_account: str


class WorkloadIdentityClient:
    def __init__(self, sts_url: str, timeout_seconds: float):
        self.sts_url = sts_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def validate(self, token: str) -> WorkloadIdentity:
        if not token.strip():
            raise ValueError("workload token is required")
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(
                f"{self.sts_url}/workloads/validate",
                headers={
                    "Authorization": f"Bearer {token}",
                    "x-api-version": "1",
                },
            )
            response.raise_for_status()
        payload = response.json()
        return WorkloadIdentity(
            subject=str(payload.get("subject", "")),
            namespace=str(payload.get("namespace", "")),
            service_account=str(payload.get("serviceAccount", "")),
        )


def read_workload_token(path: str) -> str:
    token = Path(path).read_text(encoding="utf-8").strip()
    if not token:
        raise RuntimeError("projected workload token is empty")
    return token
