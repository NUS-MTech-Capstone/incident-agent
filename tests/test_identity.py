from __future__ import annotations

import pytest

from incident_agent.identity import WorkloadIdentityClient


@pytest.mark.asyncio
async def test_workload_identity_validation_sends_sts_api_version(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {
                "subject": "system:serviceaccount:dendenmushi-agentic:incident-agent",
                "namespace": "dendenmushi-agentic",
                "serviceAccount": "incident-agent",
            }

    class Client:
        def __init__(self, timeout: float):
            captured["timeout"] = timeout

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def post(self, url: str, *, headers: dict[str, str]) -> Response:
            captured["url"] = url
            captured["headers"] = headers
            return Response()

    monkeypatch.setattr("incident_agent.identity.httpx.AsyncClient", Client)

    identity = await WorkloadIdentityClient("http://sts", 3.0).validate("projected-token")

    assert identity.service_account == "incident-agent"
    assert captured == {
        "timeout": 3.0,
        "url": "http://sts/workloads/validate",
        "headers": {
            "Authorization": "Bearer projected-token",
            "x-api-version": "1",
        },
    }
