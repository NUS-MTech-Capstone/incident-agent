from __future__ import annotations

import httpx
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from incident_agent.identity import WorkloadIdentity
from incident_agent.models import OperationResult, Run
from incident_agent.tool_gateway import CallerPolicy, GatewayBackend, GatewayPolicy, create_tool_gateway_app


class IdentityClient:
    async def validate(self, token: str) -> WorkloadIdentity:
        accounts = {
            "coordinator": "incident-agent",
            "controlplane": "agent-controlplane",
            "reasoning": "incident-reasoning-agent",
        }
        account = accounts[token]
        return WorkloadIdentity(
            subject=f"system:serviceaccount:dendenmushi-agentic:{account}",
            namespace="dendenmushi-agentic",
            service_account=account,
        )


class Backend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    async def execute(self, run_id: str, phase: str, operation: str, plan_hash: str) -> OperationResult:
        self.calls.append((run_id, phase, operation, plan_hash))
        return OperationResult(operationId=operation, stdout="ok", exitCode=0)


def _policy() -> GatewayPolicy:
    return GatewayPolicy(
        version="v1",
        default="deny",
        callers={
            "system:serviceaccount:dendenmushi-agentic:incident-agent": CallerPolicy(
                phases={"diagnose": ["service_status", "health_check"]}
            ),
            "system:serviceaccount:dendenmushi-agentic:agent-controlplane": CallerPolicy(
                phases={"remediate": ["restart_service"], "verify": ["health_check"]}
            ),
        },
    )


async def _client(app, token: str):  # type: ignore[no-untyped-def]
    http_client = httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    )
    transport = streamable_http_client("http://test/mcp", http_client=http_client)
    client = Client(transport, read_timeout_seconds=5)
    return http_client, client


@pytest.mark.asyncio
async def test_mcp_discovery_is_caller_specific_and_default_deny() -> None:
    backend = Backend()
    app = create_tool_gateway_app(_policy(), backend, IdentityClient())
    async with app.router.lifespan_context(app):
        for token, expected in [
            ("coordinator", {"service_status", "health_check"}),
            ("controlplane", {"restart_service", "health_check"}),
            ("reasoning", set()),
        ]:
            http_client, mcp = await _client(app, token)
            async with http_client, mcp:
                assert {tool.name for tool in (await mcp.list_tools()).tools} == expected

        http_client, mcp = await _client(app, "coordinator")
        async with http_client, mcp:
            allowed = await mcp.call_tool("health_check", {"runId": "run-1"})
            assert not allowed.is_error
            assert allowed.structured_content["operationId"] == "health_check"

            denied = await mcp.call_tool("restart_service", {"runId": "run-1"})
            assert denied.is_error

            arbitrary = await mcp.call_tool("health_check", {"runId": "run-1", "command": "id"})
            assert arbitrary.is_error

            unnecessary_hash = await mcp.call_tool("health_check", {"runId": "run-1", "planHash": "a" * 64})
            assert unnecessary_hash.is_error

    assert backend.calls == [("run-1", "diagnose", "health_check", "")]


def test_gateway_policy_rejects_operations_outside_the_reviewed_catalog() -> None:
    policy = _policy()
    policy.callers["system:serviceaccount:dendenmushi-agentic:incident-agent"].phases["diagnose"].append(
        "restart_service"
    )
    with pytest.raises(RuntimeError, match="unsupported phase or operation"):
        create_tool_gateway_app(policy, Backend(), IdentityClient())


@pytest.mark.asyncio
async def test_mcp_requires_a_valid_projected_workload_token() -> None:
    app = create_tool_gateway_app(_policy(), Backend(), IdentityClient())
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/mcp")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_gateway_retries_reads_but_never_remediation(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = GatewayBackend("http://controlplane", "/token", 1, 4096)

    async def issue_token(run_id: str, _phase: str, _operation: str, _plan_hash: str) -> Run:
        return Run(
            runId=run_id,
            incidentId="inc-1",
            hostId="host-1",
            operationsUrl="http://dataplane",
            capabilityToken="capability-token",
        )

    monkeypatch.setattr(backend, "_issue_token", issue_token)
    calls = 0

    class FakeClient:
        def __init__(self, **_kwargs) -> None:
            pass

        async def __aenter__(self):  # type: ignore[no-untyped-def]
            return self

        async def __aexit__(self, *_args):  # type: ignore[no-untyped-def]
            return None

        async def post(self, url: str, **_kwargs) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise httpx.ConnectError("temporary", request=httpx.Request("POST", url))
            return httpx.Response(
                200,
                request=httpx.Request("POST", url),
                json={"operationId": "health_check", "stdout": "ok", "exitCode": 0},
            )

    monkeypatch.setattr("incident_agent.tool_gateway.httpx.AsyncClient", FakeClient)
    result = await backend.execute("run-1", "verify", "health_check", "a" * 64)
    assert result.operation_id == "health_check"
    assert calls == 2

    calls = 0
    with pytest.raises(RuntimeError, match="bounded operation failed"):
        await backend.execute("run-1", "remediate", "restart_service", "a" * 64)
    assert calls == 1
