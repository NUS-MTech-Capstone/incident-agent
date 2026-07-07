from __future__ import annotations

import json

import httpx
import pytest

from incident_agent.automation.ddm import DDMClient


@pytest.mark.asyncio
async def test_ddm_start_run_payload(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("workload-token", encoding="utf-8")
    captured: dict[str, object] = {}

    async def fake_post(self, url: str, headers: dict[str, str], json: dict[str, object]):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={
                "runId": "run-1",
                "incidentId": "inc-1",
                "hostId": "host-1",
                "operationsUrl": "http://dataplane",
                "capabilityToken": "cap-token",
            },
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    client = DDMClient("http://control", str(token_file), 1)
    run = await client.start_run("inc-1", "host-1", ["health_check"])
    assert run.run_id == "run-1"
    assert captured["url"] == "http://control/automation/runs/start"
    assert captured["headers"] == {
        "Authorization": "Bearer workload-token",
        "x-api-version": "1",
    }
    assert json.dumps(captured["json"], sort_keys=True)
