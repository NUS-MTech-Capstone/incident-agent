from __future__ import annotations

import asyncio
import json
import threading
import time

import httpx
import pytest

from evals.support import incident
from incident_agent.config import Settings
from incident_agent.main import _build_planner
from incident_agent.model_trace import TraceSink, create_trace_sink, metadata_projection, span
from incident_agent.planning.planner import FallbackPlanner, OpenAIPlanner, RuleBasedPlanner


class CaptureClient:
    def __init__(self, error=None):
        self.rows = []
        self.error = error

    def create_run(self, **payload):
        if self.error:
            raise self.error
        self.rows.append(payload)


def planner(sink, transport=None):
    return OpenAIPlanner(
        "fixture",
        "gpt-5.4-2026-03-05",
        131072,
        trace_sink=sink,
        transient_retry_attempts=1,
        transport=transport
        or httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "model": "gpt-5.4-2026-03-05",
                    "usage": {"input_tokens": 10, "output_tokens": 20},
                    "output_text": json.dumps(
                        {
                            "priority": "medium",
                            "category": "availability",
                            "summary": "healthy",
                            "rationale": "safe",
                            "suggestedDiagnosticOperationIds": [],
                        }
                    ),
                },
            )
        ),
    )


async def test_concurrent_traces_isolate_parent_and_omit_bodies():
    client = CaptureClient()
    sink = TraceSink(client, "test")
    runtime = planner(sink)
    subjects = [incident("R12-S01"), incident("R12-S02")]
    for subject in subjects:
        subject.reason = "password=PRIVATE_SENTINEL diagnostic confidential text"
    results = await asyncio.gather(*(runtime.triage(subject) for subject in subjects))
    sink.close()
    assert [r.priority.value for r in results] == ["medium", "medium"]
    assert len(client.rows) == 6
    roots = [r for r in client.rows if r["parent_run_id"] is None]
    assert len(roots) == 2
    for root in roots:
        children = [r for r in client.rows if r["parent_run_id"] == root["id"]]
        assert {r["name"] for r in children} == {"provider_attempt", "result_validation"}
        assert all(r["extra"]["metadata"]["incident_id"] == root["extra"]["metadata"]["incident_id"] for r in children)
        assert all(r["trace_id"] == root["id"] for r in children)
    encoded = json.dumps(client.rows, default=str)
    assert "PRIVATE_SENTINEL" not in encoded and "diagnostic confidential" not in encoded
    assert all(r["inputs"] == {} and r["outputs"] == {} for r in client.rows)
    assert "prompt_hashes" in encoded


@pytest.mark.parametrize("status", [401, 403, 429, 500])
async def test_export_http_errors_do_not_change_model_result(status, caplog):
    error = httpx.HTTPStatusError(
        "SECRET_ERROR_BODY", request=httpx.Request("POST", "https://example.invalid"), response=httpx.Response(status)
    )
    sink = TraceSink(CaptureClient(error), "test")
    result = await planner(sink).triage(incident())
    sink.close()
    assert result.priority.value == "medium"
    assert sink.failed == 3 and sink.submitted == 0
    assert "SECRET_ERROR_BODY" not in caplog.text


async def test_export_timeout_does_not_trigger_provider_fallback():
    sink = TraceSink(CaptureClient(httpx.ReadTimeout("PRIVATE_BODY")), "test")
    result = await FallbackPlanner(planner(sink), RuleBasedPlanner()).triage(incident())
    sink.close()
    assert result.summary == "healthy"
    assert sink.failed == 3


async def test_provider_failure_and_rule_fallback_are_separate_safe_traces():
    client = CaptureClient()
    sink = TraceSink(client, "test")
    primary = planner(sink, httpx.MockTransport(lambda _: httpx.Response(503, text="PRIVATE_ERROR_BODY")))
    result = await FallbackPlanner(primary, RuleBasedPlanner()).triage(incident("R12-S01"))
    sink.close()
    assert result.summary != "healthy"
    assert any(r["name"] == "deterministic_fallback" and r["extra"]["metadata"]["fallback"] for r in client.rows)
    assert any(r["error"] == "operation_failed" for r in client.rows)
    assert "PRIVATE_ERROR_BODY" not in json.dumps(client.rows, default=str)


async def test_validation_failure_is_not_disguised_as_model_success():
    client = CaptureClient()
    sink = TraceSink(client, "test")
    with pytest.raises(ValueError):
        await planner(
            sink, httpx.MockTransport(lambda _: httpx.Response(200, json={"output_text": "PRIVATE_BAD_JSON"}))
        ).triage(incident())
    sink.close()
    validation = next(r for r in client.rows if r["name"] == "result_validation")
    assert validation["error"] == "operation_failed"
    assert "PRIVATE_BAD_JSON" not in json.dumps(client.rows, default=str)


def test_export_queue_and_shutdown_are_bounded():
    entered, release = threading.Event(), threading.Event()

    class SlowClient:
        def create_run(self, **payload):
            entered.set()
            release.wait(2)

    sink = TraceSink(SlowClient(), "test", capacity=1)
    with span(sink, "reasoning"):
        pass
    assert entered.wait(1)
    for _ in range(10):
        with span(sink, "reasoning"):
            pass
    start = time.monotonic()
    sink.close(0.01)
    assert time.monotonic() - start < 0.5
    assert sink.pending.qsize() <= 1 and sink.dropped >= 9
    release.set()
    sink.worker.join(2)
    assert not sink.worker.is_alive()


@pytest.mark.parametrize("enabled,key", [("false", "fixture"), ("true", "")])
def test_disabled_or_missing_key_does_not_construct_client(monkeypatch, enabled, key):
    monkeypatch.setenv("LANGSMITH_TRACING", enabled)
    monkeypatch.setenv("LANGSMITH_API_KEY", key)
    monkeypatch.setattr("incident_agent.model_trace.Client", lambda **_: pytest.fail("must not construct client"))
    assert create_trace_sink() is None


def test_metadata_is_allowlisted_not_only_redacted():
    projected = metadata_projection(
        {
            "headers": "SECRET",
            "prompt": "SECRET",
            "incident_id": "password=SECRET",
            "model": "SECRET",
            "outcome": "SECRET",
            "attempt": True,
            "input_tokens": -1,
            "stage": "plan",
            "prompt_hashes": {"secret": "a" * 64},
        }
    )
    assert projected["stage"] == "plan"
    assert "SECRET" not in json.dumps(projected)
    assert projected["prompt_hashes"] == {}


def test_reviewed_snapshot_and_runtime_tracer_wiring():
    sink = TraceSink(CaptureClient(), "test")
    runtime = _build_planner(
        Settings(PLANNER_MODE="openai", OPENAI_MODEL="gpt-5.5-2026-04-23", OPENAI_API_KEY="fixture"), sink
    )
    assert runtime.trace_sink is sink
    sink.close()
