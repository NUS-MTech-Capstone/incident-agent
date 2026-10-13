from __future__ import annotations

import json

import httpx
import pytest

from evals.model_comparison import CASES, CORPUS, MODELS, BudgetTransport, cost, evaluate_checks, run, usage_projection
from evals.support import FixtureTools
from incident_agent.models import Plan


def request():
    return httpx.Request(
        "POST", "https://example.invalid", json={"model": "openai/" + MODELS[0], "max_output_tokens": 4096}
    )


def test_case_selection_is_frozen_balanced_and_preserves_r12():
    ids = [i for category in CASES.values() for i in category]
    corpus = json.loads(CORPUS.read_text())
    assert all(len(items) == 2 for items in CASES.values())
    assert len(set(ids)) == 10
    assert set(ids) <= {c["id"] for c in corpus["cases"]}


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"usage": {}},
        {"usage": {"input_tokens": -1, "output_tokens": 1}},
        {"usage": {"input_tokens": True, "output_tokens": 1}},
    ],
)
def test_missing_or_invalid_usage_is_not_zero(data):
    assert usage_projection(data) is None


def test_cached_cost_and_reasoning_are_not_double_counted():
    usage = usage_projection(
        {
            "usage": {
                "input_tokens": 1000,
                "output_tokens": 100,
                "input_tokens_details": {"cached_tokens": 400},
                "output_tokens_details": {"reasoning_tokens": 50},
            }
        }
    )
    assert cost(MODELS[0], usage) == pytest.approx(0.0031)


async def test_budget_is_reserved_on_disk_before_network_and_reconciles(tmp_path):
    def response(req):
        saved = json.loads((tmp_path / "budget.json").read_text())
        assert saved["requests"][0]["status"] == "reserved"
        assert saved["accounted_usd"] > 0
        return httpx.Response(200, json={"model": MODELS[0], "usage": {"input_tokens": 20, "output_tokens": 5}})

    transport = BudgetTransport(tmp_path, httpx.MockTransport(response))
    await transport.handle_async_request(request())
    assert transport.requests[0]["estimated_usd"] == transport.accounted
    assert transport.accounted < transport.requests[0]["reserved_usd"]
    assert transport.requests[0]["returned_model"] == MODELS[0]


async def test_stop_before_spending_ceiling(tmp_path):
    transport = BudgetTransport(tmp_path, httpx.MockTransport(lambda _: pytest.fail("must not send")), ceiling=0.0001)
    with pytest.raises(RuntimeError, match="budget_limit"):
        await transport.handle_async_request(request())
    assert transport.requests == []


@pytest.mark.parametrize("outcome", ["timeout", "missing_usage", "http_error"])
async def test_uncertain_requests_keep_full_reservation(tmp_path, outcome):
    def response(req):
        if outcome == "timeout":
            raise httpx.ReadTimeout("private envelope")
        return httpx.Response(200 if outcome == "missing_usage" else 403, json={})

    transport = BudgetTransport(tmp_path, httpx.MockTransport(response))
    if outcome == "timeout":
        with pytest.raises(httpx.ReadTimeout):
            await transport.handle_async_request(request())
    else:
        await transport.handle_async_request(request())
    row = transport.requests[0]
    assert row["estimated_usd"] is None and row["usage"] is None
    assert row["accounted_usd"] == row["reserved_usd"] > 0
    assert "private envelope" not in (tmp_path / "budget.json").read_text()
    if outcome == "http_error":
        assert transport.stop_reason == "provider_configuration_or_authorization"


def test_scoring_distinguishes_wrong_allowed_action_from_unsafe_output():
    case = {"actions": [["restart_service"]]}
    wrong = Plan(
        summary="Recover application",
        rationale="Health failed",
        actions=[{"operationId": "recover_demo_app", "reason": "Health failed"}],
    )
    checks = evaluate_checks("plan", wrong, case, FixtureTools({}))
    assert not checks["action_set"] and checks["no_mutation"]
    unsafe = Plan.model_construct(
        summary="Unsafe", rationale="Unsafe", actions=[type("Unsupported", (), {"operation_id": "run_shell"})()]
    )
    with pytest.raises(ValueError):
        evaluate_checks("plan", unsafe, case, FixtureTools({}))


async def test_failed_scored_runs_are_recorded_without_becoming_baseline(monkeypatch, tmp_path):
    class UnavailablePlanner:
        def __init__(self, *args, **kwargs):
            self.trace_sink = None

        async def triage(self, subject):
            raise RuntimeError("PRIVATE_PROVIDER_FAILURE")

        async def plan(self, subject, evidence):
            raise RuntimeError("PRIVATE_PROVIDER_FAILURE")

    async def no_wait(self):
        return None

    monkeypatch.setattr("evals.model_comparison.OpenAIPlanner", UnavailablePlanner)
    monkeypatch.setattr("evals.model_comparison.gateway_url", lambda: "https://example.invalid")
    monkeypatch.setattr("evals.model_comparison.Session", lambda **_: None)
    monkeypatch.setattr(BudgetTransport, "pace", no_wait)
    await run(tmp_path, "capstone", False)
    rows = json.loads((tmp_path / "results.json").read_text())
    baseline = [r for r in rows if r["model"] == "rule_based"]
    scored = [r for r in rows if r["model"] in MODELS]
    assert len(baseline) == 20 and all(r["verdict"] == "pass" and r["provider_request"] is None for r in baseline)
    assert len(scored) == 40 and all(r["verdict"] == "error" and not r["fallback_used"] for r in scored)
    assert "PRIVATE_PROVIDER_FAILURE" not in (tmp_path / "results.json").read_text()
