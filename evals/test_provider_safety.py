from __future__ import annotations

import httpx
import pytest

from evals.runner import TrackingFallback
from evals.support import incident
from incident_agent.planning.planner import FallbackPlanner, OpenAIPlanner


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
async def test_provider_denial_is_not_retried_or_fallback(status: int) -> None:
    attempts = []

    def denied(request):
        attempts.append(1)
        return httpx.Response(status, json={"error": "fixture refusal"})

    fallback = TrackingFallback()
    planner = FallbackPlanner(
        OpenAIPlanner(
            "fixture", "gpt-5.4-2026-03-05", 131072, transport=httpx.MockTransport(denied), transient_retry_attempts=2
        ),
        fallback,
    )
    with pytest.raises(ValueError):
        await planner.triage(incident())
    assert len(attempts) == 1
    assert fallback.calls == []


@pytest.mark.parametrize("body", [{}, {"output_text": "not valid JSON"}])
async def test_invalid_provider_output_is_not_fallback(body: dict) -> None:
    attempts = []

    def malformed(request):
        attempts.append(1)
        return httpx.Response(200, json=body)

    fallback = TrackingFallback()
    planner = FallbackPlanner(
        OpenAIPlanner(
            "fixture",
            "gpt-5.4-2026-03-05",
            131072,
            transport=httpx.MockTransport(malformed),
            transient_retry_attempts=2,
        ),
        fallback,
    )
    with pytest.raises(ValueError):
        await planner.triage(incident())
    assert len(attempts) == 1
    assert fallback.calls == []
