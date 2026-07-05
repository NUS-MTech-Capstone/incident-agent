from __future__ import annotations

import json
import logging

from incident_agent.observability import JsonFormatter, emit_metric, use_request_id


def test_json_formatter_redacts_sensitive_fields() -> None:
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "event", (), None)
    record.incidentId = "inc-1"
    record.capabilityToken = "secret-token"
    record.stdout = "diagnostic output"

    payload = json.loads(JsonFormatter().format(record))

    assert payload["incidentId"] == "inc-1"
    assert payload["capabilityToken"] == "[REDACTED]"
    assert payload["stdout"] == "[REDACTED]"


def test_emit_metric_writes_cloudwatch_emf(monkeypatch, capsys) -> None:
    monkeypatch.setenv("CLOUDWATCH_NAMESPACE", "DenDenMushiTest")
    monkeypatch.setenv("ENVIRONMENT", "test")

    with use_request_id("req-1"):
        emit_metric("IncidentReceived", 1, incidentId="inc-1")

    payload = json.loads(capsys.readouterr().out)
    assert payload["_aws"]["CloudWatchMetrics"][0]["Namespace"] == "DenDenMushiTest"
    assert payload["_aws"]["CloudWatchMetrics"][0]["Dimensions"] == [["Service", "Environment"]]
    assert payload["Service"] == "incident-agent"
    assert payload["Environment"] == "test"
    assert payload["IncidentReceived"] == 1
    assert payload["requestId"] == "req-1"
