from __future__ import annotations

import json

import pytest

from incident_agent.ingest.alerts import parse_sqs_body


def test_parse_sqs_body() -> None:
    body = json.dumps(
        {
            "MessageId": "msg-1",
            "Message": json.dumps(
                {
                    "AlarmName": "High 5xx",
                    "AlarmDescription": json.dumps(
                        {"source": "managed-server", "hostId": "host-1", "runbookVersion": "v1"}
                    ),
                    "AlarmArn": "arn:alarm",
                    "NewStateValue": "ALARM",
                    "NewStateReason": "threshold breached",
                    "StateChangeTime": "2026-07-02T10:00:00.000+0000",
                }
            ),
        }
    )
    alert = parse_sqs_body(body)
    assert alert.source_id == "arn:alarm|2026-07-02T10:00:00.000+0000|ALARM"
    assert alert.host_id == "host-1"
    assert alert.source_type == "managed-server"
    assert alert.group_key == "managed-server|host-1|High 5xx"


def test_parse_sqs_body_ignores_non_managed_alarm() -> None:
    body = json.dumps(
        {
            "MessageId": "msg-1",
            "Message": json.dumps(
                {
                    "AlarmName": "Platform Alarm",
                    "AlarmDescription": json.dumps({"event": "STSUnavailable"}),
                    "AlarmArn": "arn:alarm",
                    "NewStateValue": "ALARM",
                    "NewStateReason": "threshold breached",
                    "StateChangeTime": "2026-07-02T10:00:00.000+0000",
                }
            ),
        }
    )
    assert parse_sqs_body(body) is None


def test_parse_sqs_body_requires_host_metadata() -> None:
    body = json.dumps(
        {
            "MessageId": "msg-1",
            "Message": json.dumps(
                {
                    "AlarmName": "High 5xx",
                    "AlarmDescription": json.dumps({"source": "managed-server"}),
                    "AlarmArn": "arn:alarm",
                    "NewStateValue": "ALARM",
                    "StateChangeTime": "2026-07-02T10:00:00Z",
                }
            ),
        }
    )
    with pytest.raises(ValueError, match="hostId"):
        parse_sqs_body(body)
