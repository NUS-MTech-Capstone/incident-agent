from __future__ import annotations

import json

import pytest

from incident_agent.alerts import parse_sqs_body


def test_parse_sqs_body() -> None:
    body = json.dumps(
        {
            "MessageId": "msg-1",
            "Message": json.dumps(
                {
                    "AlarmName": "High 5xx",
                    "AlarmDescription": json.dumps({"hostId": "host-1", "runbookVersion": "v1"}),
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


def test_parse_sqs_body_requires_host_metadata() -> None:
    body = json.dumps(
        {
            "MessageId": "msg-1",
            "Message": json.dumps(
                {
                    "AlarmName": "High 5xx",
                    "AlarmDescription": "{}",
                    "AlarmArn": "arn:alarm",
                    "NewStateValue": "ALARM",
                    "StateChangeTime": "2026-07-02T10:00:00Z",
                }
            ),
        }
    )
    with pytest.raises(ValueError, match="hostId"):
        parse_sqs_body(body)
