from __future__ import annotations

import json
from datetime import UTC, datetime

from incident_agent.models import Alert


def parse_sqs_body(body: str) -> Alert | None:
    envelope = json.loads(body)
    message_id = envelope.get("MessageId")
    message = envelope.get("Message")
    if not message_id or not message:
        raise ValueError("SNS envelope is incomplete")

    alarm = json.loads(message)
    state = alarm.get("NewStateValue")
    if state not in {"ALARM", "OK"}:
        return None

    alarm_arn = alarm.get("AlarmArn") or ""
    alarm_name = alarm.get("AlarmName") or ""
    if not alarm_arn or not alarm_name:
        raise ValueError("CloudWatch alarm ARN and name are required")

    metadata = _metadata(alarm.get("AlarmDescription") or "")
    if metadata.get("source") != "managed-server":
        return None
    host_id = metadata.get("hostId") or ""
    if not host_id:
        raise ValueError("alarm metadata hostId is required")

    changed_at = _parse_time(alarm.get("StateChangeTime") or "")
    source_type = "managed-server"
    return Alert(
        source_id=f"{alarm_arn}|{alarm.get('StateChangeTime', '')}|{state}",
        source_type=source_type,
        alarm_arn=alarm_arn,
        alarm_name=alarm_name,
        state=state,
        reason=alarm.get("NewStateReason") or "",
        host_id=host_id,
        runbook_version=metadata.get("runbookVersion") or "",
        group_key=f"{source_type}|{host_id}|{alarm_name}",
        occurred_at=changed_at,
    )


def _metadata(value: str) -> dict[str, str]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(key): str(item) for key, item in parsed.items()}


def _parse_time(value: str) -> datetime:
    if not value:
        raise ValueError("StateChangeTime is required")
    normalized = value
    if len(value) >= 5 and value[-5] in {"+", "-"} and value[-3] != ":":
        normalized = f"{value[:-2]}:{value[-2:]}"
    return datetime.fromisoformat(normalized.replace("Z", "+00:00")).astimezone(UTC)
