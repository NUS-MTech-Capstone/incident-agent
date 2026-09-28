from __future__ import annotations

import asyncio
import json
import threading
from typing import Any

import pytest

from incident_agent.ingest.sqs import SQSConsumer
from incident_agent.persistence.store import ClaimDisposition


class FakeSQS:
    def __init__(self, messages: list[dict[str, str]]):
        self.messages = messages
        self.deleted: list[str] = []
        self.visibility_changes: list[tuple[str, int]] = []
        self.receive_requests: list[dict[str, Any]] = []
        self.received = threading.Event()

    def receive_message(self, **kwargs: Any) -> dict[str, list[dict[str, str]]]:
        self.receive_requests.append(kwargs)
        self.received.set()
        if self.messages:
            return {"Messages": [self.messages.pop(0)]}
        return {"Messages": []}

    def delete_message(self, **kwargs: Any) -> None:
        self.deleted.append(str(kwargs["ReceiptHandle"]))

    def change_message_visibility(self, **kwargs: Any) -> None:
        self.visibility_changes.append((str(kwargs["ReceiptHandle"]), int(kwargs["VisibilityTimeout"])))


class RecordingService:
    def __init__(self, disposition: ClaimDisposition = ClaimDisposition.PROCESS, delay: float = 0) -> None:
        self.alerts = []
        self.consumer_running = False
        self.errors: list[str] = []
        self.disposition = disposition
        self.delay = delay

    async def handle_alert(self, item: object) -> ClaimDisposition:
        self.alerts.append(item)
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.disposition

    def set_consumer_running(self, running: bool) -> None:
        self.consumer_running = running

    def record_processing_error(self, summary: str) -> None:
        self.errors.append(summary)


@pytest.mark.asyncio
async def test_sqs_parse_failure_emits_metric_and_keeps_message(monkeypatch, capsys) -> None:
    fake_sqs = FakeSQS([{"ReceiptHandle": "receipt-1", "MessageId": "msg-1", "Body": "{}"}])
    monkeypatch.setattr("incident_agent.ingest.sqs.boto3.client", lambda *args, **kwargs: fake_sqs)
    service = RecordingService()
    consumer = SQSConsumer("queue-url", service, "ap-southeast-1", 0, 30)  # type: ignore[arg-type]

    task = asyncio.create_task(consumer.run())
    await asyncio.to_thread(fake_sqs.received.wait, 1)
    await asyncio.sleep(0.05)
    consumer.stop()
    await consumer.wait_stopped()
    await task

    output = capsys.readouterr().out
    assert "SQSMessageFailures" in output
    assert fake_sqs.deleted == []
    assert service.alerts == []


@pytest.mark.asyncio
async def test_sqs_success_deletes_message_and_shutdown_waits(monkeypatch) -> None:
    fake_sqs = FakeSQS(
        [
            {
                "ReceiptHandle": "receipt-1",
                "MessageId": "msg-1",
                "Body": _sns_body("ALARM"),
            }
        ]
    )
    monkeypatch.setattr("incident_agent.ingest.sqs.boto3.client", lambda *args, **kwargs: fake_sqs)
    service = RecordingService()
    consumer = SQSConsumer("queue-url", service, "ap-southeast-1", 0, 30)  # type: ignore[arg-type]

    task = asyncio.create_task(consumer.run())
    await asyncio.to_thread(fake_sqs.received.wait, 1)
    await asyncio.sleep(0.05)
    consumer.stop()
    await consumer.wait_stopped()
    await task

    assert fake_sqs.deleted == ["receipt-1"]
    assert len(service.alerts) == 1
    assert all(request["MaxNumberOfMessages"] == 1 for request in fake_sqs.receive_requests)


@pytest.mark.asyncio
async def test_sqs_busy_claim_keeps_message(monkeypatch) -> None:
    fake_sqs = FakeSQS([{"ReceiptHandle": "receipt-1", "MessageId": "msg-1", "Body": _sns_body("ALARM")}])
    monkeypatch.setattr("incident_agent.ingest.sqs.boto3.client", lambda *args, **kwargs: fake_sqs)
    service = RecordingService(ClaimDisposition.RETRY_BUSY)
    consumer = SQSConsumer(
        "queue-url",
        service,
        "ap-southeast-1",
        0,
        30,
        busy_retry_seconds=7,
    )  # type: ignore[arg-type]

    task = asyncio.create_task(consumer.run())
    await asyncio.to_thread(fake_sqs.received.wait, 1)
    await asyncio.sleep(0.05)
    consumer.stop()
    await consumer.wait_stopped()
    await task

    assert fake_sqs.deleted == []
    assert fake_sqs.visibility_changes == [("receipt-1", 7)]


@pytest.mark.asyncio
async def test_sqs_extends_visibility_during_processing(monkeypatch) -> None:
    fake_sqs = FakeSQS([{"ReceiptHandle": "receipt-1", "MessageId": "msg-1", "Body": _sns_body("ALARM")}])
    monkeypatch.setattr("incident_agent.ingest.sqs.boto3.client", lambda *args, **kwargs: fake_sqs)
    service = RecordingService(delay=0.05)
    consumer = SQSConsumer(
        "queue-url",
        service,
        "ap-southeast-1",
        0,
        30,
        visibility_heartbeat_seconds=0.01,
    )  # type: ignore[arg-type]

    task = asyncio.create_task(consumer.run())
    await asyncio.to_thread(fake_sqs.received.wait, 1)
    await asyncio.sleep(0.1)
    consumer.stop()
    await consumer.wait_stopped()
    await task

    assert fake_sqs.visibility_changes
    assert fake_sqs.deleted == ["receipt-1"]


def _sns_body(state: str) -> str:
    return json.dumps(
        {
            "MessageId": "sns-msg-1",
            "Message": json.dumps(
                {
                    "AlarmArn": "arn:alarm",
                    "AlarmName": "High 5xx",
                    "AlarmDescription": json.dumps(
                        {"source": "managed-server", "hostId": "host-1", "runbookVersion": "v1"}
                    ),
                    "NewStateValue": state,
                    "NewStateReason": "service unhealthy",
                    "StateChangeTime": "2026-07-04T00:00:00Z",
                }
            ),
        }
    )
