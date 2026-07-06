from __future__ import annotations

import asyncio
import logging

import boto3

from incident_agent.ingest.alerts import parse_sqs_body
from incident_agent.observability import emit_metric, log_exception, new_request_id, use_request_id
from incident_agent.service import IncidentService

logger = logging.getLogger(__name__)


class SQSConsumer:
    def __init__(
        self,
        queue_url: str,
        service: IncidentService,
        region_name: str,
        wait_seconds: int,
        visibility_timeout: int,
    ):
        self.queue_url = queue_url
        self.service = service
        self.client = boto3.client("sqs", region_name=region_name)
        self.wait_seconds = wait_seconds
        self.visibility_timeout = visibility_timeout
        self._stopped = asyncio.Event()
        self._finished = asyncio.Event()

    async def run(self) -> None:
        try:
            if not self.queue_url:
                logger.info("SQS consumer disabled because INCIDENT_QUEUE_URL is empty")
                return
            self.service.set_consumer_running(True)
            while not self._stopped.is_set():
                response = await asyncio.to_thread(
                    self.client.receive_message,
                    QueueUrl=self.queue_url,
                    MaxNumberOfMessages=5,
                    WaitTimeSeconds=self.wait_seconds,
                    VisibilityTimeout=self.visibility_timeout,
                )
                for message in response.get("Messages", []):
                    if self._stopped.is_set():
                        break
                    receipt = message["ReceiptHandle"]
                    request_id = str(message.get("MessageId") or new_request_id())
                    with use_request_id(request_id):
                        try:
                            alert = parse_sqs_body(message["Body"])
                            if alert is not None:
                                await self.service.handle_alert(alert)
                            else:
                                logger.info("ignored non-managed alert notification")
                            await asyncio.to_thread(
                                self.client.delete_message,
                                QueueUrl=self.queue_url,
                                ReceiptHandle=receipt,
                            )
                        except Exception as exc:  # noqa: BLE001 - SQS redelivery/DLQ handles retry budget
                            emit_metric("SQSMessageFailures", 1, errorKind=type(exc).__name__)
                            self.service.record_processing_error(
                                f"incident alert processing failed: {type(exc).__name__}"
                            )
                            log_exception(logger, "incident alert processing failed", errorKind=type(exc).__name__)
        finally:
            self.service.set_consumer_running(False)
            self._finished.set()

    def stop(self) -> None:
        self._stopped.set()

    async def wait_stopped(self) -> None:
        await self._finished.wait()
