from __future__ import annotations

import asyncio
import logging

import boto3

from incident_agent.ingest.alerts import parse_sqs_body
from incident_agent.observability import emit_metric, log_exception, new_request_id, use_request_id
from incident_agent.persistence.store import ClaimDisposition
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
        busy_retry_seconds: int | None = None,
        visibility_heartbeat_seconds: float | None = None,
    ):
        self.queue_url = queue_url
        self.service = service
        self.client = boto3.client("sqs", region_name=region_name)
        self.wait_seconds = wait_seconds
        self.visibility_timeout = visibility_timeout
        self.busy_retry_seconds = max(1, min(visibility_timeout, busy_retry_seconds or 30))
        self.visibility_heartbeat_seconds = visibility_heartbeat_seconds or max(1.0, visibility_timeout / 3)
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
                    MaxNumberOfMessages=1,
                    WaitTimeSeconds=self.wait_seconds,
                    VisibilityTimeout=self.visibility_timeout,
                )
                for message in response.get("Messages", []):
                    if self._stopped.is_set():
                        break
                    receipt = message["ReceiptHandle"]
                    request_id = str(message.get("MessageId") or new_request_id())
                    with use_request_id(request_id):
                        visibility_heartbeat = asyncio.create_task(self._extend_visibility(receipt))
                        try:
                            alert = parse_sqs_body(message["Body"])
                            disposition: ClaimDisposition | None = None
                            if alert is not None:
                                disposition = await self.service.handle_alert(alert)
                            else:
                                logger.info("ignored non-managed alert notification")
                            if disposition == ClaimDisposition.RETRY_BUSY:
                                await asyncio.to_thread(
                                    self.client.change_message_visibility,
                                    QueueUrl=self.queue_url,
                                    ReceiptHandle=receipt,
                                    VisibilityTimeout=self.busy_retry_seconds,
                                )
                            else:
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
                            visibility_heartbeat.cancel()
                            await asyncio.gather(visibility_heartbeat, return_exceptions=True)
        finally:
            self.service.set_consumer_running(False)
            self._finished.set()

    def stop(self) -> None:
        self._stopped.set()

    async def wait_stopped(self) -> None:
        await self._finished.wait()

    async def _extend_visibility(self, receipt: str) -> None:
        while True:
            await asyncio.sleep(self.visibility_heartbeat_seconds)
            try:
                await asyncio.to_thread(
                    self.client.change_message_visibility,
                    QueueUrl=self.queue_url,
                    ReceiptHandle=receipt,
                    VisibilityTimeout=self.visibility_timeout,
                )
            except Exception as exc:  # noqa: BLE001 - database fencing still prevents duplicate processing
                emit_metric("SQSVisibilityExtensionFailures", 1, errorKind=type(exc).__name__)
                log_exception(logger, "SQS visibility extension failed", errorKind=type(exc).__name__)
                return
