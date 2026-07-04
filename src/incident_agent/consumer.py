from __future__ import annotations

import asyncio
import logging

import boto3

from incident_agent.alerts import parse_sqs_body
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

    async def run(self) -> None:
        if not self.queue_url:
            logger.info("SQS consumer disabled because INCIDENT_QUEUE_URL is empty")
            return
        while not self._stopped.is_set():
            response = await asyncio.to_thread(
                self.client.receive_message,
                QueueUrl=self.queue_url,
                MaxNumberOfMessages=5,
                WaitTimeSeconds=self.wait_seconds,
                VisibilityTimeout=self.visibility_timeout,
            )
            for message in response.get("Messages", []):
                receipt = message["ReceiptHandle"]
                try:
                    alert = parse_sqs_body(message["Body"])
                    await self.service.handle_alert(alert)
                    await asyncio.to_thread(
                        self.client.delete_message,
                        QueueUrl=self.queue_url,
                        ReceiptHandle=receipt,
                    )
                except Exception:
                    logger.exception("incident alert processing failed")

    def stop(self) -> None:
        self._stopped.set()
