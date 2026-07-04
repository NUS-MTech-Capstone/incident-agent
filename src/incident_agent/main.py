from __future__ import annotations

import asyncio
import logging

import boto3
import uvicorn
from fastapi import FastAPI

from incident_agent.config import load_settings
from incident_agent.consumer import SQSConsumer
from incident_agent.ddm import DDMClient
from incident_agent.planner import BedrockPlanner
from incident_agent.service import IncidentService
from incident_agent.store import IncidentStore
from incident_agent.web import create_app
from incident_agent.workflow import IncidentWorkflow

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def build_service() -> IncidentService:
    settings = load_settings()
    database_url = settings.database_url or _database_url_from_secret(
        settings.database_secret_id,
        settings.aws_region,
    )
    if not database_url:
        raise RuntimeError("DATABASE_URL or DATABASE_SECRET_ID is required")
    store = IncidentStore(database_url)
    ddm = DDMClient(settings.proxy_controlplane_url, settings.workload_token_file, settings.http_timeout_seconds)
    planner = BedrockPlanner(settings.bedrock_model_id, settings.bedrock_max_prompt_bytes, settings.aws_region)
    workflow = IncidentWorkflow(planner, ddm, settings.operation_timeout_seconds, settings.max_operation_output_bytes)
    return IncidentService(
        store,
        workflow,
        ddm,
        settings.operation_timeout_seconds,
        settings.max_operation_output_bytes,
    )


def create_runtime_app() -> FastAPI:
    settings = load_settings()
    service = build_service()
    app = create_app(service)
    if settings.enable_sqs_consumer:
        consumer = SQSConsumer(
            settings.incident_queue_url,
            service,
            settings.aws_region,
            settings.sqs_poll_wait_seconds,
            settings.sqs_visibility_timeout_seconds,
        )

        @app.on_event("startup")
        async def start_consumer() -> None:
            asyncio.create_task(consumer.run())

        @app.on_event("shutdown")
        async def stop_consumer() -> None:
            consumer.stop()
            service.store.close()

    return app


app = create_runtime_app()


def main() -> None:
    settings = load_settings()
    uvicorn.run("incident_agent.main:app", host="0.0.0.0", port=settings.port)  # nosec B104 # noqa: S104


def _database_url_from_secret(secret_id: str, region_name: str) -> str:
    if not secret_id:
        return ""
    client = boto3.client("secretsmanager", region_name=region_name)
    response = client.get_secret_value(SecretId=secret_id)
    return str(response.get("SecretString", "")).strip()


if __name__ == "__main__":
    main()
