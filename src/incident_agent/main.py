from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

import boto3
import uvicorn
from fastapi import FastAPI

from incident_agent.a2a_runtime import create_reasoning_app
from incident_agent.api.web import create_app
from incident_agent.automation.ddm import DDMClient
from incident_agent.config import Settings, load_settings
from incident_agent.identity import WorkloadIdentityClient
from incident_agent.ingest.sqs import SQSConsumer
from incident_agent.langsmith import configure_langsmith
from incident_agent.observability import configure_logging
from incident_agent.persistence.store import IncidentStore
from incident_agent.planning.a2a_client import A2APlanner
from incident_agent.planning.planner import BedrockPlanner, FallbackPlanner, OpenAIPlanner, RuleBasedPlanner
from incident_agent.planning.workflow import IncidentWorkflow
from incident_agent.service import IncidentService
from incident_agent.tool_gateway import GatewayBackend, GatewayPolicy, create_tool_gateway_app

ALLOWED_BEDROCK_MODEL_IDS = {"global.amazon.nova-2-lite-v1:0"}
ALLOWED_OPENAI_MODEL_IDS = {"gpt-5.5", "gpt-5.4-2026-03-05"}


def _database_url_from_secret(secret_id: str, region_name: str) -> str:
    if not secret_id:
        return ""
    client = boto3.client("secretsmanager", region_name=region_name)
    response = client.get_secret_value(SecretId=secret_id)
    return str(response.get("SecretString", "")).strip()


def build_service() -> IncidentService:
    settings = load_settings()
    database_url = settings.database_url or _database_url_from_secret(
        settings.database_secret_id,
        settings.aws_region,
    )
    if not database_url:
        raise RuntimeError("DATABASE_URL or DATABASE_SECRET_ID is required")
    store = IncidentStore(database_url)
    controlplane_url = settings.agent_controlplane_url or settings.proxy_controlplane_url
    ddm = DDMClient(
        controlplane_url,
        settings.workload_token_file,
        settings.http_timeout_seconds,
        settings.transient_retry_attempts,
        tool_gateway_url=settings.tool_gateway_url,
    )
    openai_mode = settings.planner_mode.strip().lower().startswith("openai")
    planner = A2APlanner(
        settings.reasoning_agent_url,
        settings.workload_token_file,
        RuleBasedPlanner(),
        settings.http_timeout_seconds,
        settings.transient_retry_attempts,
        settings.openai_model if openai_mode else settings.bedrock_model_id,
        (settings.openai_aws_region or settings.aws_region)
        if openai_mode
        else (settings.bedrock_region or settings.aws_region),
        provider="openai-agentcore" if openai_mode and settings.openai_auth_mode == "aws_iam" else None,
        gateway_route=f"{settings.openai_gateway_target}/{settings.openai_model}" if openai_mode else "",
    )
    workflow = IncidentWorkflow(planner, ddm, settings.operation_timeout_seconds, settings.max_operation_output_bytes)
    return IncidentService(
        store,
        workflow,
        ddm,
        settings.operation_timeout_seconds,
        settings.max_operation_output_bytes,
        claim_lease=timedelta(seconds=settings.incident_claim_lease_seconds),
        claim_renew_seconds=settings.incident_claim_renew_seconds,
    )


def _build_planner(settings: Settings) -> BedrockPlanner | FallbackPlanner | OpenAIPlanner | RuleBasedPlanner:
    mode = settings.planner_mode.strip().lower()
    if mode == "rule_based":
        return RuleBasedPlanner()
    if mode in {"openai", "openai_with_fallback"}:
        auth_mode = settings.openai_auth_mode.strip().lower()
        if auth_mode == "api_key" and not settings.openai_api_key.strip():
            raise RuntimeError("OPENAI_API_KEY is required when OPENAI_AUTH_MODE=api_key")
        if auth_mode == "aws_iam" and not settings.openai_gateway_url.strip():
            raise RuntimeError("OPENAI_GATEWAY_URL is required when OPENAI_AUTH_MODE=aws_iam")
        if settings.openai_model not in ALLOWED_OPENAI_MODEL_IDS:
            raise RuntimeError("OPENAI_MODEL is not in the reviewed model allowlist")
        openai_planner = OpenAIPlanner(
            settings.openai_api_key,
            settings.openai_model,
            settings.bedrock_max_prompt_bytes,
            settings.incident_agent_prompts_dir,
            settings.openai_timeout_seconds,
            settings.transient_retry_attempts,
            auth_mode=auth_mode,
            gateway_url=settings.openai_gateway_url,
            gateway_target=settings.openai_gateway_target,
            aws_region=settings.openai_aws_region or settings.aws_region,
            reasoning_effort=settings.openai_reasoning_effort,
            max_output_tokens=settings.openai_max_output_tokens,
        )
        if mode == "openai":
            return openai_planner
        return FallbackPlanner(openai_planner, RuleBasedPlanner())
    if settings.bedrock_model_id not in ALLOWED_BEDROCK_MODEL_IDS:
        raise RuntimeError("BEDROCK_MODEL_ID is not in the reviewed model allowlist")
    bedrock_planner = BedrockPlanner(
        settings.bedrock_model_id,
        settings.bedrock_max_prompt_bytes,
        settings.bedrock_region or settings.aws_region,
        settings.incident_agent_prompts_dir,
        settings.transient_retry_attempts,
    )
    if mode == "bedrock":
        return bedrock_planner
    if mode == "bedrock_with_fallback":
        return FallbackPlanner(bedrock_planner, RuleBasedPlanner())
    raise ValueError(
        "PLANNER_MODE must be one of: rule_based, openai, openai_with_fallback, bedrock, bedrock_with_fallback"
    )


def create_runtime_app() -> FastAPI:
    settings = load_settings()
    configure_logging(settings.log_format)
    service = build_service()
    app = create_app(service)
    service.set_consumer_configured(bool(settings.enable_sqs_consumer and settings.incident_queue_url))
    if settings.enable_sqs_consumer:
        consumer = SQSConsumer(
            settings.incident_queue_url,
            service,
            settings.aws_region,
            settings.sqs_poll_wait_seconds,
            settings.sqs_visibility_timeout_seconds,
            busy_retry_seconds=settings.incident_claim_renew_seconds,
        )

        @app.on_event("startup")
        async def start_consumer() -> None:
            asyncio.create_task(consumer.run())

        @app.on_event("shutdown")
        async def stop_consumer() -> None:
            consumer.stop()
            await consumer.wait_stopped()
            service.store.close()

    return app


def create_reasoning_runtime_app() -> FastAPI:
    settings = load_settings()
    configure_logging(settings.log_format)
    configure_langsmith(settings)
    planner = _build_planner(settings)
    return create_reasoning_app(
        planner,
        WorkloadIdentityClient(settings.sts_url, settings.http_timeout_seconds),
        settings.reasoning_agent_url,
    )


def create_tool_gateway_runtime_app() -> Any:
    settings = load_settings()
    configure_logging(settings.log_format)
    policy = GatewayPolicy.load(settings.tool_policy_file)
    return create_tool_gateway_app(
        policy,
        GatewayBackend(
            settings.agent_controlplane_url or settings.proxy_controlplane_url,
            settings.workload_token_file,
            settings.http_timeout_seconds,
            settings.max_operation_output_bytes,
        ),
        WorkloadIdentityClient(settings.sts_url, settings.http_timeout_seconds),
    )


def create_component_app() -> Any:
    component = load_settings().component.strip().lower()
    if component == "coordinator":
        return create_runtime_app()
    if component == "reasoning":
        return create_reasoning_runtime_app()
    if component == "tool_gateway":
        return create_tool_gateway_runtime_app()
    raise RuntimeError("INCIDENT_AGENT_COMPONENT must be coordinator, reasoning, or tool_gateway")


def main() -> None:
    settings = load_settings()
    uvicorn.run("incident_agent.main:create_component_app", host="0.0.0.0", port=settings.port, factory=True)  # nosec B104 # noqa: S104


if __name__ == "__main__":
    main()
