from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    port: int = Field(default=8091, alias="PORT")
    aws_region: str = Field(default="ap-southeast-1", alias="AWS_REGION")
    incident_queue_url: str = Field(default="", alias="INCIDENT_QUEUE_URL")
    database_url: str = Field(default="", alias="DATABASE_URL")
    database_secret_id: str = Field(default="", alias="DATABASE_SECRET_ID")
    proxy_controlplane_url: str = Field(default="http://localhost:8080", alias="PROXY_CONTROLPLANE_URL")
    workload_token_file: str = Field(
        default="/var/run/secrets/tokens/incident-agent-token",
        alias="WORKLOAD_TOKEN_FILE",
    )
    bedrock_model_id: str = Field(default="global.amazon.nova-2-lite-v1:0", alias="BEDROCK_MODEL_ID")
    bedrock_max_prompt_bytes: int = Field(default=131072, alias="BEDROCK_MAX_PROMPT_BYTES")
    http_timeout_seconds: float = Field(default=10.0, alias="HTTP_TIMEOUT_SECONDS")
    operation_timeout_seconds: float = Field(default=45.0, alias="OPERATION_TIMEOUT_SECONDS")
    max_operation_output_bytes: int = Field(default=262144, alias="MAX_OPERATION_OUTPUT_BYTES")
    sqs_poll_wait_seconds: int = Field(default=20, alias="SQS_POLL_WAIT_SECONDS")
    sqs_visibility_timeout_seconds: int = Field(default=600, alias="SQS_VISIBILITY_TIMEOUT_SECONDS")
    enable_sqs_consumer: bool = Field(default=True, alias="ENABLE_SQS_CONSUMER")
    langsmith_tracing: bool = Field(default=False, alias="LANGSMITH_TRACING")

    model_config = SettingsConfigDict(extra="ignore", populate_by_name=True)


@lru_cache(maxsize=1)
def load_settings() -> Settings:
    return Settings()
