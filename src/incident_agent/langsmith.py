from __future__ import annotations

import logging
import os
from collections.abc import Callable

import boto3

from incident_agent.config import Settings

logger = logging.getLogger(__name__)


SecretFetcher = Callable[[str, str], str]


def configure_langsmith(settings: Settings, fetch_secret: SecretFetcher | None = None) -> None:
    if not settings.langsmith_tracing:
        os.environ["LANGSMITH_TRACING"] = "false"
        return

    api_key = os.getenv("LANGSMITH_API_KEY", "").strip()
    if not api_key and settings.langsmith_api_key_secret_id:
        reader = fetch_secret or _secret_string_from_secret
        try:
            api_key = reader(settings.langsmith_api_key_secret_id, settings.aws_region).strip()
        except Exception as exc:  # noqa: BLE001 - provider SDK exceptions vary
            os.environ["LANGSMITH_TRACING"] = "false"
            logger.warning(
                "LangSmith API key could not be loaded; tracing disabled",
                extra={"errorKind": type(exc).__name__},
            )
            return

    if not api_key:
        os.environ["LANGSMITH_TRACING"] = "false"
        logger.warning("LangSmith tracing requested but no API key was configured; tracing disabled")
        return

    os.environ["LANGSMITH_TRACING"] = "true"
    os.environ["LANGSMITH_API_KEY"] = api_key
    _set_optional("LANGSMITH_PROJECT", settings.langsmith_project)
    _set_optional("LANGSMITH_ENDPOINT", settings.langsmith_endpoint)
    _set_optional("LANGSMITH_WORKSPACE_ID", settings.langsmith_workspace_id)


def _set_optional(name: str, value: str) -> None:
    if value:
        os.environ[name] = value


def _secret_string_from_secret(secret_id: str, region_name: str) -> str:
    client = boto3.client("secretsmanager", region_name=region_name)
    response = client.get_secret_value(SecretId=secret_id)
    return str(response.get("SecretString", ""))
