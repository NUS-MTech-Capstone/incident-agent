from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import os
import sys
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

REQUEST_ID_HEADER = "X-Request-ID"
SERVICE_NAME = "incident-agent"

_request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
_RESERVED_LOG_ATTRS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "taskName",
    "thread",
    "threadName",
}
_SENSITIVE_FIELD_PARTS = ("token", "secret", "password", "credential", "authorization", "prompt", "stdout", "stderr")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": SERVICE_NAME,
        }
        current_request_id = request_id()
        if current_request_id:
            payload["requestId"] = current_request_id
        for key, value in record.__dict__.items():
            if key not in _RESERVED_LOG_ATTRS and not key.startswith("_"):
                payload[key] = sanitize_log_value(key, value)
        if record.exc_info and record.exc_info[0] is not None:
            payload["errorKind"] = record.exc_info[0].__name__
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)


class SuccessfulProbeAccessLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        method, path, status = _uvicorn_access_fields(record)
        if method is None or path is None or status is None:
            return True
        return not is_successful_probe_request(method, path, status)


def configure_logging(log_format: str) -> None:
    handler = logging.StreamHandler()
    if log_format.lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").addFilter(SuccessfulProbeAccessLogFilter())


def is_successful_probe_request(method: str, path: str, status: int) -> bool:
    return status < 400 and method == "GET" and path in {"/healthz", "/readyz"}


def _uvicorn_access_fields(record: logging.LogRecord) -> tuple[str | None, str | None, int | None]:
    args = record.args
    if not isinstance(args, tuple) or len(args) < 5:
        return None, None, None
    method = str(args[1])
    path = str(args[2]).split("?", 1)[0]
    raw_status = args[4]
    if not isinstance(raw_status, (str, bytes, bytearray, int)):
        return None, None, None
    try:
        status = int(raw_status)
    except (TypeError, ValueError):
        return None, None, None
    return method, path, status


def sanitize_log_value(key: str, value: object) -> object:
    lowered = key.lower()
    if any(part in lowered for part in _SENSITIVE_FIELD_PARTS):
        return "[REDACTED]"
    if isinstance(value, str):
        return value if len(value) <= 512 else value[:512] + "...[truncated]"
    if isinstance(value, int | float | bool) or value is None:
        return value
    return str(value)


def request_id() -> str:
    return _request_id.get()


def new_request_id() -> str:
    return uuid.uuid4().hex


@contextlib.contextmanager
def use_request_id(value: str) -> Iterator[None]:
    token = _request_id.set(value)
    try:
        yield
    finally:
        _request_id.reset(token)


def log_event(logger: logging.Logger, event: str, **fields: object) -> None:
    logger.info(event, extra={key: sanitize_log_value(key, value) for key, value in fields.items()})


def log_exception(logger: logging.Logger, event: str, **fields: object) -> None:
    logger.exception(event, extra={key: sanitize_log_value(key, value) for key, value in fields.items()})


def emit_metric(name: str, value: float = 1, unit: str = "Count", **fields: object) -> None:
    namespace = os.getenv("CLOUDWATCH_NAMESPACE", "DenDenMushi")
    environment = os.getenv("ENVIRONMENT") or os.getenv("DDM_ENV") or "unknown"
    metric: dict[str, Any] = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": namespace,
                    "Dimensions": [["Service", "Environment"]],
                    "Metrics": [{"Name": name, "Unit": unit}],
                }
            ],
        },
        "Service": SERVICE_NAME,
        "Environment": environment,
        name: value,
    }
    current_request_id = request_id()
    if current_request_id:
        metric["requestId"] = current_request_id
    for key, field_value in fields.items():
        metric[key] = sanitize_log_value(key, field_value)
    print(json.dumps(metric, separators=(",", ":"), sort_keys=True), file=sys.stdout, flush=True)
