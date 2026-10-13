"""Optional metadata-only tracing; runtime work never waits for the exporter."""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import os
import queue
import re
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from langsmith import Client
from urllib3.util.retry import Retry


class RunClient(Protocol):
    def create_run(
        self, name: str, inputs: dict[str, Any], run_type: Literal["chain", "llm"], **kwargs: Any
    ) -> None: ...


def metadata_projection(values: dict[str, Any]) -> dict[str, Any]:
    """Positive schema, including values. Never export arbitrary strings/exceptions."""
    result: dict[str, Any] = {}
    for key, value in values.items():
        if key in {"attempt", "input_tokens", "output_tokens", "cached_input_tokens", "reasoning_tokens"}:
            if type(value) is int and value >= 0:
                result[key] = value
        elif key == "duration_ms" and type(value) in {int, float} and 0 <= value < 86400000:
            result[key] = round(value, 2)
        elif key == "fallback" and type(value) is bool:
            result[key] = value
        elif key == "stage" and value in {"triage", "plan"}:
            result[key] = value
        elif key == "outcome" and value in {"succeeded", "failed", "fallback"}:
            result[key] = value
        elif key in {"model", "returned_model"} and isinstance(value, str):
            if re.fullmatch(r"(?:openai/)?gpt-[0-9.]+(?:-\d{4}-\d{2}-\d{2})?", value):
                result[key] = value
        elif key == "incident_id" and isinstance(value, str):
            # Only known opaque IDs are exported directly. Other IDs are irreversible digests.
            result[key] = (
                value
                if re.fullmatch(r"(?:R12-S\d{2}|inc-[a-f0-9]{32}|[a-f0-9-]{36})", value)
                else hashlib.sha256(value.encode()).hexdigest()
            )
        elif key == "prompt_hashes" and isinstance(value, dict):
            result[key] = {
                name: digest
                for name, digest in value.items()
                if name in {"triage_system.md.j2", "triage_user.md.j2", "plan_system.md.j2", "plan_user.md.j2"}
                and isinstance(digest, str)
                and re.fullmatch(r"(?:sha256:)?[a-f0-9]{64}", digest)
            }
    return result


@dataclass
class Span:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: dict[str, Any] = field(default_factory=dict)
    trace_id: str = ""
    dotted_order: str = ""

    def update(self, **values: Any) -> None:
        self.metadata.update(metadata_projection(values))


class TraceSink:
    """One daemon worker, bounded queue and deadline-bounded shutdown, no retries."""

    def __init__(self, client: RunClient, project: str, *, capacity: int = 128):
        self.client = client
        self.project = project
        self.pending: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=capacity)
        self.parent: contextvars.ContextVar[Span | None] = contextvars.ContextVar("model_trace_parent", default=None)
        self.stopping = threading.Event()
        self.failed = 0
        self.dropped = 0
        self.submitted = 0
        self.worker = threading.Thread(target=self._export, name="model-trace-export", daemon=True)
        self.worker.start()

    def _export(self) -> None:
        while not self.stopping.is_set() or not self.pending.empty():
            try:
                payload = self.pending.get(timeout=0.05)
            except queue.Empty:
                continue
            try:
                self.client.create_run(**payload)
                self.submitted += 1
            except Exception:  # noqa: BLE001 - telemetry cannot affect model execution; no raw SDK error logging
                self.failed += 1
            finally:
                self.pending.task_done()

    def enqueue(self, payload: dict[str, Any]) -> None:
        if self.stopping.is_set():
            self.dropped += 1
            return
        try:
            self.pending.put_nowait(payload)
        except queue.Full:
            self.dropped += 1

    def close(self, timeout: float = 5.0) -> None:
        self.stopping.set()
        self.worker.join(timeout=max(0, timeout))


def create_trace_sink() -> TraceSink | None:
    if os.environ.get("LANGSMITH_TRACING", "").lower() != "true" or not os.environ.get("LANGSMITH_API_KEY", "").strip():
        return None
    try:
        client = Client(
            auto_batch_tracing=False,
            timeout_ms=(1000, 2000),
            retry_config=Retry(total=0),
            hide_inputs=True,
            hide_outputs=True,
            omit_traced_runtime_info=True,
        )
        return TraceSink(client, os.environ.get("LANGSMITH_PROJECT", "default"))
    except Exception:  # noqa: BLE001 - configuration of optional telemetry must not block processing
        return None


@contextlib.contextmanager
def span(sink: TraceSink | None, name: str, **metadata: Any) -> Iterator[Span]:
    current = Span(metadata=metadata_projection(metadata))
    if sink is None:
        yield current
        return
    if name not in {"reasoning", "provider_attempt", "result_validation", "deterministic_fallback"}:
        raise ValueError("Unknown trace span")
    parent = sink.parent.get()
    started = datetime.now(UTC)
    clock = time.monotonic()
    current.trace_id = parent.trace_id if parent else current.id
    order = started.strftime("%Y%m%dT%H%M%S%fZ") + current.id
    current.dotted_order = f"{parent.dotted_order}.{order}" if parent else order
    if parent:
        current.metadata = {**parent.metadata, **current.metadata}
    token = sink.parent.set(current)
    error = None
    try:
        yield current
        current.metadata.setdefault("outcome", "succeeded")
    except BaseException:
        # Never let an exception string/traceback (which can contain inputs) enter the SDK.
        error = "operation_failed"
        current.update(outcome="failed")
        raise
    finally:
        sink.parent.reset(token)
        current.update(duration_ms=(time.monotonic() - clock) * 1000)
        sink.enqueue(
            {
                "name": name,
                "inputs": {},
                "outputs": {},
                "run_type": "llm" if name == "provider_attempt" else "chain",
                "project_name": sink.project,
                "id": current.id,
                "trace_id": current.trace_id,
                "parent_run_id": parent.id if parent else None,
                "dotted_order": current.dotted_order,
                "start_time": started,
                "end_time": datetime.now(UTC),
                "extra": {"metadata": current.metadata},
                "error": error,
            }
        )
