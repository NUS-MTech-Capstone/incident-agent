from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from incident_agent.redact import text

ROLES = ["manager", "triage", "collector", "planner", "reviewer", "executor"]
CATEGORIES = ["routing", "tool_use", "workflow", "safety", "escalation"]


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def safe(value: Any) -> Any:
    """Artifacts contain bounded structured projections, never transport envelopes."""
    if isinstance(value, dict):
        return {str(k): safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [safe(v) for v in value]
    if isinstance(value, str):
        value = text(value, 4096)
        value = re.sub(r"(?i)(token\s*[=:]\s*)[^\s]+", r"\1[REDACTED]", value)
        value = value.replace("R12_SECRET_SENTINEL", "[REDACTED]")
        if re.search(r"\b(sudo|bash|curl|wget|chmod|chown)\b|[`$|&><]", value):
            return "[UNSAFE_TEXT_OMITTED]"
        return value
    return value


class Record(BaseModel):
    schema_version: str = "r12.v1"
    case_id: str
    role: Literal["manager", "triage", "collector", "planner", "reviewer", "executor"]
    category: Literal["routing", "tool_use", "workflow", "safety", "escalation"]
    repetition: int = 1
    mode: Literal["deterministic", "gateway", "contract"]
    source: str
    expected: dict[str, Any]
    actual: dict[str, Any]
    assertions: dict[str, bool] = Field(default_factory=dict)
    verdict: Literal["pass", "fail", "error", "blocked"]
    failure_reason: str = ""
    duration_ms: float = 0
    provider_attempts: int = 0
    fallback_used: bool = False
    fallback_stage: str = ""
    fallback_reason: str = ""


def record(
    case_id: str, role: str, category: str, expected: dict, actual: dict, assertions: dict[str, bool], **kwargs: Any
) -> Record:
    return Record(
        case_id=case_id,
        role=role,
        category=category,
        expected=safe(expected),
        actual=safe(actual),
        assertions=assertions,
        verdict="pass" if all(assertions.values()) and assertions else "fail",
        failure_reason=", ".join(k for k, v in assertions.items() if not v),
        mode=kwargs.pop("mode", "deterministic"),
        source=kwargs.pop("source", "implementation_with_fixtures"),
        **kwargs,
    )


def save_records(directory: Path, manifest: dict, records: list[Record]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (directory / "results.json").write_text(json.dumps([r.model_dump() for r in records], indent=2) + "\n")
    counts = Counter(r.verdict for r in records)
    lines = [
        "# R12 evaluation results",
        "",
        f"Run: {manifest['run_id']}",
        "",
        f"Records: {len(records)}; outcomes: {dict(counts)}",
        "",
        "| Role | Pass | Fail | Error | Blocked | Fallback |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for role in ROLES:
        selected = [r for r in records if r.role == role]
        counts = Counter(r.verdict for r in selected)
        lines.append(
            f"| {role} | {counts['pass']} | {counts['fail']} | {counts['error']} | "
            f"{counts['blocked']} | {sum(r.fallback_used for r in selected)} |"
        )
    lines.extend(["", "| Case | Role | Repeat | Source | Verdict | Detail |", "|---|---|---:|---|---|---|"])
    for r in records:
        lines.append(
            f"| {r.case_id} | {r.role} | {r.repetition} | {r.source} | {r.verdict} | "
            f"{r.failure_reason or 'Assertions satisfied'} |"
        )
    (directory / "summary.md").write_text("\n".join(lines) + "\n")
