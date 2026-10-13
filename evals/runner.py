"""Run from the repository root: python -m evals.runner --mode deterministic."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
from boto3.session import Session

from evals.records import Record, digest, record, safe, save_records, utc_now
from evals.support import FixtureTools, incident
from incident_agent.models import OperationResult
from incident_agent.planning.agents import ActionPlanAgent, ActionPlanReviewerAgent, EvidenceCollectorAgent, TriageAgent
from incident_agent.planning.catalog import CATALOG_VERSION, DIAGNOSTIC_OPERATIONS, REMEDIATION_OPERATIONS
from incident_agent.planning.planner import FallbackPlanner, OpenAIPlanner, RuleBasedPlanner
from incident_agent.redact import text

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "evals/fixtures/six_role_v1.json"


class GatewayTransport(httpx.AsyncBaseTransport):
    """Evaluation-only request counter/rate limiter. Never captures headers or bodies."""

    def __init__(self, limit: int = 144, interval: float = 10.1):
        self.inner = httpx.AsyncHTTPTransport()
        self.limit = limit
        self.interval = interval
        self.attempts = 0
        self.last_request = 0.0
        self.fatal = ""
        self.statuses: list[int] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self.fatal or self.attempts >= self.limit:
            self.fatal = self.fatal or "request_budget_exhausted"
            raise RuntimeError(self.fatal)
        await asyncio.sleep(max(0, self.interval - (time.monotonic() - self.last_request)))
        self.last_request = time.monotonic()
        self.attempts += 1
        response = await self.inner.handle_async_request(request)
        self.statuses.append(response.status_code)
        if response.status_code in {400, 401, 403, 404, 405, 422}:
            self.fatal = f"gateway_configuration_or_authorization_HTTP{response.status_code}"
        return response

    async def aclose(self) -> None:
        # OpenAIPlanner creates a client per attempt. The runner owns this transport.
        return None

    async def finish(self) -> None:
        await self.inner.aclose()


class TrackingFallback(RuleBasedPlanner):
    def __init__(self):
        self.calls: list[str] = []

    async def triage(self, incident):
        self.calls.append("triage")
        return await super().triage(incident)

    async def plan(self, incident, evidence):
        self.calls.append("plan")
        return await super().plan(incident, evidence)


def revision(repo: Path) -> dict:
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()  # noqa: S603,S607

    hashes = {}
    for folder in ["src", "internal", "tests", "evals", "prompts"]:
        for path in sorted((repo / folder).rglob("*")):
            if path.is_file() and path.suffix in {".py", ".go", ".json", ".j2"}:
                hashes[str(path.relative_to(repo))] = digest(path.read_bytes())
    for name in ["pyproject.toml", "uv.lock", "go.mod", "go.sum"]:
        if (repo / name).exists():
            hashes[name] = digest((repo / name).read_bytes())
    return {"head": git("rev-parse", "HEAD"), "dirty": bool(git("status", "--porcelain")), "source_hashes": hashes}


def gateway_url() -> str:
    if os.getenv("OPENAI_GATEWAY_URL"):
        return os.environ["OPENAI_GATEWAY_URL"]
    properties = ROOT.parent / "kubernetes/apps/dendenmushi/overlays/dev/env.properties"
    for line in properties.read_text().splitlines():
        if line.startswith("AGENTCORE_OPENAI_GATEWAY_URL="):
            return line.split("=", 1)[1].strip()
    raise ValueError("OPENAI_GATEWAY_URL is required")


def make_manifest(args, directory: Path) -> dict:
    return {
        "schema_version": "r12.v1",
        "run_id": directory.name,
        "started_at": utc_now(),
        "mode": args.mode,
        "corpus_version": "r12.corpus.v1",
        "corpus_hash": digest(CORPUS.read_bytes()),
        "repetitions": args.repetitions,
        "selected_cases": args.cases or "all",
        "repositories": {
            name: revision(ROOT.parent / name) for name in ["incident-agent", "agent-controlplane", "proxy-dataplane"]
        },
        "catalog_version": CATALOG_VERSION,
        "catalog_hash": digest((ROOT / "src/incident_agent/planning/catalog.py").read_bytes()),
        "prompt_hashes": {p.name: digest(p.read_bytes()) for p in sorted((ROOT / "prompts").glob("*.j2"))},
        "provider": "openai_via_bedrock_agentcore" if args.mode == "gateway" else "none",
        "model": "gpt-5.4-2026-03-05" if args.mode == "gateway" else "rule_based",
        "route": "openai/gpt-5.4-2026-03-05" if args.mode == "gateway" else "",
        "settings": {
            "region": "ap-southeast-1",
            "auth": "aws_iam",
            "reasoning_effort": "low",
            "max_output_tokens": 4096,
            "max_prompt_bytes": 131072,
            "timeout_seconds": 60,
            "attempts_per_stage": 2,
            "request_interval_seconds": 10.1,
            "http_attempt_limit": 144,
            "concurrency": 1,
            "store": False,
            "langsmith": False,
        },
        "limitations": [
            "Synthetic isolated incidents and tools; no live remediation or deployment verification.",
            "Engineering expectations, not human-labelled ground truth or judge scores.",
            "Category schema checked; semantic category accuracy is not scored.",
        ],
    }


async def evaluate_scenarios(args, directory: Path, manifest: dict) -> list[Record]:
    corpus = json.loads(CORPUS.read_text())["cases"]
    if args.cases:
        selected = set(args.cases.split(","))
        if selected - {c["id"] for c in corpus}:
            raise ValueError("Unknown case IDs")
        corpus = [c for c in corpus if c["id"] in selected]
    transport = GatewayTransport()
    fallback = TrackingFallback()
    planner = RuleBasedPlanner()
    if args.mode == "gateway":
        primary = OpenAIPlanner(
            "",
            "gpt-5.4-2026-03-05",
            131072,
            timeout_seconds=60,
            transient_retry_attempts=2,
            auth_mode="aws_iam",
            gateway_url=gateway_url(),
            aws_region="ap-southeast-1",
            aws_session=Session(profile_name=args.aws_profile),
            transport=transport,
        )
        planner = FallbackPlanner(primary, fallback)
    records = []
    try:
        for repeat in range(1, args.repetitions + 1):
            for case in corpus:
                print(f"R12 {args.mode} repetition {repeat}: {case['id']}", file=sys.__stdout__, flush=True)
                subject = incident(case["id"])
                subject.alarm_name = case["name"]
                subject.reason = text(case["reason"], 4096)
                fixture_results = {
                    "service_status": OperationResult(operationId="service_status", stdout="active", exitCode=0),
                    "health_check": OperationResult(operationId="health_check", stdout="healthy HTTP 200", exitCode=0),
                }
                for op, value in case["evidence"].items():
                    value = dict(value)
                    if case.get("long_evidence") and op == "service_logs":
                        value["stdout"] += "Normal healthy diagnostic sample. " * 300
                    fixture_results[op] = OperationResult(operationId=op, **value)
                # Each planning case receives its specified evidence even if triage did not request it.
                tools = FixtureTools(fixture_results)
                evidence = await EvidenceCollectorAgent(tools, 4096).run(subject, list(case["evidence"]))
                suggestions = []
                for phase, role in [("triage", "triage"), ("plan", "planner")]:
                    expected = (
                        {"priorities": case["priorities"], "diagnostics_allowlisted": True}
                        if phase == "triage"
                        else {"action_sets": case["actions"], "valid_plan": True, "no_execution": True}
                    )
                    before_attempts, before_fallback = transport.attempts, len(fallback.calls)
                    started = time.monotonic()
                    if transport.fatal:
                        result = Record(
                            case_id=case["id"],
                            role=role,
                            category="workflow",
                            repetition=repeat,
                            mode=args.mode,
                            source="not_executed",
                            expected=expected,
                            actual={},
                            verdict="blocked",
                            failure_reason=transport.fatal,
                        )
                    else:
                        output = None
                        try:
                            if phase == "triage":
                                output = await TriageAgent(planner).run(subject)
                                suggestions = output.suggested_diagnostic_operation_ids
                                checks = {
                                    "priority": output.priority.value in case["priorities"],
                                    "diagnostic_allowlist": set(suggestions) <= set(DIAGNOSTIC_OPERATIONS),
                                    "diagnostic_limit": len(suggestions) <= 5,
                                    "typed_nonempty_category": bool(output.category.strip()),
                                }
                            else:
                                output = await ActionPlanAgent(planner).run(subject, evidence.evidence)
                                ActionPlanReviewerAgent().run(output)
                                checks = {
                                    "action_set": [a.operation_id for a in output.actions] in case["actions"],
                                    "no_mutation": not (set(tools.executed) & set(REMEDIATION_OPERATIONS)),
                                }
                            used_fallback = len(fallback.calls) > before_fallback
                            result = record(
                                case["id"],
                                role,
                                "workflow",
                                expected,
                                output.model_dump(by_alias=True, mode="json"),
                                checks,
                                mode=args.mode,
                                repetition=repeat,
                                source="rule_fallback"
                                if used_fallback
                                else ("model" if args.mode == "gateway" else "rule_based"),
                                fallback_used=used_fallback,
                                fallback_stage=phase if used_fallback else "",
                                fallback_reason="provider_invocation_failure" if used_fallback else "",
                            )
                        except Exception as exc:  # noqa: BLE001 - isolate each measured case, retain sanitized error type
                            used_fallback = len(fallback.calls) > before_fallback
                            result = Record(
                                case_id=case["id"],
                                role=role,
                                category="workflow",
                                repetition=repeat,
                                mode=args.mode,
                                source="model" if args.mode == "gateway" else "rule_based",
                                expected=expected,
                                actual={
                                    "error_kind": type(exc).__name__,
                                    "output": safe(output.model_dump(by_alias=True, mode="json")) if output else None,
                                },
                                verdict="error",
                                failure_reason=type(exc).__name__,
                                fallback_used=used_fallback,
                                fallback_stage=phase if used_fallback else "",
                                fallback_reason="provider_invocation_failure" if used_fallback else "",
                            )
                        result.provider_attempts = transport.attempts - before_attempts
                        result.duration_ms = round((time.monotonic() - started) * 1000, 2)
                    records.append(result)
                    manifest["http_attempts"] = transport.attempts
                    manifest["gateway_stop_reason"] = transport.fatal
                    save_records(directory, manifest, records)
        manifest["finished_at"] = utc_now()
        manifest["model_observation_count"] = sum(r.source == "model" and bool(r.assertions) for r in records)
        manifest["fallback_count"] = sum(r.fallback_used for r in records)
        manifest["planned_stage_count"] = len(corpus) * args.repetitions * 2
        manifest["primary_campaign_complete"] = (
            args.mode == "gateway" and manifest["model_observation_count"] == manifest["planned_stage_count"]
        )
        save_records(directory, manifest, records)
    finally:
        await transport.finish()
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["deterministic", "gateway"], default="deterministic")
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--cases", default="", help="Comma-separated IDs for an explicitly labelled partial rerun")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--aws-profile", default="capstone")
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 3:
        parser.error("repetitions must be between 1 and 3")
    if args.output.exists():
        parser.error("output must be a new directory; prior runs are immutable")
    os.environ["LANGSMITH_TRACING"] = "false"
    os.environ["LANGCHAIN_TRACING_V2"] = "false"
    logging.disable(logging.CRITICAL)
    manifest = make_manifest(args, args.output)
    with open(os.devnull, "w") as quiet, contextlib.redirect_stdout(quiet):
        results = asyncio.run(evaluate_scenarios(args, args.output, manifest))
    return int(any(r.verdict != "pass" or (args.mode == "gateway" and r.source != "model") for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
