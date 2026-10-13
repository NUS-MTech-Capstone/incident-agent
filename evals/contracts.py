"""Aggregate role records and boundary-test outcomes without persisting captured logs."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

from evals.records import CATEGORIES, ROLES, Record, record, save_records, utc_now
from evals.runner import ROOT, make_manifest

BOUNDARIES = [
    ("manager", "escalation", "tests/test_sqs.py"),
    ("triage", "routing", "tests/test_a2a_protocol.py"),
    ("collector", "escalation", "tests/test_tool_gateway_protocol.py"),
    ("manager", "workflow", "tests/test_postgres_claims.py"),
    ("manager", "safety", "evals/test_postgres_roles.py"),
    ("reviewer", "safety", "evals/test_provider_safety.py"),
    ("manager", "safety", "evals/test_harness.py"),
]


def read_junit(path: Path, role: str = "manager", category: str = "workflow") -> list[Record]:
    if not path.exists():
        return [
            Record(
                case_id="R12-TEST-RUNNER",
                role=role,
                category=category,
                mode="contract",
                source="test_runner",
                expected={"report_written": True},
                actual={},
                verdict="blocked",
                failure_reason="Test runner did not produce a report",
            )
        ]
    results = []
    for case in ET.parse(path).iter("testcase"):  # noqa: S314 - our own local pytest report
        custom = case.find("./properties/property[@name='r12_record']")
        if custom is not None:
            item = Record.model_validate_json(custom.attrib["value"])
            if case.find("failure") is not None or case.find("error") is not None:
                item.verdict = "fail"
                item.failure_reason = item.failure_reason or "Test failed after emitting its result"
            if case.find("skipped") is not None:
                item.verdict = "blocked"
                item.failure_reason = "Test skipped"
        else:
            verdict = (
                "blocked"
                if case.find("skipped") is not None
                else (
                    "error"
                    if case.find("error") is not None
                    else "fail"
                    if case.find("failure") is not None
                    else "pass"
                )
            )
            item = Record(
                case_id=f"R12-BOUNDARY-{case.attrib['name']}",
                role=role,
                category=category,
                mode="contract",
                source="existing_boundary_test",
                expected={"test_outcome": "passed"},
                actual={"test_name": case.attrib["name"], "test_outcome": verdict},
                verdict=verdict,
                failure_reason="" if verdict == "pass" else "Boundary test failed or was not executed",
            )
        item.duration_ms = float(case.attrib.get("time", "0")) * 1000
        results.append(item)
    if not results:
        return [
            Record(
                case_id="R12-EMPTY-TEST-REPORT",
                role=role,
                category=category,
                mode="contract",
                source="test_runner",
                expected={"tests_executed": True},
                actual={},
                verdict="blocked",
                failure_reason="Test report contained no test cases",
            )
        ]
    return results


def run_tests(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=180, check=False, **kwargs)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(command, 124, stdout="", stderr="")


def read_go(output: str) -> list[Record]:
    records = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        text = event.get("Output", "")
        if text.startswith("R12_RECORD "):
            records.append(Record.model_validate_json(text.removeprefix("R12_RECORD ")))
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new; do not overwrite previous evidence")
    manifest = make_manifest(SimpleNamespace(mode="deterministic", repetitions=1, cases="role_contracts"), args.output)
    records = []
    with tempfile.TemporaryDirectory(prefix="r12-contracts-") as temp:
        for index, (role, category, target) in enumerate([("manager", "routing", "evals/test_roles.py"), *BOUNDARIES]):
            report = Path(temp) / f"pytest-{index}.xml"
            run_tests(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    target,
                    f"--junitxml={report}",
                    "-o",
                    "junit_family=legacy",
                ],
                cwd=ROOT,
            )
            records.extend(read_junit(report, role, category))
        env = dict(os.environ, GOCACHE="/private/tmp/ddm-go-build-cache")
        process = run_tests(
            [
                shutil.which("go") or "go",
                "test",
                "-json",
                "./internal/service",
                "-run",
                "^TestR12RoleCases$",
                "-count=1",
            ],
            cwd=ROOT.parent / "agent-controlplane",
            env=env,
        )
        records.extend(read_go(process.stdout))
        process = run_tests(
            [
                shutil.which("go") or "go",
                "test",
                "-json",
                "./internal/service",
                "-run",
                "^TestExecuteOperationRequiresAssignedInstanceAndPlanHash$",
                "-count=1",
            ],
            cwd=ROOT.parent / "proxy-dataplane",
            env=env,
        )
        events = [json.loads(line) for line in process.stdout.splitlines() if line.startswith("{")]
        executed = any(
            e.get("Test") == "TestExecuteOperationRequiresAssignedInstanceAndPlanHash" and e.get("Action") == "pass"
            for e in events
        )
        records.append(
            record(
                "R12-BOUNDARY-DATAPLANE-OWNERSHIP",
                "executor",
                "safety",
                {"assigned_instance_and_plan_hash_enforced": True},
                {"test_passed": executed, "exit_code": process.returncode},
                {"ownership_test_executed_and_passed": executed and process.returncode == 0},
                mode="contract",
                source="existing_boundary_test",
            )
        )
    observed = {(r.role, r.category) for r in records if r.case_id.startswith("R12-" + r.role.upper() + "-")}
    for role in ROLES:
        for category in CATEGORIES:
            if (role, category) not in observed:
                records.append(
                    Record(
                        case_id=f"R12-{role.upper()}-{category.upper()}",
                        role=role,
                        category=category,
                        mode="contract",
                        source="not_executed",
                        expected={"role_case_executed": True},
                        actual={},
                        verdict="blocked",
                        failure_reason="Missing role/category evaluation record",
                    )
                )
    manifest["finished_at"] = utc_now()
    manifest["role_category_count"] = len(observed)
    save_records(args.output, manifest, records)
    print(f"Saved {len(records)} records; {len(observed)}/30 role/category rows")
    return int(any(r.verdict != "pass" for r in records))


if __name__ == "__main__":
    raise SystemExit(main())
