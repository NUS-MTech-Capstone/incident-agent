from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from evals.contracts import read_go, read_junit
from evals.records import Record, safe
from evals.runner import evaluate_scenarios


async def test_frozen_scenarios_execute_production_rule_planner(tmp_path) -> None:
    output = tmp_path / "run"
    args = SimpleNamespace(mode="deterministic", repetitions=1, cases="")
    results = await evaluate_scenarios(args, output, {"run_id": "test"})
    assert len(results) == 24
    assert all(r.verdict == "pass" for r in results)
    assert all(r.provider_attempts == 0 and not r.fallback_used and r.source == "rule_based" for r in results)
    assert len({r.case_id for r in results}) == 12
    stored = [Record.model_validate(row) for row in json.loads((output / "results.json").read_text())]
    assert stored == results


def test_artifacts_omit_secrets_and_command_like_content() -> None:
    value = safe(
        {
            "summary": "password=R12_SECRET_SENTINEL",
            "rationale": "sudo arbitrary_command",
            "nested": ["token=synthetic-test-value", "api_key=synthetic-test-value"],
        }
    )
    encoded = json.dumps(value)
    assert "R12_SECRET_SENTINEL" not in encoded
    assert "synthetic-test-value" not in encoded
    assert "arbitrary_command" not in encoded


def test_missing_empty_and_skipped_tests_are_blocked(tmp_path) -> None:
    report = tmp_path / "junit.xml"
    assert read_junit(report)[0].verdict == "blocked"
    report.write_text("<testsuite/>")
    assert read_junit(report)[0].verdict == "blocked"
    report.write_text('<testsuite><testcase name="missing_database"><skipped/></testcase></testsuite>')
    assert read_junit(report)[0].verdict == "blocked"


def test_go_results_are_validated_and_non_records_ignored() -> None:
    event = {
        "Output": "R12_RECORD "
        + json.dumps(
            {
                "case_id": "fixture",
                "role": "executor",
                "category": "safety",
                "mode": "deterministic",
                "source": "fixture",
                "expected": {},
                "actual": {},
                "verdict": "pass",
            }
        )
    }
    assert read_go("compiler noise\n" + json.dumps(event))[0].role == "executor"
    event["Output"] = event["Output"].replace('"executor"', '"invented_role"')
    with pytest.raises(ValueError):
        read_go(json.dumps(event))
