from __future__ import annotations

from pathlib import Path

import pytest
from jinja2 import UndefinedError

from incident_agent.planning.prompt_loader import PromptLoader


def test_prompt_loader_renders_required_variables(tmp_path: Path) -> None:
    (tmp_path / "example.md.j2").write_text("Alarm: {{ alarm_name }}\nHost: {{ host_id }}")

    rendered = PromptLoader(tmp_path).render("example.md.j2", alarm_name="High 5xx", host_id="host-1")

    assert rendered == "Alarm: High 5xx\nHost: host-1"


def test_prompt_loader_rejects_missing_variables(tmp_path: Path) -> None:
    (tmp_path / "example.md.j2").write_text("Alarm: {{ alarm_name }}")

    with pytest.raises(UndefinedError):
        PromptLoader(tmp_path).render("example.md.j2")
