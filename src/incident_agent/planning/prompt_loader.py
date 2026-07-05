from __future__ import annotations

import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

PROMPTS_DIR_ENV = "INCIDENT_AGENT_PROMPTS_DIR"


class PromptLoader:
    def __init__(self, prompts_dir: str | Path | None = None):
        self.prompts_dir = Path(prompts_dir) if prompts_dir else _default_prompts_dir()
        self.environment = Environment(
            loader=FileSystemLoader(self.prompts_dir),
            autoescape=select_autoescape(default=False),
            undefined=StrictUndefined,
            keep_trailing_newline=True,
        )

    def render(self, template_name: str, **variables: object) -> str:
        return self.environment.get_template(template_name).render(**variables)


def _default_prompts_dir() -> Path:
    override = os.getenv(PROMPTS_DIR_ENV)
    if override:
        return Path(override)

    for parent in Path(__file__).resolve().parents:
        candidate = parent / "prompts"
        if candidate.is_dir():
            return candidate

    return Path("/app/prompts")
