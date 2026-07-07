from __future__ import annotations

import importlib


def test_main_module_import_does_not_create_runtime_app() -> None:
    module = importlib.import_module("incident_agent.main")

    assert callable(module.create_runtime_app)
    assert not hasattr(module, "app")
