from __future__ import annotations

CATALOG_VERSION = "v1"

DIAGNOSTIC_OPERATIONS = [
    "system_overview",
    "disk_usage",
    "memory_usage",
    "top_processes",
    "service_status",
    "service_logs",
    "health_check",
    "target_probe",
]

REMEDIATION_OPERATIONS = [
    "restart_service",
    "recover_demo_app",
    "reload_service",
]

VERIFY_OPERATIONS = [
    "service_status",
    "health_check",
]

SUPPORTED_OPERATIONS = set(DIAGNOSTIC_OPERATIONS + REMEDIATION_OPERATIONS + VERIFY_OPERATIONS)

REQUIRED_DIAGNOSTIC_OPERATIONS = ["service_status", "health_check"]
MAX_DIAGNOSTIC_OPERATIONS = 5


def select_diagnostic_operations(suggested: list[str]) -> list[str]:
    selected: list[str] = []
    for operation in [*REQUIRED_DIAGNOSTIC_OPERATIONS, *suggested]:
        if operation in DIAGNOSTIC_OPERATIONS and operation not in selected:
            selected.append(operation)
        if len(selected) >= MAX_DIAGNOSTIC_OPERATIONS:
            break
    return selected
