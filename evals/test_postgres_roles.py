from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import pytest

from evals.records import record
from evals.support import alert
from incident_agent.migrate import run_migrations
from incident_agent.models import Plan
from incident_agent.persistence.store import Conflict, IncidentStore, alerts, incidents


def test_postgres_stale_worker_is_fenced(record_property) -> None:
    url = os.environ.get("INCIDENT_TEST_DATABASE_URL", "")
    if not url:
        pytest.skip("Disposable local Postgres is not configured")
    parsed = urlparse(url)
    assert parsed.hostname in {"127.0.0.1", "localhost"} and parsed.path.startswith("/r12"), (
        "R12 requires a disposable localhost database named r12*"
    )
    run_migrations(url)
    store = IncidentStore(url)
    source = alert("r12-" + uuid.uuid4().hex)
    try:
        first = store.ingest_and_claim(source, "worker-a", timedelta(minutes=2))
        with store.engine.begin() as connection:
            connection.execute(
                incidents.update()
                .where(incidents.c.id == first.incident.id)
                .values(processing_lease_expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )
        replacement = store.ingest_and_claim(source, "worker-b", timedelta(minutes=2))
        denied = False
        try:
            store.set_diagnosis(
                first.incident.id,
                "stale-run",
                "http://fixture.invalid",
                [],
                Plan(summary="No action", rationale="stale worker"),
                "stale-hash",
                claim_token=first.claim_token,
            )
        except Conflict:
            denied = True
        old_renewed = store.renew_claim(first.incident.id, first.claim_token, timedelta(minutes=2))
        new_renewed = store.renew_claim(first.incident.id, replacement.claim_token, timedelta(minutes=2))
        actual = {
            "stale_write_denied": denied,
            "old_claim_renewed": old_renewed,
            "new_claim_renewed": new_renewed,
            "processing_attempt": store.processing_attempt(first.incident.id),
        }
        result = record(
            "R12-POSTGRES-STALE-WORKER",
            "manager",
            "safety",
            {
                "stale_write_denied": True,
                "old_claim_renewed": False,
                "new_claim_renewed": True,
                "processing_attempt": 2,
            },
            actual,
            {"fenced": denied and not old_renewed and new_renewed, "reclaimed_once": actual["processing_attempt"] == 2},
            mode="contract",
            source="disposable_postgres",
        )
        record_property("r12_record", result.model_dump_json())
        assert result.verdict == "pass"
    finally:
        with store.engine.begin() as connection:
            connection.execute(alerts.delete().where(alerts.c.group_key == source.group_key))
            connection.execute(incidents.delete().where(incidents.c.group_key == source.group_key))
        store.close()
