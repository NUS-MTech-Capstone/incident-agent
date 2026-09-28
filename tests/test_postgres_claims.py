from __future__ import annotations

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from incident_agent.migrate import run_migrations
from incident_agent.models import Alert
from incident_agent.persistence.store import ClaimDisposition, IncidentStore, IngestClaim, alerts, incidents


def test_postgres_concurrent_group_claim_is_atomic() -> None:
    database_url = os.getenv("INCIDENT_TEST_DATABASE_URL", "")
    if not database_url:
        pytest.skip("INCIDENT_TEST_DATABASE_URL is not configured")
    run_migrations(database_url)
    store = IncidentStore(database_url)
    suffix = uuid.uuid4().hex
    group_key = f"managed-server|host-{suffix}|High 5xx"

    def claim(index: int) -> IngestClaim:
        return store.ingest_and_claim(
            Alert(
                source_id=f"source-{suffix}-{index}",
                alarm_arn=f"arn:alarm:{suffix}",
                alarm_name="High 5xx",
                state="ALARM",
                host_id=f"host-{suffix}",
                group_key=group_key,
                occurred_at=datetime.now(UTC),
            ),
            f"worker-{index}",
            timedelta(minutes=2),
        )

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(claim, [1, 2]))

        assert sorted(result.disposition for result in results) == [
            ClaimDisposition.GROUPED,
            ClaimDisposition.PROCESS,
        ]
        assert len({result.incident.id for result in results if result.incident is not None}) == 1
    finally:
        with store.engine.begin() as conn:
            conn.execute(alerts.delete().where(alerts.c.group_key == group_key))
            conn.execute(incidents.delete().where(incidents.c.group_key == group_key))
        store.close()
