from __future__ import annotations

from incident_agent.persistence.store import normalize_database_url


def test_normalize_database_url_accepts_heroku_style_postgres_scheme() -> None:
    assert (
        normalize_database_url("postgres://user:pass@db.example.com:5432/incidents")
        == "postgresql+psycopg://user:pass@db.example.com:5432/incidents"
    )


def test_normalize_database_url_selects_installed_postgresql_driver() -> None:
    assert (
        normalize_database_url("postgresql://user:pass@db.example.com:5432/incidents")
        == "postgresql+psycopg://user:pass@db.example.com:5432/incidents"
    )


def test_normalize_database_url_preserves_explicit_or_non_postgres_schemes() -> None:
    assert (
        normalize_database_url("postgresql+psycopg://user:pass@db.example.com:5432/incidents")
        == "postgresql+psycopg://user:pass@db.example.com:5432/incidents"
    )
    assert normalize_database_url("sqlite+pysqlite://") == "sqlite+pysqlite://"
