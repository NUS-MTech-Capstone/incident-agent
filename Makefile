.PHONY: sync lint format-check typecheck test test-postgres coverage build security audit ci

sync:
	uv sync --frozen

lint:
	uv run ruff check .

format-check:
	uv run ruff format --check .

typecheck:
	uv run mypy

test:
	uv run pytest

test-postgres:
	@test -n "$(INCIDENT_TEST_DATABASE_URL)" || (echo "INCIDENT_TEST_DATABASE_URL is required" && exit 1)
	uv run pytest -q tests/test_migrate.py tests/test_postgres_claims.py

coverage:
	uv run pytest --cov=incident_agent --cov-report=term-missing --cov-report=xml --cov-report=html

build:
	uv build --no-build-isolation

security:
	uv run bandit -r src -q

audit:
	uv run pip-audit

ci: sync lint format-check typecheck test security audit
