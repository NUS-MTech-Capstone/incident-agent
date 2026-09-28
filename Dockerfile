FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY pyproject.toml uv.lock ./
COPY src ./src
COPY api ./api
COPY prompts ./prompts
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini
RUN uv sync --frozen --no-dev --no-editable
RUN /app/.venv/bin/python -c "import incident_agent.main; assert callable(incident_agent.main.create_runtime_app)"

FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app
RUN useradd --system --uid 10001 --create-home incident-agent
COPY --from=builder --chown=10001:10001 /app /app
USER 10001:10001

EXPOSE 8091
CMD ["uvicorn", "incident_agent.main:create_runtime_app", "--factory", "--host", "0.0.0.0", "--port", "8091"]
