FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
COPY api ./api
COPY prompts ./prompts

FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/src"

WORKDIR /app
RUN useradd --system --uid 10001 --create-home incident-agent
COPY --from=builder --chown=10001:10001 /app /app
USER 10001:10001

EXPOSE 8091
CMD ["uvicorn", "incident_agent.main:app", "--host", "0.0.0.0", "--port", "8091"]
