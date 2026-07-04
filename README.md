# Incident Agent

Python LangGraph baseline for DenDenMushi incident triage, evidence gathering,
approval-gated action planning, and constrained remediation.

This is the first concrete Phase 2 AI-agent baseline. It is intentionally
bounded: the model can classify, summarize evidence, and propose a structured
plan, but authority to mutate infrastructure or target hosts remains outside
the model and behind explicit validation plus human approval.

The service consumes CloudWatch alarm notifications from SQS, gathers bounded
diagnostics through the existing DenDenMushi automation path, asks Bedrock
through LangChain for structured triage and plan output, stores the incident in
Postgres, and exposes Cognito-protected approval pages.

The model never receives authority to execute free-form shell commands. The
only mutating v1 operation is `restart_service`, and it runs only after a human
approves the exact stored plan hash. Live terminal traffic remains direct
between the browser, Proxy Dataplane, and target host; the incident agent never
proxies interactive terminal streams.

## Configuration

```text
PORT=8091
AWS_REGION=ap-southeast-1
INCIDENT_QUEUE_URL=
DATABASE_URL=
DATABASE_SECRET_ID=
PROXY_CONTROLPLANE_URL=http://proxy-controlplane:8080
WORKLOAD_TOKEN_FILE=/var/run/secrets/tokens/incident-agent-token
BEDROCK_MODEL_ID=global.amazon.nova-2-lite-v1:0
BEDROCK_MAX_PROMPT_BYTES=131072
HTTP_TIMEOUT_SECONDS=10
OPERATION_TIMEOUT_SECONDS=45
MAX_OPERATION_OUTPUT_BYTES=262144
SQS_POLL_WAIT_SECONDS=20
SQS_VISIBILITY_TIMEOUT_SECONDS=600
ENABLE_SQS_CONSUMER=true
LANGSMITH_TRACING=false
```

`DATABASE_SECRET_ID` must contain the raw Postgres connection URL. Prefer it to
`DATABASE_URL` in EKS.

CloudWatch alarm descriptions must be JSON:

```json
{"hostId":"host-dev-1","runbookVersion":"v1"}
```

The monitored 3-tier Terraform stack should own its alarms and pass the
DenDenMushi `incident_alerts_topic_arn` output into `alarm_actions` and
`ok_actions`. See `examples/three-tier-alarm`.

## Workflow

```text
SQS alert
-> ingest
-> triage
-> gather_evidence using DDM automation operations
-> propose_plan using structured Bedrock output
-> await human approval
-> execute approved restart_service only
-> verify service_status and health_check
-> close automation run
```

Allowed diagnostic operations:

```text
system_overview
disk_usage
memory_usage
top_processes
service_status
service_logs
health_check
```

Allowed remediation operation:

```text
restart_service
```

The deterministic supervisor rejects unknown tools, command-like plan content,
plan hash drift, missing approval, and execution outside the approved operation
order.

## Routes

```http
GET  /healthz
GET  /openapi.yaml
GET  /incidents
GET  /incidents/{incidentId}
POST /incidents/{incidentId}/approve
POST /incidents/{incidentId}/reject
```

The incident routes trust Cognito identity headers supplied by the authenticated
ALB boundary and must not be exposed through an unauthenticated ingress.

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run bandit -r src -q
uv run pip-audit
```

Run locally with a direct database URL and SQS disabled:

```bash
DATABASE_URL=sqlite:///./incident-agent.db \
ENABLE_SQS_CONSUMER=false \
uv run uvicorn incident_agent.main:app --host 0.0.0.0 --port 8091
```

## Evaluation Baseline

`evals/fixtures/baseline.json` contains deterministic incident examples used by
`pytest`. The baseline checks classification, schema validity, supported tool
selection, prompt-injection resistance, and approval gating. LangSmith tracing
and managed evaluation can be enabled later with environment variables, but CI
must pass without LangSmith credentials.
