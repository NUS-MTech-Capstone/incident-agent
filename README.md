# Incident Agent

Python LangGraph baseline for DenDenMushi incident triage, evidence gathering,
approval-gated action planning, and constrained remediation.

This is the first concrete Phase 2 AI-agent baseline. It is intentionally
bounded: the model can classify, summarize evidence, and propose a structured
plan, but authority to mutate infrastructure or target hosts remains outside
the model and behind explicit validation plus human approval.

The service consumes managed-server CloudWatch alarm notifications from SQS,
gathers bounded diagnostics through the existing DenDenMushi automation path,
asks Bedrock through LangChain for structured triage and plan output, stores
sanitized alert and incident metadata in Postgres, and exposes
Cognito-protected approval pages plus JSON endpoints for the Angular Agentic AI
UI.

The model never receives authority to execute free-form shell commands. The
only mutating v1 operation is `restart_service`, and it runs only after a human
approves the exact stored plan hash. Live terminal traffic remains direct
between the browser, Proxy Dataplane, and target host; the incident agent never
proxies interactive terminal streams.

## Configuration

```text
PORT=8091
LOG_FORMAT=json
AWS_REGION=ap-southeast-1
ENVIRONMENT=dev
CLOUDWATCH_NAMESPACE=DenDenMushi
INCIDENT_QUEUE_URL=
DATABASE_URL=
DATABASE_SECRET_ID=
PROXY_CONTROLPLANE_URL=http://proxy-controlplane:8080
WORKLOAD_TOKEN_FILE=/var/run/secrets/tokens/incident-agent-token
BEDROCK_MODEL_ID=global.amazon.nova-2-lite-v1:0
BEDROCK_MAX_PROMPT_BYTES=131072
INCIDENT_AGENT_PROMPTS_DIR=
HTTP_TIMEOUT_SECONDS=10
TRANSIENT_RETRY_ATTEMPTS=2
OPERATION_TIMEOUT_SECONDS=45
MAX_OPERATION_OUTPUT_BYTES=262144
SQS_POLL_WAIT_SECONDS=20
SQS_VISIBILITY_TIMEOUT_SECONDS=600
ENABLE_SQS_CONSUMER=true
LANGSMITH_TRACING=false
```

`DATABASE_SECRET_ID` must contain the raw Postgres connection URL. Prefer it to
`DATABASE_URL` in EKS.

Bedrock prompt templates live under the repository root `prompts/` directory.
`INCIDENT_AGENT_PROMPTS_DIR` may point at another template directory for local
experiments or environment-specific packaging; if unset, the service resolves
the root `prompts/` directory and the Docker image copies it to `/app/prompts`.

CloudWatch alarm descriptions must be JSON:

```json
{"source":"managed-server","hostId":"host-dev-1","runbookVersion":"v1"}
```

Only alarms with `source=managed-server` are turned into alert and incident
records. Other CloudWatch alarms delivered to the central queue are
acknowledged and ignored so DenDenMushi platform alarms do not appear in the
managed-server alert inbox.

Target host Terraform should pass the DenDenMushi
`incident_alerts_topic_arn` output into its alarm actions so target ALARM/OK
transitions land in the central incident queue.

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

## Observability

Production observability is AWS-native by default. The service emits JSON logs
when `LOG_FORMAT=json`, propagates `X-Request-ID` on HTTP requests, creates a
correlation ID for each SQS message, and writes CloudWatch EMF metrics to
stdout in `CLOUDWATCH_NAMESPACE`.

Metrics use low-cardinality dimensions only (`Service=incident-agent` and
`Environment`). Log fields are metadata such as `requestId`, `incidentId`,
`runId`, `hostId`, `operation`, `planHash`, `state`, `durationMs`, and
`errorKind`; prompts, model responses, tokens, command bodies, diagnostic
stdout/stderr, and terminal streams must not be logged.

LangSmith can be enabled for local or staging prompt debugging with
`LANGSMITH_TRACING=true`, but production keeps it disabled. Bedrock invocation
logging and OpenTelemetry/X-Ray tracing should also remain disabled by default
because they can retain sensitive prompt or evidence data; enable them only for
short, explicit debug windows.

SQS failures are left for normal queue redelivery and DLQ handling. Inspect the
Terraform-created DLQ when `SQSMessageFailures` alarms, fix the parser or
upstream alarm description, then replay messages by redriving them from the DLQ.

Alert rows store sanitized metadata only: source identifiers, managed-server
source type, alarm ARN/name, CloudWatch state, host ID, reason, status,
group key, linked incident ID, grouped flag, error summary, and timestamps.
Raw SNS/SQS payloads are not retained.

The `groupKey` suppresses duplicate active agent runs. A managed-server `ALARM`
for the same active group links to the existing incident and records an
`AlertGrouped` timeline event instead of starting another workflow. The alert
row is still retained for operator visibility. Managed-server `OK` alerts
recover matching active incidents and record recovery timeline metadata.

Alert statuses:

```text
RECEIVED -> TRIAGING -> PENDING_APPROVAL -> EXECUTING -> RESOLVED
RECEIVED -> TRIAGING -> TRIAGED
RECEIVED -> TRIAGING -> FAILED
PENDING_APPROVAL -> REJECTED
```

## Routes

```http
GET  /healthz
GET  /readyz
GET  /openapi.yaml
GET  /alerts
GET  /alerts/{alertId}
GET  /agentic-ai/health
GET  /incidents
GET  /incidents/{incidentId}
POST /incidents/{incidentId}/approve
POST /incidents/{incidentId}/reject
```

The incident list and detail routes preserve their HTML responses for direct
browser review. When called with `Accept: application/json`, they return safe
incident summaries/details for the Angular Agentic AI tab. The JSON incident
detail includes stored triage summary/rationale, proposed plan, evidence,
approval metadata, plan expiry, append-only timeline, approval decision audit,
and structured post-incident report/error fields. Approval routes accept either
HTML form data or JSON:

```json
{"planHash":"<exact stored plan hash>"}
```

JSON approval and rejection responses return the updated incident detail.
`/alerts` and `/alerts/{alertId}` return sanitized managed-server alert
metadata and the linked incident detail when one exists. `/agentic-ai/health`
returns safe operational status for the Angular Agentic AI page: database
readiness, queue consumer configured/running flags, last processed alert time,
last sanitized error summary, and active/failed incident counts. The JSON surface
intentionally omits raw payloads, automation operation URLs, capability tokens,
secrets, prompts, and terminal streams.

The incident routes trust Cognito identity headers supplied by the authenticated
ALB boundary and must not be exposed through an unauthenticated ingress. Any
authenticated operator may view incidents, but approval and rejection require
the Cognito user to be in the `Manager` or `Admin` group.

Proposed plans expire 30 minutes after `PlanProposed`. Approve/reject attempts
after expiry return `409` and are recorded in the approval audit. All approval
attempts are retained as sanitized metadata, including successful decisions,
manager/admin authorization failures, stale plan hashes, missing incidents, and
expired plans.

## Development

The Python import namespace remains `incident_agent`, with implementation
grouped into domain subpackages:

```text
incident_agent.api          HTTP routes and approval pages
incident_agent.automation   DenDenMushi automation client
incident_agent.ingest       CloudWatch/SQS alert ingestion
incident_agent.persistence  incident storage
incident_agent.planning     prompts, Bedrock planning, LangGraph workflow, guardrails
```

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
