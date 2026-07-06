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
sanitized alert and incident metadata in Postgres. The Go
`agent-controlplane` exposes Cognito-protected approval pages plus JSON
endpoints for the Angular Agentic AI UI.

The model never receives authority to execute free-form shell commands.
Mutating operations come from the code-reviewed v1 remediation catalog, and one
catalog operation runs only after a human approves the exact stored plan hash.
Live terminal traffic remains direct
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
AGENT_CONTROLPLANE_URL=http://agent-controlplane:8092
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
-> execute the single approved v1 remediation operation
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
target_probe
```

Allowed v1 remediation operations:

```text
restart_service
recover_demo_app
reload_service
```

The deterministic supervisor rejects unknown tools, command-like plan content,
plan hash drift, missing approval, multiple remediation actions, and execution
outside the v1 remediation catalog.

Each incident stores safe explainability metadata in `explanation_json`: model
provider/type/ID, Bedrock region, prompt template hashes, catalog version,
diagnostic and verification operation IDs, tool-selection reasons, guardrail
outcomes, and responsibility boundaries. It intentionally excludes rendered
prompts, model responses, tokens, command bodies, secrets, and terminal streams.

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

`PlanValidationFailed` timeline events are metadata-only and record validation
failure class names, not raw model output or rejected command-like text.

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

`AGENT_CONTROLPLANE_URL` is used for bounded automation run start/token/close
calls. `PROXY_CONTROLPLANE_URL` remains as a temporary local fallback during
the extraction rollout.

## Routes

```http
GET  /healthz
GET  /readyz
GET  /openapi.yaml
GET  /internal/worker/health
```

Public Agentic AI routes now live in `agent-controlplane`:

```http
GET  /agentic-ai/health
GET  /alerts
GET  /alerts/{alertId}
GET  /incidents
GET  /incidents/{incidentId}
POST /incidents/{incidentId}/approve
POST /incidents/{incidentId}/reject
```

`/internal/worker/health` returns safe worker status for agent-controlplane:
database readiness, queue consumer configured/running flags, last processed
alert time, last sanitized error summary, and active/failed incident counts. It
intentionally omits raw payloads, automation operation URLs, capability tokens,
secrets, prompts, and terminal streams.

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
