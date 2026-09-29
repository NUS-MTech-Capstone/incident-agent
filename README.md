# Incident Agent

Python LangGraph baseline for DenDenMushi incident triage, evidence gathering,
approval-gated action planning, and constrained remediation.

This is the first concrete Phase 2 AI-agent baseline. It is intentionally
bounded: the model can classify, summarize evidence, and propose a structured
plan, but authority to mutate infrastructure or target hosts remains outside
the model and behind explicit validation plus human approval.

The coordinator consumes managed-server CloudWatch alarm notifications from
SQS, delegates structured triage and planning to a private Reasoning Agent over
A2A, gathers bounded diagnostics through a private MCP Tool Gateway, and stores
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
INCIDENT_AGENT_COMPONENT=coordinator
SERVICE_NAME=incident-agent
LOG_FORMAT=json
AWS_REGION=ap-southeast-1
ENVIRONMENT=dev
CLOUDWATCH_NAMESPACE=DenDenMushi
INCIDENT_QUEUE_URL=
DATABASE_URL=
DATABASE_SECRET_ID=
AGENT_CONTROLPLANE_URL=http://agent-controlplane:8092
REASONING_AGENT_URL=http://incident-reasoning-agent:8093
TOOL_GATEWAY_URL=http://agent-tool-gateway:8094/mcp
STS_URL=http://sts:8082
TOOL_POLICY_FILE=
PROXY_CONTROLPLANE_URL=http://proxy-controlplane:8080
WORKLOAD_TOKEN_FILE=/var/run/secrets/tokens/incident-agent-token
PLANNER_MODE=openai_with_fallback
OPENAI_MODEL=gpt-5.4-2026-03-05
OPENAI_AUTH_MODE=aws_iam
OPENAI_GATEWAY_URL=
OPENAI_GATEWAY_TARGET=openai
OPENAI_AWS_REGION=ap-southeast-1
OPENAI_REASONING_EFFORT=low
OPENAI_MAX_OUTPUT_TOKENS=4096
OPENAI_TIMEOUT_SECONDS=60
OPENAI_API_KEY=
BEDROCK_REGION=us-east-1
BEDROCK_MODEL_ID=global.amazon.nova-2-lite-v1:0
BEDROCK_FALLBACK_ENABLED=true
BEDROCK_MAX_PROMPT_BYTES=131072
INCIDENT_AGENT_PROMPTS_DIR=
HTTP_TIMEOUT_SECONDS=10
TRANSIENT_RETRY_ATTEMPTS=2
OPERATION_TIMEOUT_SECONDS=45
MAX_OPERATION_OUTPUT_BYTES=262144
SQS_POLL_WAIT_SECONDS=20
SQS_VISIBILITY_TIMEOUT_SECONDS=600
INCIDENT_CLAIM_LEASE_SECONDS=120
INCIDENT_CLAIM_RENEW_SECONDS=30
ENABLE_SQS_CONSUMER=true
LANGSMITH_TRACING=false
LANGSMITH_API_KEY_SECRET_ID=
LANGSMITH_PROJECT=
LANGSMITH_ENDPOINT=
LANGSMITH_WORKSPACE_ID=
```

`DATABASE_SECRET_ID` must contain the raw Postgres connection URL. Prefer it to
`DATABASE_URL` in EKS. The service accepts `postgres://`, `postgresql://`, and
`postgresql+psycopg://` URLs, normalizing them to the bundled `psycopg` driver
before opening the SQLAlchemy engine.

When `LANGSMITH_TRACING=true`, the Reasoning Agent reads `LANGSMITH_API_KEY` from the
environment or fetches it from `LANGSMITH_API_KEY_SECRET_ID` in AWS Secrets
Manager before constructing the LangChain Bedrock client. If no key is
available, tracing is disabled and the worker continues so incident processing
is not blocked by optional observability. The API key, secret ID, prompts, model
responses, and diagnostic output are not logged.

Planner prompt templates live under the repository root `prompts/` directory.
`INCIDENT_AGENT_PROMPTS_DIR` may point at another template directory for local
experiments or environment-specific packaging; if unset, the service resolves
the root `prompts/` directory and the Docker image copies it to `/app/prompts`.
`PLANNER_MODE` controls model usage. Dev uses the IAM-authenticated AgentCore
inference gateway and pinned `gpt-5.4-2026-03-05` with deterministic fallback:

- `bedrock_with_fallback`: Bedrock first, then deterministic fallback on
  provider invocation failure.
- `bedrock`: Bedrock only.
- `openai_with_fallback`: OpenAI Responses API first, then deterministic
  fallback on provider invocation failure.
- `openai`: OpenAI Responses API only.
- `rule_based`: deterministic triage and planning, no LLM calls.

Provider modes and model IDs are code allowlisted before a provider client is
constructed. `OPENAI_AUTH_MODE=aws_iam` signs every request for service
`bedrock-agentcore` with the current IRSA credentials. The Terraform gateway
URL ends in `/mcp`; the client removes that MCP suffix and sends inference to
`/inference/v1/responses`. The gateway route is
`openai/gpt-5.4-2026-03-05`. The pod has `InvokeGateway` permission but no
permission to read the OpenAI secret. `OPENAI_AUTH_MODE=api_key` remains
available for local development and is the only mode that requires
`OPENAI_API_KEY`. Never put an API key in this README, Kustomize overlays,
Terraform variables, shell history, or committed manifests.

OpenAI requests use `reasoning.effort=low`, low text verbosity,
`max_output_tokens=4096`, `store=false`, a 60-second provider timeout, and at
most two attempts. The dedicated OpenAI project is intentionally opted into
input/output sharing for complimentary usage. `store=false` disables Responses
API application storage for these calls; it does not override that project
sharing choice. Prompts and evidence therefore remain redacted, bounded, and
free of credentials or terminal streams.

`BEDROCK_REGION` overrides only the compatibility Bedrock runtime client region. Leave
`AWS_REGION` set to the deployment region for SQS, Secrets Manager, and other
AWS dependencies. `global.amazon.nova-2-lite-v1:0` in `us-east-1` is the
configured Bedrock model for dev; if the Nova quota was requested in another
region, set `BEDROCK_REGION` to that region before rollout.
The deployed OpenAI fallback mode handles availability errors such as throttling, quota
exhaustion, and network failures by using the deterministic `RuleBasedPlanner`.
It never falls back to Bedrock or Nova. Bedrock modes and `gpt-5.5` remain in
the reviewed compatibility allowlists but are not selected by the dev workload.
Invalid model JSON, oversized prompts, and plan validation failures still fail
the incident because those are correctness or safety failures, not provider
availability failures.

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

## Multi-Agent Workflow

```text
SQS alert
-> Incident Manager Agent
-> Reasoning Agent over A2A for structured triage
-> Evidence Collector Agent through the MCP Tool Gateway
-> Reasoning Agent over A2A for a structured single-action candidate plan
-> Action Plan Reviewer Agent with deterministic guardrails and plan hash
-> await human approval
-> Agent Control Plane through the MCP Tool Gateway for the approved operation
-> verify service_status and health_check
-> close automation run
```

The coordinator and Reasoning Agent are separate private workloads using the
official A2A Python SDK. Authenticated `GET /.well-known/agent-card.json` advertises one
`analyze_incident` skill and `POST /` accepts A2A JSON-RPC for the `triage` and
`plan` stages. A2A task state is disposable; Postgres remains authoritative.
The Reasoning Agent has no database, SQS, Kubernetes, or operation permissions.

The Tool Gateway is an official Streamable HTTP MCP server at `/mcp`. It
filters `tools/list` by projected workload identity and accepts only `runId`
plus `planHash` where required. The GitOps policy defaults to deny. The
coordinator can discover diagnostics; Agent Control Plane can discover the
reviewed remediation catalog and fixed verification tools; the Reasoning Agent
has no tools. Commands, addresses, credentials, URLs, and arbitrary arguments
are never accepted. The model proposes, deterministic code reviews,
Manager/Admin users approve, and fresh STS capabilities authorize execution.

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
named agent roles, reasoning types, memory scope, tools, inputs, outputs,
handoffs, diagnostic and verification operation IDs, tool-selection reasons,
guardrail outcomes, and responsibility boundaries. It intentionally excludes
rendered prompts, model responses, tokens, command bodies, secrets, and
terminal streams.

## Observability

Production observability is AWS-native by default. The service emits JSON logs
when `LOG_FORMAT=json`, propagates `X-Request-ID` on HTTP requests, creates a
correlation ID for each SQS message, and writes CloudWatch EMF metrics to
stdout in `CLOUDWATCH_NAMESPACE`.

Metrics use low-cardinality dimensions only (`Service` is the active component
name and `Environment` identifies the environment). Log fields are metadata such as `requestId`, `incidentId`,
`runId`, `hostId`, `operation`, `planHash`, `state`, `durationMs`, and
`errorKind`; prompts, model responses, tokens, command bodies, diagnostic
stdout/stderr, and terminal streams must not be logged.
Claim lifecycle signals are `IncidentClaimContended`,
`IncidentClaimReclaimed`, and `IncidentClaimLost`; SQS heartbeat failures emit
`SQSVisibilityExtensionFailures` without adding high-cardinality dimensions.

LangSmith can be enabled for local or staging prompt debugging with
`LANGSMITH_TRACING=true`; the dev Kubernetes overlay wires the API key only to
the Reasoning Agent through AWS Secrets Manager. Production keeps it disabled. Bedrock invocation logging
and OpenTelemetry/X-Ray tracing should also remain disabled by default because
they can retain sensitive prompt or evidence data; enable them only for short,
explicit debug windows.

SQS failures are left for normal queue redelivery and DLQ handling. Inspect the
Terraform-created DLQ when `SQSMessageFailures` alarms, fix the parser or
upstream alarm description, then replay messages by redriving them from the DLQ.

Alert rows store sanitized metadata only: source identifiers, managed-server
source type, alarm ARN/name, CloudWatch state, host ID, reason, status,
group key, linked incident ID, grouped flag, error summary, and timestamps.
Raw SNS/SQS payloads are not retained.

`PlanValidationFailed` timeline events are metadata-only and record validation
failure class names, not raw model output or rejected command-like text.

The deterministic `groupKey` (`sourceType|hostId|alarmName`) suppresses duplicate
active agent runs. Postgres atomically permits only one active incident per
non-empty group key. A managed-server `ALARM` for the same active group links to
the existing incident and records an `AlertGrouped` timeline event instead of
starting another workflow. The alert row is still retained for operator
visibility.

Diagnosis ownership uses an opaque, renewable, per-process fenced lease. A
same-source SQS redelivery is not acknowledged while another live owner holds
the claim. After expiry, a worker can reclaim the incident, emit
`IncidentProcessingReclaimed`, and restart read-only diagnosis from the
beginning. Every diagnosis state write checks the new claim token, so an old
worker cannot overwrite the replacement. The SQS consumer also extends message
visibility while work is in progress. It receives one message at a time and,
when another worker owns the claim, shortens that message's visibility to the
configured claim-renew interval without acknowledging it. Managed-server `OK`
alerts clear any diagnosis claim, recover matching active incidents, and
record recovery timeline metadata.

This ownership path intentionally does not use a vector store. Embedding
similarity is not a concurrency primitive and cross-incident model memory is
outside the current bounded-agent scope.

Alert statuses:

```text
RECEIVED -> TRIAGING -> PENDING_APPROVAL -> EXECUTING -> RESOLVED
RECEIVED -> TRIAGING -> TRIAGED
RECEIVED -> TRIAGING -> FAILED
PENDING_APPROVAL -> REJECTED
```

`AGENT_CONTROLPLANE_URL` is used for automation-run lifecycle and state-aware
capability requests. Operation execution always uses `TOOL_GATEWAY_URL`.
`PROXY_CONTROLPLANE_URL` remains only as a local compatibility fallback for the
control-plane address and is not an operation path.

## Routes

```http
GET  /healthz
GET  /readyz
GET  /openapi.yaml
GET  /internal/worker/health
```

Private protocol routes use separate component processes from the same image:

```http
GET  /.well-known/agent-card.json  # Reasoning Agent, port 8093
POST /                             # A2A JSON-RPC, port 8093
POST /mcp                          # MCP Streamable HTTP, port 8094
```

Every A2A and MCP request carries a projected service-account token validated
through STS TokenReview. Authentication, validation, policy, stale-state, and
plan-hash failures fail closed. Only bounded transient A2A/provider failures
fall back to the deterministic planner. Diagnostics and verification allow one
transient transport retry; remediation is never retried automatically.

Business endpoints require `x-api-version: 1`. `GET /healthz`, `GET /readyz`,
and `GET /openapi.yaml` are exempt so probes and spec reads do not need custom
headers.
Successful probe access logs are suppressed; failed probe responses still emit
access logs.

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

Run the focused transactional claim test against a migrated disposable
Postgres database:

```bash
INCIDENT_TEST_DATABASE_URL=postgresql://... make test-postgres
```

Production schema changes run through the `incident-agent-migrate` Argo CD
PreSync job before the Deployment rolls out. The image contains Alembic and can
also be migrated explicitly with either `DATABASE_URL` or
`DATABASE_SECRET_ID` configured:

```bash
uv run python -m incident_agent.migrate
```

Application startup never creates or changes tables. The migration entrypoint
upgrades versioned and empty databases normally. For the original unversioned
production schema, it first requires the complete revision 0004 table, column,
primary-key, and source-ID uniqueness signature; recreates only the known
baseline indexes omitted by the legacy `create_all` path; stamps revision 0004;
then upgrades and verifies revision 0005, the claim columns, and the partial
unique active-group index. Unknown, incomplete, or partially upgraded schemas
fail closed without logging database URLs, row values, or group keys.

Run locally with a direct database URL and SQS disabled:

```bash
DATABASE_URL=sqlite:///./incident-agent.db \
ENABLE_SQS_CONSUMER=false \
uv run incident-agent
```

## Evaluation Baseline

`evals/fixtures/baseline.json` contains deterministic incident examples used by
`pytest`. The baseline checks classification, schema validity, supported tool
selection, prompt-injection resistance, and approval gating. LangSmith tracing
and managed evaluation can be enabled later with environment variables, but CI
must pass without LangSmith credentials.
