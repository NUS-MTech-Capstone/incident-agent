# Incident Agent

Alarm-driven, approval-gated incident diagnosis and remediation for
DenDenMushi. The service consumes CloudWatch alarm notifications from SQS,
collects bounded diagnostics through the assigned Proxy Dataplane, asks Amazon
Bedrock for a structured plan, and exposes Cognito-protected approval pages.

The model never produces or executes shell commands. The only mutating v1
operation is `restart_service`, implemented by the root-owned `ddm-ops` helper
on the target.

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
HTTP_TIMEOUT=10s
OPERATION_TIMEOUT=45s
MAX_OPERATION_OUTPUT_BYTES=262144
SQS_POLL_WAIT_SECONDS=20
SQS_VISIBILITY_TIMEOUT_SECONDS=600
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

## Routes

```http
GET  /healthz
GET  /incidents
GET  /incidents/{incidentId}
POST /incidents/{incidentId}/approve
POST /incidents/{incidentId}/reject
```

The incident routes trust Cognito identity headers supplied by the authenticated
ALB boundary and must not be exposed through an unauthenticated ingress.
