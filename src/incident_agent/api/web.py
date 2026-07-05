from __future__ import annotations

import base64
import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, TypedDict
from urllib.parse import quote

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from incident_agent.models import Incident, IncidentState, ManagedAlert
from incident_agent.observability import REQUEST_ID_HEADER, new_request_id, use_request_id
from incident_agent.persistence.store import Conflict, NotFound
from incident_agent.service import IncidentService

APPROVER_GROUPS = {"Manager", "Admin"}


class UserClaims(TypedDict):
    sub: str
    email: str
    groups: list[str]


def create_app(service: IncidentService) -> FastAPI:
    app = FastAPI(title="DenDenMushi Incident Agent API", version="0.1.0")

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = request.headers.get(REQUEST_ID_HEADER) or new_request_id()
        with use_request_id(request_id):
            response = await call_next(request)
            response.headers[REQUEST_ID_HEADER] = request_id
            return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, str]:
        try:
            service.ready()
        except Exception as exc:
            raise HTTPException(status_code=503, detail="service is not ready") from exc
        return {"status": "ready"}

    @app.get("/openapi.yaml")
    async def openapi_yaml() -> Response:
        path = Path(__file__).resolve().parents[3] / "api" / "openapi.yaml"
        return Response(path.read_text(encoding="utf-8"), media_type="application/yaml; charset=utf-8")

    @app.get("/alerts")
    async def list_alerts(x_amzn_oidc_data: str | None = Header(default=None)) -> JSONResponse:
        _user_from_header(x_amzn_oidc_data)
        return _json({"alerts": [_alert_summary(alert) for alert in service.list_alerts()]})

    @app.get("/alerts/{alert_id}")
    async def alert_detail(alert_id: str, x_amzn_oidc_data: str | None = Header(default=None)) -> JSONResponse:
        _user_from_header(x_amzn_oidc_data)
        try:
            alert = service.get_alert(alert_id)
        except NotFound as exc:
            raise HTTPException(status_code=404, detail="alert not found") from exc
        incident = None
        if alert.incident_id:
            try:
                incident = service.get(alert.incident_id)
            except NotFound:
                incident = None
        return _json(_alert_detail(alert, incident))

    @app.get("/incidents")
    async def list_incidents(
        request: Request,
        x_amzn_oidc_data: str | None = Header(default=None),
    ) -> Response:
        user = _user_from_header(x_amzn_oidc_data)
        incidents = service.list()
        if _wants_json(request):
            return _json({"incidents": [_incident_summary(incident) for incident in incidents]})
        rows = (
            "".join(
                f"<tr><td>{incident.created_at}</td><td><a href='/incidents/{quote(incident.id)}'>"
                f"{_h(incident.alarm_name)}</a></td><td>{_h(incident.host_id)}</td>"
                f"<td class='state'>{incident.state.value}</td></tr>"
                for incident in incidents
            )
            or "<tr><td colspan='4'>No incidents</td></tr>"
        )
        return HTMLResponse(
            _page(
                "Incidents",
                f"<h1>Incidents</h1><p>Signed in as {_h(user.get('email', ''))}</p>"
                "<table><thead><tr><th>Created</th><th>Alarm</th><th>Host</th><th>State</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>",
            )
        )

    @app.get("/incidents/{incident_id}")
    async def detail(
        request: Request,
        incident_id: str,
        x_amzn_oidc_data: str | None = Header(default=None),
    ) -> Response:
        user = _user_from_header(x_amzn_oidc_data)
        try:
            incident = service.get(incident_id)
        except NotFound as exc:
            raise HTTPException(status_code=404, detail="incident not found") from exc
        if _wants_json(request):
            return _json(_incident_detail(incident))
        actions = "".join(
            f"<p><code>{_h(action.operation_id)}</code>: {_h(action.reason)}</p>" for action in incident.plan.actions
        )
        plan = ""
        if incident.plan.summary:
            plan = (
                "<div class='card'><h2>Proposed plan</h2>"
                f"<p><b>{_h(incident.plan.summary)}</b></p><p>{_h(incident.plan.rationale)}</p>{actions}</div>"
            )
        decision = ""
        if incident.state == IncidentState.AWAITING_APPROVAL and _can_decide(user):
            decision = (
                f"<form method='post' action='/incidents/{quote(incident.id)}/approve'>"
                f"<input type='hidden' name='planHash' value='{_h(incident.plan_hash)}'>"
                "<button class='approve' type='submit'>Approve exact plan</button></form>"
                f"<form method='post' action='/incidents/{quote(incident.id)}/reject'>"
                f"<input type='hidden' name='planHash' value='{_h(incident.plan_hash)}'>"
                "<button class='danger' type='submit'>Reject</button></form>"
            )
        evidence = "".join(
            f"<div class='card'><b>{_h(result.operation_id)}</b> (exit {result.exit_code})"
            f"<pre>{_h(result.stdout)}{_h(result.stderr)}</pre></div>"
            for result in incident.evidence
        )
        body = (
            "<p><a href='/incidents'>Back</a></p>"
            f"<h1>{_h(incident.alarm_name)}</h1>"
            f"<div class='card'><b>State:</b> {incident.state.value}<br><b>Host:</b> {_h(incident.host_id)}"
            f"<br><b>Reason:</b> {_h(incident.reason)}</div>"
            f"{plan}{decision}"
            f"{'<h2>Evidence</h2>' + evidence if evidence else ''}"
            f"{'<h2>Report</h2><pre>' + _h(incident.report) + '</pre>' if incident.report else ''}"
            f"{'<h2>Error</h2><pre>' + _h(incident.error_message) + '</pre>' if incident.error_message else ''}"
        )
        return HTMLResponse(_page(incident.alarm_name, body))

    @app.post("/incidents/{incident_id}/approve")
    async def approve(
        request: Request,
        incident_id: str,
        x_amzn_oidc_data: str | None = Header(default=None),
    ) -> Response:
        user = _user_from_header(x_amzn_oidc_data)
        _require_decision_authority(user)
        _same_origin(request)
        plan_hash = await _plan_hash_from_request(request)
        try:
            service.approve(incident_id, plan_hash, user["sub"])
        except Conflict as exc:
            raise HTTPException(status_code=409, detail="incident changed; reload before deciding") from exc
        if _wants_json(request):
            return _json(_incident_detail(service.get(incident_id)))
        return RedirectResponse(f"/incidents/{quote(incident_id)}", status_code=303)

    @app.post("/incidents/{incident_id}/reject")
    async def reject(
        request: Request,
        incident_id: str,
        x_amzn_oidc_data: str | None = Header(default=None),
    ) -> Response:
        user = _user_from_header(x_amzn_oidc_data)
        _require_decision_authority(user)
        _same_origin(request)
        plan_hash = await _plan_hash_from_request(request)
        try:
            service.reject(incident_id, plan_hash, user["sub"])
        except Conflict as exc:
            raise HTTPException(status_code=409, detail="incident changed; reload before deciding") from exc
        if _wants_json(request):
            return _json(_incident_detail(service.get(incident_id)))
        return RedirectResponse(f"/incidents/{quote(incident_id)}", status_code=303)

    return app


def _user_from_header(token: str | None) -> UserClaims:
    if not token:
        raise HTTPException(status_code=401, detail="missing or invalid Cognito identity")
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=401, detail="missing or invalid Cognito identity")
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except Exception as exc:
        raise HTTPException(status_code=401, detail="missing or invalid Cognito identity") from exc
    if not claims.get("sub"):
        raise HTTPException(status_code=401, detail="missing or invalid Cognito identity")
    return {
        "sub": str(claims["sub"]),
        "email": str(claims.get("email", "")),
        "groups": _groups_from_claims(claims),
    }


def _groups_from_claims(claims: dict[str, Any]) -> list[str]:
    raw = claims.get("cognito:groups") or claims.get("groups") or []
    if isinstance(raw, list):
        return [str(item) for item in raw]
    if isinstance(raw, str):
        return [item.strip() for item in raw.split(",") if item.strip()]
    return []


def _can_decide(user: UserClaims) -> bool:
    return bool(APPROVER_GROUPS.intersection(user["groups"]))


def _require_decision_authority(user: UserClaims) -> None:
    if not _can_decide(user):
        raise HTTPException(status_code=403, detail="manager approval is required")


async def _plan_hash_from_request(request: Request) -> str:
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        try:
            body = await request.json()
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="planHash is required") from exc
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="planHash is required")
        value = body.get("planHash")
    else:
        form = await request.form()
        value = form.get("planHash")
    if not isinstance(value, str) or not value:
        raise HTTPException(status_code=400, detail="planHash is required")
    return value


def _wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    content_type = request.headers.get("content-type", "")
    return "application/json" in accept.lower() or "application/json" in content_type.lower()


def _json(payload: dict[str, Any]) -> JSONResponse:
    return JSONResponse(content=jsonable_encoder(payload))


def _incident_summary(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "alarmName": incident.alarm_name,
        "hostId": incident.host_id,
        "state": incident.state.value,
        "reason": incident.reason,
        "runbookVersion": incident.runbook_version,
        "planHash": incident.plan_hash,
        "approvalDecision": incident.approval_decision,
        "approvalAt": incident.approval_at,
        "createdAt": incident.created_at,
        "updatedAt": incident.updated_at,
    }


def _incident_detail(incident: Incident) -> dict[str, Any]:
    detail = _incident_summary(incident)
    detail.update(
        {
            "sourceId": incident.source_id,
            "alarmArn": incident.alarm_arn,
            "evidence": [item.model_dump(by_alias=True) for item in incident.evidence],
            "triage": incident.triage.model_dump() if incident.triage else None,
            "plan": incident.plan.model_dump(by_alias=True),
            "approverSubject": incident.approver_subject,
            "report": incident.report,
            "errorMessage": incident.error_message,
            "postIncidentStatus": _post_incident_status(incident),
            "postIncidentSummary": incident.report or incident.error_message,
        }
    )
    return detail


def _alert_summary(alert: ManagedAlert) -> dict[str, Any]:
    return {
        "id": alert.id,
        "sourceId": alert.source_id,
        "sourceType": alert.source_type,
        "alarmArn": alert.alarm_arn,
        "alarmName": alert.alarm_name,
        "cloudwatchState": alert.cloudwatch_state,
        "hostId": alert.host_id,
        "reason": alert.reason,
        "status": alert.status.value,
        "groupKey": alert.group_key,
        "incidentId": alert.incident_id,
        "errorSummary": alert.error_summary,
        "occurredAt": alert.occurred_at,
        "createdAt": alert.created_at,
        "updatedAt": alert.updated_at,
    }


def _alert_detail(alert: ManagedAlert, incident: Incident | None) -> dict[str, Any]:
    detail = _alert_summary(alert)
    detail["incident"] = _incident_detail(incident) if incident else None
    return detail


def _post_incident_status(incident: Incident) -> str:
    if incident.state in {
        IncidentState.COMPLETED,
        IncidentState.RECOVERED,
        IncidentState.REJECTED,
        IncidentState.FAILED,
    }:
        return incident.state.value
    return ""


def _same_origin(request: Request) -> None:
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        raise HTTPException(status_code=403, detail="cross-site decisions are not allowed")
    origin = request.headers.get("origin")
    host = request.headers.get("host")
    if origin and (host is None or host not in origin):
        raise HTTPException(status_code=403, detail="cross-site decisions are not allowed")


def _h(value: object) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _page(title: str, body: str) -> str:
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_h(title)}</title><style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a}}
table{{border-collapse:collapse;width:100%}}th,td{{padding:.65rem;border-bottom:1px solid #ddd;text-align:left}}
.state{{font-weight:700}}.card{{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}}
pre{{white-space:pre-wrap;background:#f6f8fa;padding:1rem;overflow:auto}}button{{padding:.6rem 1rem;margin-right:.5rem}}
.danger{{background:#a61b1b;color:white;border:0}}.approve{{background:#176b36;color:white;border:0}}
a{{color:#175ea8}}</style></head><body>{body}</body></html>"""
