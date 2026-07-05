from __future__ import annotations

import base64
import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from incident_agent.models import IncidentState
from incident_agent.observability import REQUEST_ID_HEADER, new_request_id, use_request_id
from incident_agent.persistence.store import Conflict, NotFound
from incident_agent.service import IncidentService


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

    @app.get("/incidents", response_class=HTMLResponse)
    async def list_incidents(x_amzn_oidc_data: str | None = Header(default=None)) -> HTMLResponse:
        user = _user_from_header(x_amzn_oidc_data)
        incidents = service.list()
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

    @app.get("/incidents/{incident_id}", response_class=HTMLResponse)
    async def detail(incident_id: str, x_amzn_oidc_data: str | None = Header(default=None)) -> HTMLResponse:
        _user_from_header(x_amzn_oidc_data)
        try:
            incident = service.get(incident_id)
        except NotFound as exc:
            raise HTTPException(status_code=404, detail="incident not found") from exc
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
        if incident.state == IncidentState.AWAITING_APPROVAL:
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
        plan_hash: str = Form(alias="planHash"),
        x_amzn_oidc_data: str | None = Header(default=None),
    ) -> RedirectResponse:
        user = _user_from_header(x_amzn_oidc_data)
        _same_origin(request)
        try:
            service.approve(incident_id, plan_hash, user["sub"])
        except Conflict as exc:
            raise HTTPException(status_code=409, detail="incident changed; reload before deciding") from exc
        return RedirectResponse(f"/incidents/{quote(incident_id)}", status_code=303)

    @app.post("/incidents/{incident_id}/reject")
    async def reject(
        request: Request,
        incident_id: str,
        plan_hash: str = Form(alias="planHash"),
        x_amzn_oidc_data: str | None = Header(default=None),
    ) -> RedirectResponse:
        user = _user_from_header(x_amzn_oidc_data)
        _same_origin(request)
        try:
            service.reject(incident_id, plan_hash, user["sub"])
        except Conflict as exc:
            raise HTTPException(status_code=409, detail="incident changed; reload before deciding") from exc
        return RedirectResponse(f"/incidents/{quote(incident_id)}", status_code=303)

    return app


def _user_from_header(token: str | None) -> dict[str, str]:
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
    return {"sub": str(claims["sub"]), "email": str(claims.get("email", ""))}


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
