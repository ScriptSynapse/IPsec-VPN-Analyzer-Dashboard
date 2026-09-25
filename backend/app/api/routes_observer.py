from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session as DbSession

from app.api.deps import get_session_or_404
from app.core.db import get_db
from app.core.models import FlowFindingRecord, SessionRecord
from app.core.schemas import FlowFindingSchema, SessionSchema
from app.observer.correlate import build_correlated_findings, insufficient_history
from app.observer.profile import build_session_observer_findings
from app.observer.render import render_observer_profile_markdown

router = APIRouter(tags=["observer"])


def _flows_for_session(session_id: str, db: DbSession) -> list[FlowFindingSchema]:
    records = db.query(FlowFindingRecord).filter_by(session_id=session_id).all()
    return [FlowFindingSchema.model_validate(r) for r in records]


def _respond(profile: dict, format: str):
    if format == "markdown":
        return PlainTextResponse(render_observer_profile_markdown(profile), media_type="text/markdown")
    return profile


@router.get("/sessions/{session_id}/observer-profile")
def get_session_observer_profile(
    session_id: str,
    format: str = Query("json", pattern="^(json|markdown)$"),
    db: DbSession = Depends(get_db),
):
    record = get_session_or_404(session_id, db)
    flows = _flows_for_session(session_id, db)
    findings = [asdict(f) for f in build_session_observer_findings(flows)]

    if record.tunnel_id:
        tunnel_sessions = db.query(SessionRecord).filter_by(tunnel_id=record.tunnel_id).all()
        session_schemas = [SessionSchema.model_validate(s) for s in tunnel_sessions]
        sessions_flows = [_flows_for_session(s.id, db) for s in tunnel_sessions]
        findings += build_correlated_findings(session_schemas, sessions_flows)
    else:
        findings.append(insufficient_history(1))

    profile = {"session_id": session_id, "tunnel_id": record.tunnel_id, "findings": findings}
    return _respond(profile, format)


@router.get("/tunnels/{tunnel_id}/observer-profile")
def get_tunnel_observer_profile(
    tunnel_id: str,
    format: str = Query("json", pattern="^(json|markdown)$"),
    db: DbSession = Depends(get_db),
):
    sessions = db.query(SessionRecord).filter_by(tunnel_id=tunnel_id).all()
    if not sessions:
        raise HTTPException(status_code=404, detail="no sessions found for this tunnel_id")

    session_schemas = [SessionSchema.model_validate(s) for s in sessions]
    sessions_flows = [_flows_for_session(s.id, db) for s in sessions]

    per_session_findings = []
    for flows in sessions_flows:
        per_session_findings.extend(asdict(f) for f in build_session_observer_findings(flows))

    correlated = build_correlated_findings(session_schemas, sessions_flows)

    profile = {
        "tunnel_id": tunnel_id,
        "session_count": len(sessions),
        "findings": per_session_findings + correlated,
    }
    return _respond(profile, format)
