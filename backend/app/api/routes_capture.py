from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.api.deps import get_session_or_404
from app.core.db import get_db
from app.core.models import AgentRecord, SessionRecord
from app.core.schemas import SessionSchema, SessionUpdate
from app.utils.pcap_io import InvalidPcapError, save_upload

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.post("/upload", response_model=SessionSchema, status_code=201)
def upload_session(
    file: UploadFile = File(...),
    tunnel_id: str | None = Form(None),
    peer_label: str | None = Form(None),
    x_agent_id: str | None = Header(None),
    x_agent_key: str | None = Header(None),
    db: DbSession = Depends(get_db),
) -> SessionSchema:
    # A monitoring agent (app/agent/agent.py) identifies itself via these two
    # headers rather than a session/cookie -- same verification path as its
    # heartbeat call. A manual dashboard upload omits both and this is a
    # no-op, exactly like before this endpoint knew about agents at all.
    agent: AgentRecord | None = None
    if x_agent_id or x_agent_key:
        if not (x_agent_id and x_agent_key):
            raise HTTPException(status_code=401, detail="both X-Agent-Id and X-Agent-Key are required")
        from app.api.routes_agents import verify_agent_key  # local import: avoid a route-module import cycle

        agent = verify_agent_key(x_agent_id, x_agent_key, db)

    record = SessionRecord(
        filename=file.filename or "capture.pcap",
        pcap_path="",
        tunnel_id=tunnel_id,
        peer_label=peer_label,
        agent_id=agent.id if agent else None,
    )
    db.add(record)
    db.flush()

    try:
        pcap_path = save_upload(file, record.id)
    except InvalidPcapError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record.pcap_path = str(pcap_path)
    if agent:
        agent.last_seen_at = datetime.now(timezone.utc)
        agent.session_count += 1
    db.commit()
    db.refresh(record)
    return SessionSchema.model_validate(record)


@router.get("", response_model=list[SessionSchema])
def list_sessions(db: DbSession = Depends(get_db)) -> list[SessionSchema]:
    records = db.execute(select(SessionRecord).order_by(SessionRecord.created_at.desc())).scalars().all()
    return [SessionSchema.model_validate(r) for r in records]


@router.get("/{session_id}", response_model=SessionSchema)
def get_session(session_id: str, db: DbSession = Depends(get_db)) -> SessionSchema:
    record = get_session_or_404(session_id, db)
    return SessionSchema.model_validate(record)


@router.patch("/{session_id}", response_model=SessionSchema)
def update_session(session_id: str, update: SessionUpdate, db: DbSession = Depends(get_db)) -> SessionSchema:
    record = get_session_or_404(session_id, db)
    if update.tunnel_id is not None:
        record.tunnel_id = update.tunnel_id
    if update.peer_label is not None:
        record.peer_label = update.peer_label
    db.commit()
    db.refresh(record)
    return SessionSchema.model_validate(record)
