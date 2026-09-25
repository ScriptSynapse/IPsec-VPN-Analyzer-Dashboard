from fastapi import HTTPException
from sqlalchemy.orm import Session as DbSession

from app.core.models import SessionRecord


def get_session_or_404(session_id: str, db: DbSession) -> SessionRecord:
    record = db.get(SessionRecord, session_id)
    if record is None:
        raise HTTPException(status_code=404, detail="session not found")
    return record
