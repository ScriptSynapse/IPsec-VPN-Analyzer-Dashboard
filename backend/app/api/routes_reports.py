from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session as DbSession

from app.api.deps import get_session_or_404
from app.core.db import get_db
from app.core.models import FlowFindingRecord, IkeFindingRecord, ScoreResultRecord
from app.core.schemas import FlowFindingSchema, IkeFindingSchema, ScoreResultSchema, SessionSchema
from app.reports.executive import build_executive_report, render_executive_markdown
from app.reports.technical import build_technical_report, render_technical_markdown

router = APIRouter(prefix="/sessions", tags=["reports"])


@router.get("/{session_id}/report")
def get_report(
    session_id: str,
    type: str = Query("technical", pattern="^(technical|executive)$"),
    format: str = Query("json", pattern="^(json|markdown)$"),
    db: DbSession = Depends(get_db),
):
    record = get_session_or_404(session_id, db)
    ike_record = db.query(IkeFindingRecord).filter_by(session_id=session_id).first()
    score_record = db.query(ScoreResultRecord).filter_by(session_id=session_id).first()
    if ike_record is None or score_record is None:
        raise HTTPException(
            status_code=404,
            detail="analysis and scoring must run before a report can be generated "
            "(POST /sessions/{id}/analyze, then GET /sessions/{id}/score)",
        )

    session_schema = SessionSchema.model_validate(record)
    ike_schema = IkeFindingSchema.model_validate(ike_record)
    score_schema = ScoreResultSchema.model_validate(score_record)

    if type == "executive":
        report = build_executive_report(session_schema, score_schema)
        if format == "markdown":
            return PlainTextResponse(render_executive_markdown(report), media_type="text/markdown")
        return report

    flow_records = db.query(FlowFindingRecord).filter_by(session_id=session_id).all()
    flow_schemas = [FlowFindingSchema.model_validate(f) for f in flow_records]
    report = build_technical_report(session_schema, ike_schema, flow_schemas, score_schema)
    if format == "markdown":
        return PlainTextResponse(render_technical_markdown(report), media_type="text/markdown")
    return report
