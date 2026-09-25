from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.api.deps import get_session_or_404
from app.core.db import get_db
from app.core.models import FlowFindingRecord, IkeFindingRecord, PolicyRecord, ScoreResultRecord
from app.core.schemas import PolicySchema, ScoreResultSchema
from app.ike.schemas import IkeHandshake, SaProposal
from app.scoring.engine import compute_score
from app.scoring.policy import CryptoPolicy, PolicyParseError, parse_policy_yaml

router = APIRouter(tags=["scoring"])


def _ike_finding_to_handshake(finding: IkeFindingRecord) -> IkeHandshake:
    proposals = [SaProposal(**p) for p in (finding.proposals or [])]
    return IkeHandshake(
        ike_version=finding.ike_version,
        exchange_type=finding.exchange_type,
        proposals=proposals,
        pfs_enabled=finding.pfs_enabled,
        vendor_ids=finding.vendor_ids or [],
        implementation_guess=finding.implementation_guess,
    )


@router.get("/sessions/{session_id}/score", response_model=ScoreResultSchema)
def get_score(
    session_id: str, policy_id: str | None = None, db: DbSession = Depends(get_db)
) -> ScoreResultSchema:
    get_session_or_404(session_id, db)
    ike_record = db.query(IkeFindingRecord).filter_by(session_id=session_id).first()
    if ike_record is None:
        raise HTTPException(status_code=404, detail="no IKE finding yet -- POST /sessions/{id}/analyze first")

    flow_records = db.query(FlowFindingRecord).filter_by(session_id=session_id).all()

    policy = CryptoPolicy()
    if policy_id:
        policy_record = db.get(PolicyRecord, policy_id)
        if policy_record is None:
            raise HTTPException(status_code=404, detail="policy not found")
        policy = CryptoPolicy(**policy_record.definition)

    handshake = _ike_finding_to_handshake(ike_record)
    result = compute_score(
        handshake,
        flows=flow_records,
        flow_confidences=[f.confidence for f in flow_records],
        policy=policy,
    )

    db.query(ScoreResultRecord).filter_by(session_id=session_id).delete()
    score_record = ScoreResultRecord(
        session_id=session_id,
        crypto_strength=result.crypto_strength,
        compliance=result.compliance,
        key_management=result.key_management,
        metadata_exposure=result.metadata_exposure,
        overall_score=result.overall_score,
        threat_matrix=[
            {
                "finding": t.finding,
                "likelihood": t.likelihood,
                "impact": t.impact,
                "recommendation": t.recommendation,
            }
            for t in result.threat_matrix
        ],
        policy_id=policy_id,
    )
    db.add(score_record)
    db.commit()
    db.refresh(score_record)
    return ScoreResultSchema.model_validate(score_record)


@router.post("/policy", response_model=PolicySchema, status_code=201)
async def upload_policy(file: UploadFile = File(...), db: DbSession = Depends(get_db)) -> PolicySchema:
    raw = (await file.read()).decode("utf-8")
    try:
        policy = parse_policy_yaml(raw)
    except PolicyParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record = PolicyRecord(name=file.filename or "policy.yaml", definition=policy.model_dump())
    db.add(record)
    db.commit()
    db.refresh(record)
    return PolicySchema.model_validate(record)


@router.get("/policy", response_model=list[PolicySchema])
def list_policies(db: DbSession = Depends(get_db)) -> list[PolicySchema]:
    records = db.execute(select(PolicyRecord).order_by(PolicyRecord.created_at.desc())).scalars().all()
    return [PolicySchema.model_validate(r) for r in records]


@router.get("/policy/{policy_id}", response_model=PolicySchema)
def get_policy(policy_id: str, db: DbSession = Depends(get_db)) -> PolicySchema:
    record = db.get(PolicyRecord, policy_id)
    if record is None:
        raise HTTPException(status_code=404, detail="policy not found")
    return PolicySchema.model_validate(record)
