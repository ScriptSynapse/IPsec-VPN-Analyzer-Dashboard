from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DbSession

from app.api.deps import get_session_or_404
from app.core.db import get_db
from app.core.models import FlowFindingRecord, IkeFindingRecord
from app.core.schemas import FlowFindingSchema, IkeFindingSchema
from app.flow.extractor import FlowExtractionError, extract_flows
from app.ike.parser import IkeParseError, parse_ike
from app.ml.classifier import predict
from app.utils.pcap_io import get_first_packet_ips

router = APIRouter(prefix="/sessions", tags=["analysis"])


@router.post("/{session_id}/analyze", status_code=202)
def analyze_session(session_id: str, db: DbSession = Depends(get_db)) -> dict:
    record = get_session_or_404(session_id, db)

    try:
        handshake = parse_ike(record.pcap_path)
    except IkeParseError as exc:
        raise HTTPException(status_code=422, detail=f"IKE parsing failed: {exc}") from exc

    proposal = handshake.chosen_proposal
    db.query(IkeFindingRecord).filter_by(session_id=session_id).delete()
    db.add(
        IkeFindingRecord(
            session_id=session_id,
            ike_version=handshake.ike_version,
            exchange_type=handshake.exchange_type,
            encryption_alg=proposal.encryption_alg if proposal else None,
            auth_alg=proposal.auth_alg if proposal else None,
            dh_group=proposal.dh_group if proposal else None,
            pfs_enabled=handshake.pfs_enabled,
            sa_lifetime=proposal.lifetime_seconds if proposal else None,
            implementation_guess=handshake.implementation_guess,
            proposals=[p.model_dump() for p in handshake.proposals],
            vendor_ids=handshake.vendor_ids,
        )
    )

    try:
        flows = extract_flows(record.pcap_path)
    except FlowExtractionError as exc:
        raise HTTPException(status_code=422, detail=f"flow extraction failed: {exc}") from exc

    db.query(FlowFindingRecord).filter_by(session_id=session_id).delete()
    for flow in flows:
        label, confidence = predict(flow)
        db.add(
            FlowFindingRecord(
                session_id=session_id,
                flow_key=flow.flow_key,
                predicted_traffic_type=label,
                confidence=confidence,
                packet_count=flow.packet_count,
                avg_packet_size=flow.avg_packet_size,
                std_packet_size=flow.std_packet_size,
                duration_s=flow.duration_s,
            )
        )

    record.ike_version = handshake.ike_version
    peer_ips = get_first_packet_ips(record.pcap_path)
    if peer_ips:
        record.peer_src_ip, record.peer_dst_ip = peer_ips
    db.commit()

    return {"session_id": session_id, "status": "analyzed", "flow_count": len(flows)}


@router.get("/{session_id}/ike", response_model=IkeFindingSchema)
def get_ike_finding(session_id: str, db: DbSession = Depends(get_db)) -> IkeFindingSchema:
    get_session_or_404(session_id, db)
    finding = db.query(IkeFindingRecord).filter_by(session_id=session_id).first()
    if finding is None:
        raise HTTPException(status_code=404, detail="no IKE finding yet -- POST /sessions/{id}/analyze first")
    return IkeFindingSchema.model_validate(finding)


@router.get("/{session_id}/flows", response_model=list[FlowFindingSchema])
def get_flow_findings(session_id: str, db: DbSession = Depends(get_db)) -> list[FlowFindingSchema]:
    get_session_or_404(session_id, db)
    findings = db.query(FlowFindingRecord).filter_by(session_id=session_id).all()
    return [FlowFindingSchema.model_validate(f) for f in findings]
