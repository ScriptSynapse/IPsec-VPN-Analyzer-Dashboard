import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SessionRecord(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    filename: Mapped[str] = mapped_column(String)
    pcap_path: Mapped[str] = mapped_column(String)
    mode: Mapped[str | None] = mapped_column(String, nullable=True)
    ip_version: Mapped[str | None] = mapped_column(String, nullable=True)
    ike_version: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    # PHASE2.md: user-supplied grouping so multiple captures of the same
    # monitored tunnel can be correlated over time (app/observer/correlate.py).
    tunnel_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    peer_label: Mapped[str | None] = mapped_column(String, nullable=True)
    # Observed (not user-supplied) peer addresses, read from the capture's
    # first IP packet during analysis -- used for the peer_stability finding.
    peer_src_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    peer_dst_ip: Mapped[str | None] = mapped_column(String, nullable=True)

    # Set when this session was submitted by a monitoring agent (app/agent/)
    # rather than a manual dashboard upload -- feeds the /topology graph.
    agent_id: Mapped[str | None] = mapped_column(ForeignKey("agents.id"), nullable=True, index=True)
    agent: Mapped["AgentRecord | None"] = relationship(back_populates="sessions")

    ike_finding: Mapped["IkeFindingRecord | None"] = relationship(
        back_populates="session", uselist=False, cascade="all, delete-orphan"
    )
    flow_findings: Mapped[list["FlowFindingRecord"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    score_result: Mapped["ScoreResultRecord | None"] = relationship(
        back_populates="session", uselist=False, cascade="all, delete-orphan"
    )


class IkeFindingRecord(Base):
    __tablename__ = "ike_findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), unique=True)

    ike_version: Mapped[str | None] = mapped_column(String, nullable=True)
    exchange_type: Mapped[str | None] = mapped_column(String, nullable=True)
    encryption_alg: Mapped[str | None] = mapped_column(String, nullable=True)
    auth_alg: Mapped[str | None] = mapped_column(String, nullable=True)
    dh_group: Mapped[str | None] = mapped_column(String, nullable=True)
    pfs_enabled: Mapped[bool | None] = mapped_column(nullable=True)
    sa_lifetime: Mapped[int | None] = mapped_column(Integer, nullable=True)
    implementation_guess: Mapped[str | None] = mapped_column(String, nullable=True)
    proposals: Mapped[list | None] = mapped_column(JSON, nullable=True)
    vendor_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)

    session: Mapped["SessionRecord"] = relationship(back_populates="ike_finding")


class FlowFindingRecord(Base):
    __tablename__ = "flow_findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"))

    flow_key: Mapped[str] = mapped_column(String)
    predicted_traffic_type: Mapped[str] = mapped_column(String)
    confidence: Mapped[float] = mapped_column(Float)
    packet_count: Mapped[int] = mapped_column(Integer)
    avg_packet_size: Mapped[float] = mapped_column(Float)
    std_packet_size: Mapped[float | None] = mapped_column(Float, nullable=True)
    duration_s: Mapped[float] = mapped_column(Float)
    feature_importances: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    session: Mapped["SessionRecord"] = relationship(back_populates="flow_findings")


class ScoreResultRecord(Base):
    __tablename__ = "score_results"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), unique=True)

    crypto_strength: Mapped[float] = mapped_column(Float)
    compliance: Mapped[float] = mapped_column(Float)
    key_management: Mapped[float] = mapped_column(Float)
    metadata_exposure: Mapped[float] = mapped_column(Float)
    overall_score: Mapped[float] = mapped_column(Float)
    threat_matrix: Mapped[list] = mapped_column(JSON)
    policy_id: Mapped[str | None] = mapped_column(String, nullable=True)

    session: Mapped["SessionRecord"] = relationship(back_populates="score_result")


class PolicyRecord(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    definition: Mapped[dict] = mapped_column(JSON)


class AgentRecord(Base):
    """A monitoring agent running on an authorized remote machine (see
    app/agent/agent.py) -- captures traffic locally and uploads pcaps to this
    backend via POST /sessions/upload, authenticated with api_key_hash below.
    """

    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    # Only a hash is ever stored -- the plaintext key is returned exactly
    # once, at registration time, and cannot be recovered after that.
    api_key_hash: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    session_count: Mapped[int] = mapped_column(Integer, default=0)

    sessions: Mapped[list["SessionRecord"]] = relationship(back_populates="agent")
