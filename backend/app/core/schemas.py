from datetime import datetime

from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    status: str
    app_name: str
    database_connected: bool


class SaProposalSchema(BaseModel):
    encryption_alg: str | None = None
    key_length: int | None = None
    auth_alg: str | None = None
    dh_group: str | None = None
    lifetime_seconds: int | None = None


class SessionSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    filename: str
    mode: str | None = None
    ip_version: str | None = None
    ike_version: str | None = None
    created_at: datetime
    tunnel_id: str | None = None
    peer_label: str | None = None
    peer_src_ip: str | None = None
    peer_dst_ip: str | None = None
    agent_id: str | None = None


class SessionUpdate(BaseModel):
    tunnel_id: str | None = None
    peer_label: str | None = None


class IkeFindingSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: str
    ike_version: str | None = None
    exchange_type: str | None = None
    encryption_alg: str | None = None
    auth_alg: str | None = None
    dh_group: str | None = None
    pfs_enabled: bool | None = None
    sa_lifetime: int | None = None
    implementation_guess: str | None = None
    proposals: list[SaProposalSchema] = []
    vendor_ids: list[str] = []


class FlowFindingSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    flow_key: str
    predicted_traffic_type: str
    confidence: float
    packet_count: int
    avg_packet_size: float
    std_packet_size: float | None = None
    duration_s: float
    feature_importances: dict[str, float] | None = None


class ThreatMatrixItem(BaseModel):
    finding: str
    likelihood: str
    impact: str
    recommendation: str


class ScoreResultSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: str
    crypto_strength: float
    compliance: float
    key_management: float
    metadata_exposure: float
    overall_score: float
    threat_matrix: list[ThreatMatrixItem]
    policy_id: str | None = None


class PolicySchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    created_at: datetime
    definition: dict


class AgentRegisterRequest(BaseModel):
    name: str


class AgentRegisterResponse(BaseModel):
    """Returned exactly once, at registration -- api_key is never shown again."""

    id: str
    name: str
    api_key: str


class AgentSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    created_at: datetime
    last_seen_at: datetime | None = None
    session_count: int
    # Computed at read time, not stored: "online" if a heartbeat or upload
    # was seen inside AGENT_ONLINE_WINDOW_S (see routes_agents.py), else
    # "offline". A brand-new agent that has never checked in is "pending".
    status: str


class TopologyNode(BaseModel):
    id: str
    type: str  # "agent" | "tunnel" | "peer"
    label: str


class TopologyEdge(BaseModel):
    source: str
    target: str


class TopologyResponse(BaseModel):
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]
