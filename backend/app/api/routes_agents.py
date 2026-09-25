"""Monitoring agents (app/agent/agent.py) and the global topology graph they feed.

An agent is a small process running on an authorized remote machine. It
captures traffic locally and uploads pcaps to POST /sessions/upload,
authenticated with the API key it was issued at registration (see
verify_agent_key below, used by routes_capture.upload_session).
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.agent.auth import generate_api_key, hash_api_key, verify_api_key
from app.core.db import get_db
from app.core.models import AgentRecord, SessionRecord
from app.core.schemas import (
    AgentRegisterRequest,
    AgentRegisterResponse,
    AgentSchema,
    TopologyEdge,
    TopologyNode,
    TopologyResponse,
)

router = APIRouter(tags=["agents"])

# An agent that hasn't checked in (heartbeat or upload) within this window
# is shown as offline -- generous enough to survive one missed capture
# cycle without flapping, per the agent's default 5-minute capture chunk.
AGENT_ONLINE_WINDOW_S = 600


def _agent_status(agent: AgentRecord) -> str:
    if agent.last_seen_at is None:
        return "pending"
    # SQLite doesn't preserve tzinfo on round-trip even for a
    # DateTime(timezone=True) column -- values read back are naive. They
    # were always written as UTC (see the heartbeat/upload handlers below),
    # so treat a naive value as UTC rather than letting the subtraction
    # below raise on aware-minus-naive.
    last_seen = agent.last_seen_at
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - last_seen
    return "online" if age <= timedelta(seconds=AGENT_ONLINE_WINDOW_S) else "offline"


def _to_schema(agent: AgentRecord) -> AgentSchema:
    return AgentSchema(
        id=agent.id,
        name=agent.name,
        created_at=agent.created_at,
        last_seen_at=agent.last_seen_at,
        session_count=agent.session_count,
        status=_agent_status(agent),
    )


def verify_agent_key(agent_id: str, api_key: str, db: DbSession) -> AgentRecord:
    """Used by routes_capture.upload_session when an upload claims to be
    from an agent. Raises 401 on any mismatch -- never leaks which part
    (unknown id vs wrong key) failed, same principle as a login form.
    """
    agent = db.get(AgentRecord, agent_id)
    if agent is None or not verify_api_key(api_key, agent.api_key_hash):
        raise HTTPException(status_code=401, detail="invalid agent id or api key")
    return agent


@router.post("/agents", response_model=AgentRegisterResponse, status_code=201)
def register_agent(body: AgentRegisterRequest, db: DbSession = Depends(get_db)) -> AgentRegisterResponse:
    api_key = generate_api_key()
    record = AgentRecord(name=body.name, api_key_hash=hash_api_key(api_key))
    db.add(record)
    db.commit()
    db.refresh(record)
    return AgentRegisterResponse(id=record.id, name=record.name, api_key=api_key)


@router.get("/agents", response_model=list[AgentSchema])
def list_agents(db: DbSession = Depends(get_db)) -> list[AgentSchema]:
    records = db.execute(select(AgentRecord).order_by(AgentRecord.created_at.desc())).scalars().all()
    return [_to_schema(a) for a in records]


@router.post("/agents/{agent_id}/heartbeat", response_model=AgentSchema)
def agent_heartbeat(
    agent_id: str,
    x_agent_key: str = Header(...),
    db: DbSession = Depends(get_db),
) -> AgentSchema:
    agent = verify_agent_key(agent_id, x_agent_key, db)
    agent.last_seen_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(agent)
    return _to_schema(agent)


@router.get("/topology", response_model=TopologyResponse)
def get_topology(db: DbSession = Depends(get_db)) -> TopologyResponse:
    """Global topology across every agent and every tunnel: which agent
    submitted sessions for which tunnel, and which peer IPs were observed
    on that tunnel. Built entirely from data already stored per-session --
    no new capture or inference happens here, just aggregation.
    """
    sessions = db.execute(select(SessionRecord)).scalars().all()
    agents_by_id = {a.id: a for a in db.execute(select(AgentRecord)).scalars().all()}

    nodes: dict[str, TopologyNode] = {}
    edges: set[tuple[str, str]] = set()

    def add_node(node_id: str, node_type: str, label: str) -> None:
        nodes.setdefault(node_id, TopologyNode(id=node_id, type=node_type, label=label))

    for s in sessions:
        agent_node_id = None
        if s.agent_id and s.agent_id in agents_by_id:
            agent = agents_by_id[s.agent_id]
            agent_node_id = f"agent:{agent.id}"
            add_node(agent_node_id, "agent", agent.name)

        tunnel_node_id = None
        if s.tunnel_id:
            tunnel_node_id = f"tunnel:{s.tunnel_id}"
            add_node(tunnel_node_id, "tunnel", s.peer_label or s.tunnel_id)

        if agent_node_id and tunnel_node_id:
            edges.add((agent_node_id, tunnel_node_id))

        for peer_ip in (s.peer_src_ip, s.peer_dst_ip):
            if not peer_ip:
                continue
            peer_node_id = f"peer:{peer_ip}"
            add_node(peer_node_id, "peer", peer_ip)
            if tunnel_node_id:
                edges.add((tunnel_node_id, peer_node_id))
            elif agent_node_id:
                # No tunnel_id set on this session -- still show the agent
                # directly observed this peer, rather than dropping it.
                edges.add((agent_node_id, peer_node_id))

    return TopologyResponse(
        nodes=list(nodes.values()),
        edges=[TopologyEdge(source=s, target=t) for s, t in edges],
    )
