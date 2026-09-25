"""Agent registration/auth/heartbeat and the global topology graph they feed."""

import io

import pytest
from fastapi.testclient import TestClient

from app.main import app

VALID_PCAP_HEADER = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20  # classic pcap magic + stub global header


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.config.settings.database_url", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setattr("app.core.config.settings.pcap_storage_dir", tmp_path / "pcaps")

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import app.core.db as db_module

    test_engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    monkeypatch.setattr(db_module, "engine", test_engine)
    monkeypatch.setattr(db_module, "SessionLocal", sessionmaker(bind=test_engine))

    with TestClient(app) as c:
        yield c


def _register(client: TestClient, name: str = "member-pc-1") -> dict:
    resp = client.post("/agents", json={"name": name})
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_register_agent_returns_api_key_once(client: TestClient):
    agent = _register(client)
    assert agent["id"]
    assert agent["name"] == "member-pc-1"
    assert len(agent["api_key"]) > 20

    listed = client.get("/agents").json()
    assert len(listed) == 1
    assert listed[0]["id"] == agent["id"]
    assert listed[0]["status"] == "pending"  # never checked in yet
    assert "api_key" not in listed[0]  # the key is never returned again


def test_heartbeat_requires_correct_key(client: TestClient):
    agent = _register(client)

    ok = client.post(f"/agents/{agent['id']}/heartbeat", headers={"X-Agent-Key": agent["api_key"]})
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "online"

    bad = client.post(f"/agents/{agent['id']}/heartbeat", headers={"X-Agent-Key": "wrong-key"})
    assert bad.status_code == 401


def test_upload_without_agent_headers_still_works(client: TestClient):
    resp = client.post(
        "/sessions/upload",
        files={"file": ("manual.pcap", io.BytesIO(VALID_PCAP_HEADER), "application/octet-stream")},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["agent_id"] is None


def test_agent_upload_requires_valid_key_and_updates_agent(client: TestClient):
    agent = _register(client)

    rejected = client.post(
        "/sessions/upload",
        files={"file": ("agent.pcap", io.BytesIO(VALID_PCAP_HEADER), "application/octet-stream")},
        headers={"X-Agent-Id": agent["id"], "X-Agent-Key": "wrong-key"},
    )
    assert rejected.status_code == 401

    accepted = client.post(
        "/sessions/upload",
        data={"tunnel_id": "office-tunnel"},
        files={"file": ("agent.pcap", io.BytesIO(VALID_PCAP_HEADER), "application/octet-stream")},
        headers={"X-Agent-Id": agent["id"], "X-Agent-Key": agent["api_key"]},
    )
    assert accepted.status_code == 201, accepted.text
    body = accepted.json()
    assert body["agent_id"] == agent["id"]
    assert body["tunnel_id"] == "office-tunnel"

    listed = client.get("/agents").json()
    assert listed[0]["session_count"] == 1
    assert listed[0]["status"] == "online"


def test_topology_reflects_agent_tunnel_and_peers(client: TestClient, monkeypatch):
    agent = _register(client)
    client.post(
        "/sessions/upload",
        data={"tunnel_id": "office-tunnel", "peer_label": "HQ<->Branch"},
        files={"file": ("agent.pcap", io.BytesIO(VALID_PCAP_HEADER), "application/octet-stream")},
        headers={"X-Agent-Id": agent["id"], "X-Agent-Key": agent["api_key"]},
    )

    # peer_src_ip/peer_dst_ip are normally populated by /analyze reading the
    # capture; set directly here since this test only exercises /topology.
    import app.core.db as db_module
    from app.core.models import SessionRecord

    with db_module.SessionLocal() as db:
        record = db.query(SessionRecord).one()
        record.peer_src_ip = "10.0.0.1"
        record.peer_dst_ip = "10.0.0.2"
        db.commit()

    topo = client.get("/topology").json()
    node_ids = {n["id"] for n in topo["nodes"]}
    assert f"agent:{agent['id']}" in node_ids
    assert "tunnel:office-tunnel" in node_ids
    assert "peer:10.0.0.1" in node_ids
    assert "peer:10.0.0.2" in node_ids

    edges = {(e["source"], e["target"]) for e in topo["edges"]}
    assert (f"agent:{agent['id']}", "tunnel:office-tunnel") in edges
    assert ("tunnel:office-tunnel", "peer:10.0.0.1") in edges
    assert ("tunnel:office-tunnel", "peer:10.0.0.2") in edges
