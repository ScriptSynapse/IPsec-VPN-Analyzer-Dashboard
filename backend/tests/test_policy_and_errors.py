from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

FIXTURES_DIR = Path(__file__).parent / "fixtures"


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


VALID_POLICY_YAML = """
min_encryption_score: 80
require_pfs: true
banned_encryption_algs: ["DES-CBC", "3DES-CBC"]
"""


def test_upload_and_fetch_policy(client):
    resp = client.post("/policy", files={"file": ("strict.yaml", VALID_POLICY_YAML, "application/x-yaml")})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["definition"]["min_encryption_score"] == 80

    fetch_resp = client.get(f"/policy/{body['id']}")
    assert fetch_resp.status_code == 200
    assert fetch_resp.json()["definition"]["banned_encryption_algs"] == ["DES-CBC", "3DES-CBC"]


def test_list_policies(client):
    assert client.get("/policy").json() == []

    client.post("/policy", files={"file": ("a.yaml", VALID_POLICY_YAML, "application/x-yaml")})
    client.post("/policy", files={"file": ("b.yaml", VALID_POLICY_YAML, "application/x-yaml")})

    listed = client.get("/policy").json()
    assert len(listed) == 2
    assert {p["name"] for p in listed} == {"a.yaml", "b.yaml"}


def test_upload_invalid_policy_yaml_rejected(client):
    resp = client.post("/policy", files={"file": ("bad.yaml", "not: valid: yaml: at: all: :", "application/x-yaml")})
    assert resp.status_code == 400


def test_get_missing_policy_404(client):
    assert client.get("/policy/does-not-exist").status_code == 404


def test_analyze_missing_session_404(client):
    assert client.post("/sessions/does-not-exist/analyze").status_code == 404
    assert client.get("/sessions/does-not-exist/ike").status_code == 404
    assert client.get("/sessions/does-not-exist/flows").status_code == 404


def test_analyze_non_ike_pcap_returns_422(client):
    from scapy.all import IP, UDP, wrpcap

    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_file = Path(tmpdir) / "no_ike.pcap"
        wrpcap(str(pcap_file), [IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=1234, dport=80)])

        with open(pcap_file, "rb") as f:
            upload_resp = client.post("/sessions/upload", files={"file": ("no_ike.pcap", f, "application/octet-stream")})
        session_id = upload_resp.json()["id"]

        analyze_resp = client.post(f"/sessions/{session_id}/analyze")
        assert analyze_resp.status_code == 422
