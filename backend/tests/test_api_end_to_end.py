"""End-to-end walk of the full API: upload -> analyze -> ike -> flows -> score -> report."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scapy.all import IP, UDP, Raw, wrpcap
from scapy.layers.ipsec import ESP

from app.main import app

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.config.settings.database_url", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setattr("app.core.config.settings.pcap_storage_dir", tmp_path / "pcaps")

    # db.py builds its engine/session at import time from settings, so patch those directly too.
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import app.core.db as db_module

    test_engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    monkeypatch.setattr(db_module, "engine", test_engine)
    monkeypatch.setattr(db_module, "SessionLocal", sessionmaker(bind=test_engine))

    with TestClient(app) as c:
        yield c


def _combined_pcap(tmp_path: Path) -> Path:
    """A capture with a real ISAKMP handshake packet plus a run of ESP flow packets."""
    ike_bytes = (FIXTURES_DIR / "ikev2_sa_init.pcap")
    from scapy.all import rdpcap

    ike_packets = list(rdpcap(str(ike_bytes)))

    esp_packets = []
    for i in range(20):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ESP(spi=0xC0FFEE00, seq=i + 1) / Raw(load=b"x" * 200)
        pkt.time = i * 0.02
        esp_packets.append(pkt)

    out_path = tmp_path / "combined.pcap"
    wrpcap(str(out_path), ike_packets + esp_packets)
    return out_path


def test_full_pipeline(client, tmp_path):
    pcap_path = _combined_pcap(tmp_path)

    with open(pcap_path, "rb") as f:
        upload_resp = client.post(
            "/sessions/upload",
            files={"file": ("tunnel_aesgcm256_dh19_pfson_ipv4_web_20260901T1400.pcap", f, "application/octet-stream")},
        )
    assert upload_resp.status_code == 201, upload_resp.text
    session_id = upload_resp.json()["id"]

    assert client.get("/sessions").status_code == 200
    assert client.get(f"/sessions/{session_id}").status_code == 200

    analyze_resp = client.post(f"/sessions/{session_id}/analyze")
    assert analyze_resp.status_code == 202, analyze_resp.text
    assert analyze_resp.json()["flow_count"] >= 1

    ike_resp = client.get(f"/sessions/{session_id}/ike")
    assert ike_resp.status_code == 200
    ike_body = ike_resp.json()
    assert ike_body["encryption_alg"] == "AES-GCM-16"
    assert ike_body["dh_group"] == "ECP-384"

    flows_resp = client.get(f"/sessions/{session_id}/flows")
    assert flows_resp.status_code == 200
    assert len(flows_resp.json()) >= 1

    score_resp = client.get(f"/sessions/{session_id}/score")
    assert score_resp.status_code == 200
    score_body = score_resp.json()
    assert 0 <= score_body["overall_score"] <= 100
    assert "threat_matrix" in score_body

    tech_report = client.get(f"/sessions/{session_id}/report", params={"type": "technical"})
    assert tech_report.status_code == 200
    assert tech_report.json()["session"]["id"] == session_id

    tech_md = client.get(f"/sessions/{session_id}/report", params={"type": "technical", "format": "markdown"})
    assert tech_md.status_code == 200
    assert "Technical Report" in tech_md.text

    exec_report = client.get(f"/sessions/{session_id}/report", params={"type": "executive"})
    assert exec_report.status_code == 200
    assert "risk_band" in exec_report.json()


def test_upload_rejects_non_pcap(client):
    resp = client.post(
        "/sessions/upload",
        files={"file": ("not_a_pcap.txt", b"hello world", "text/plain")},
    )
    assert resp.status_code == 400


def test_score_before_analysis_is_404(client, tmp_path):
    pcap_path = _combined_pcap(tmp_path)
    with open(pcap_path, "rb") as f:
        upload_resp = client.post("/sessions/upload", files={"file": ("test.pcap", f, "application/octet-stream")})
    session_id = upload_resp.json()["id"]

    assert client.get(f"/sessions/{session_id}/score").status_code == 404
    assert client.get(f"/sessions/{session_id}/report").status_code == 404
