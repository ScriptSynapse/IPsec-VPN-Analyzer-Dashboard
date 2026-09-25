"""API-level Observer Profile tests, including the PHASE2.md core-thesis
regression: a session that is strong on crypto (high overall_score) but bad
on metadata exposure (a confidently-classified flow), proving those two
numbers are genuinely independent.
"""

import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scapy.all import IP, UDP, Raw, wrpcap
from scapy.layers.ipsec import ESP

from app.main import app
from app.ml import classifier, train
from app.ml.dataset import build_dataset


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


# ---------------------------------------------------------------------------
# Hand-built ISAKMP packets: a strong IKE_SA_INIT proposal (AES-CBC-256 /
# HMAC-SHA2-384-192 / ECP-384) plus a CREATE_CHILD_SA-style ESP proposal that
# negotiates its own DH group -- i.e. PFS -- so the scoring engine sees a
# fully-compliant, high-scoring handshake. Same wire-format approach as
# tests/fixtures/generate_fixtures.py.
# ---------------------------------------------------------------------------

def _tv_attr(attr_type: int, value: int) -> bytes:
    return struct.pack(">HH", 0x8000 | attr_type, value)


def _transform(last: int, ttype: int, tid: int, attrs: bytes = b"") -> bytes:
    return struct.pack(">BBHBBH", last, 0, 8 + len(attrs), ttype, 0, tid) + attrs


def _isakmp_sa_packet(*, spi: int, exch_type: int, proto_id: int, transform_specs: list[tuple[int, int, bytes]]) -> bytes:
    transforms = b"".join(
        _transform(0 if i == len(transform_specs) - 1 else 3, ttype, tid, attrs)
        for i, (ttype, tid, attrs) in enumerate(transform_specs)
    )
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(transforms), 1, proto_id, 0, len(transform_specs)) + transforms
    sa_payload = struct.pack(">BBH", 0, 0, 4 + len(proposal)) + proposal
    total_len = 28 + len(sa_payload)
    header = struct.pack(">QQBBBBII", spi, 0, 33, 0x20, exch_type, 0x08, 0, total_len)
    return header + sa_payload


def _strong_ike_packets() -> list:
    key_len = _tv_attr(14, 256)
    phase1 = _isakmp_sa_packet(
        spi=0x3333333333333333,
        exch_type=34,  # IKE_SA_INIT
        proto_id=1,  # IKE
        transform_specs=[
            (1, 12, key_len),  # ENCR AES-CBC, 256-bit (IANA IKEv2 transform ID 12)
            (3, 13, b""),  # INTEG HMAC-SHA2-384-192
            (4, 20, b""),  # D-H ECP-384
        ],
    )
    child_sa = _isakmp_sa_packet(
        spi=0x3333333333333333,
        exch_type=36,  # CREATE_CHILD_SA
        proto_id=3,  # ESP
        transform_specs=[
            (1, 12, key_len),
            (4, 20, b""),  # D-H present in the Child SA proposal -> PFS
        ],
    )
    return [
        IP(src="10.1.0.1", dst="10.1.0.2") / UDP(sport=500, dport=500) / Raw(load=phase1),
        IP(src="10.1.0.1", dst="10.1.0.2") / UDP(sport=500, dport=500) / Raw(load=child_sa),
    ]


def _voip_esp_packets(spi: int = 0xC0FFEE00) -> list:
    packets = []
    for i in range(40):
        pkt = IP(src="10.1.0.1", dst="10.1.0.2") / ESP(spi=spi, seq=i + 1) / Raw(load=b"x" * 80)
        pkt.time = i * 0.02  # steady 20ms cadence, like a G.711 VoIP call
        packets.append(pkt)
    return packets


def _web_esp_packets(spi: int = 0xFEEDFACE) -> list:
    packets = []
    sizes = [1400, 60, 1400, 1400, 60] * 8
    for i, size in enumerate(sizes):
        pkt = IP(src="10.1.0.1", dst="10.1.0.2") / ESP(spi=spi, seq=i + 1) / Raw(load=b"x" * size)
        pkt.time = i * 0.001
        packets.append(pkt)
    return packets


def _train_synthetic_classifier(tmp_path: Path, monkeypatch) -> None:
    """Mirrors tests/test_ml_pipeline.py's approach: train a tiny RandomForest
    on synthetic voip/web pcaps so the demo capture below gets a confident,
    real classification instead of the "unknown" fallback.
    """
    pcap_dir = tmp_path / "training_pcaps"
    pcap_dir.mkdir()
    dataset_dir = tmp_path / "datasets"
    artifacts_dir = tmp_path / "artifacts"

    monkeypatch.setattr("app.ml.dataset.settings.pcap_storage_dir", pcap_dir)
    monkeypatch.setattr("app.ml.dataset.settings.dataset_dir", dataset_dir)
    monkeypatch.setattr("app.ml.train.settings.ml_artifacts_dir", artifacts_dir)
    monkeypatch.setattr("app.ml.classifier.settings.ml_artifacts_dir", artifacts_dir)
    classifier.reset_cache()

    for i in range(6):
        wrpcap(str(pcap_dir / f"tunnel_aes256_dh14_pfson_ipv4_voip_2026090{i}T1400.pcap"), _voip_esp_packets())
        wrpcap(str(pcap_dir / f"tunnel_aes256_dh14_pfson_ipv4_web_2026090{i}T1400.pcap"), _web_esp_packets())

    train.train()
    classifier.reset_cache()


def _combined_demo_pcap(tmp_path: Path) -> Path:
    out_path = tmp_path / "strong_crypto_voip.pcap"
    wrpcap(str(out_path), _strong_ike_packets() + _voip_esp_packets())
    return out_path


def test_core_thesis_strong_crypto_high_metadata_exposure(client, tmp_path, monkeypatch):
    _train_synthetic_classifier(tmp_path, monkeypatch)
    pcap_path = _combined_demo_pcap(tmp_path)

    with open(pcap_path, "rb") as f:
        upload_resp = client.post("/sessions/upload", files={"file": ("demo.pcap", f, "application/octet-stream")})
    assert upload_resp.status_code == 201, upload_resp.text
    session_id = upload_resp.json()["id"]

    analyze_resp = client.post(f"/sessions/{session_id}/analyze")
    assert analyze_resp.status_code == 202, analyze_resp.text

    ike_body = client.get(f"/sessions/{session_id}/ike").json()
    assert ike_body["pfs_enabled"] is True
    assert ike_body["encryption_alg"] == "AES-CBC"
    assert ike_body["dh_group"] == "ECP-384"

    score_body = client.get(f"/sessions/{session_id}/score").json()
    # A+ on technical posture ...
    assert score_body["overall_score"] > 85
    assert score_body["compliance"] == 100.0
    # ... and F on metadata exposure, from the same session.
    assert score_body["metadata_exposure"] < 40

    profile_body = client.get(f"/sessions/{session_id}/observer-profile").json()
    traffic_findings = [f for f in profile_body["findings"] if f["category"] == "traffic_identifiability"]
    assert len(traffic_findings) == 1
    assert traffic_findings[0]["evidence"]["predicted_traffic_type"] == "voip"
    assert traffic_findings[0]["confidence"] >= 0.75

    # No tunnel_id set -> multi-session correlation reports insufficient history explicitly.
    history = [f for f in profile_body["findings"] if f["category"] == "insufficient_history"]
    assert history == [{"category": "insufficient_history", "sessions_needed": 2, "sessions_have": 1}]

    md_resp = client.get(f"/sessions/{session_id}/observer-profile", params={"format": "markdown"})
    assert md_resp.status_code == 200
    assert "Observer Profile" in md_resp.text
    assert "voip" in md_resp.text.lower()


def test_patch_session_and_tunnel_aggregate_profile(client, tmp_path, monkeypatch):
    _train_synthetic_classifier(tmp_path, monkeypatch)

    session_ids = []
    for _ in range(3):
        pcap_path = _combined_demo_pcap(tmp_path)
        with open(pcap_path, "rb") as f:
            upload_resp = client.post("/sessions/upload", files={"file": ("demo.pcap", f, "application/octet-stream")})
        session_id = upload_resp.json()["id"]
        assert client.post(f"/sessions/{session_id}/analyze").status_code == 202

        patch_resp = client.patch(f"/sessions/{session_id}", json={"tunnel_id": "office-vpn", "peer_label": "HQ<->Branch"})
        assert patch_resp.status_code == 200
        assert patch_resp.json()["tunnel_id"] == "office-vpn"
        session_ids.append(session_id)

    tunnel_profile = client.get("/tunnels/office-vpn/observer-profile").json()
    assert tunnel_profile["session_count"] == 3

    categories = {f["category"] for f in tunnel_profile["findings"]}
    assert "temporal_pattern" in categories
    assert "peer_stability" in categories
    assert "traffic_identifiability" in categories

    peer_finding = next(f for f in tunnel_profile["findings"] if f["category"] == "peer_stability")
    assert peer_finding["confidence"] == 0.9  # all three sessions share the same crafted peer IPs

    # Single-session endpoint should now surface real correlation instead of insufficient_history.
    single_profile = client.get(f"/sessions/{session_ids[0]}/observer-profile").json()
    single_categories = {f["category"] for f in single_profile["findings"]}
    assert "insufficient_history" not in single_categories
    assert "temporal_pattern" in single_categories


def test_unknown_tunnel_id_is_404(client):
    resp = client.get("/tunnels/does-not-exist/observer-profile")
    assert resp.status_code == 404
