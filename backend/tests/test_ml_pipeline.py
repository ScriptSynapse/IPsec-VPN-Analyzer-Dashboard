"""End-to-end sanity check for the ML pipeline against synthetic ESP traffic.

This does NOT validate real-world classifier accuracy -- that requires the
actual strongSwan testbed captures described in CLAUDE.md M1-M3. It only
proves dataset build -> train -> classify wiring works end-to-end so the API
layer has something real to call.
"""

from pathlib import Path

import pytest
from scapy.all import IP, wrpcap
from scapy.layers.ipsec import ESP

from app.ml import classifier, train
from app.ml.dataset import build_dataset


def _write_pcap(path: Path, packet_sizes: list[int], gap_s: float) -> None:
    packets = []
    for i, size in enumerate(packet_sizes):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ESP(spi=0xAAAA0000 + i % 3, seq=i + 1) / (b"x" * size)
        pkt.time = i * gap_s
        packets.append(pkt)
    wrpcap(str(path), packets)


@pytest.fixture
def synthetic_pcap_dir(tmp_path, monkeypatch):
    pcap_dir = tmp_path / "pcaps"
    dataset_dir = tmp_path / "datasets"
    artifacts_dir = tmp_path / "artifacts"
    pcap_dir.mkdir()

    monkeypatch.setattr("app.ml.dataset.settings.pcap_storage_dir", pcap_dir)
    monkeypatch.setattr("app.ml.dataset.settings.dataset_dir", dataset_dir)
    monkeypatch.setattr("app.ml.train.settings.ml_artifacts_dir", artifacts_dir)
    monkeypatch.setattr("app.ml.classifier.settings.ml_artifacts_dir", artifacts_dir)
    classifier.reset_cache()

    for i in range(6):
        _write_pcap(
            pcap_dir / f"tunnel_aesgcm256_dh19_pfson_ipv4_voip_2026090{i}T1400.pcap",
            packet_sizes=[80] * 40,
            gap_s=0.02,
        )
        _write_pcap(
            pcap_dir / f"tunnel_aesgcm256_dh19_pfson_ipv4_web_2026090{i}T1400.pcap",
            packet_sizes=[1400, 60, 1400, 1400, 60] * 8,
            gap_s=0.001,
        )

    yield pcap_dir
    classifier.reset_cache()


def test_dataset_labels_match_filename_convention(synthetic_pcap_dir):
    df = build_dataset(synthetic_pcap_dir)
    assert set(df["traffic_type"].unique()) == {"voip", "web"}
    assert len(df) > 0


def test_train_and_classify_round_trip(synthetic_pcap_dir):
    outcome = train.train()
    assert Path(outcome["artifact_path"]).exists()

    classifier.reset_cache()
    df = build_dataset(synthetic_pcap_dir)
    from app.flow.extractor import FlowFeatures

    row = df.iloc[0]
    features = FlowFeatures(flow_key=row["flow_key"], **{
        col: row[col] for col in df.columns if col not in ("flow_key", "traffic_type", "source_pcap")
    })
    label, confidence = classifier.predict(features)
    assert label in {"voip", "web"}
    assert 0.0 <= confidence <= 1.0


def test_classifier_falls_back_gracefully(tmp_path, monkeypatch):
    monkeypatch.setattr("app.ml.classifier.settings.ml_artifacts_dir", tmp_path / "empty")
    classifier.reset_cache()

    from app.flow.extractor import FlowFeatures

    dummy = FlowFeatures(
        flow_key="x", packet_count=1, duration_s=1, avg_packet_size=1, std_packet_size=0,
        min_packet_size=1, max_packet_size=1, avg_inter_arrival_ms=1, std_inter_arrival_ms=0,
        bytes_per_second=1, packets_per_second=1, burstiness=0, seq_gap_ratio=0,
    )
    label, confidence = classifier.predict(dummy)
    assert label == "unknown"
    assert confidence == 0.0
