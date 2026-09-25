from datetime import datetime, timedelta, timezone

from app.core.schemas import FlowFindingSchema, SessionSchema
from app.observer.correlate import build_correlated_findings


def _session(session_id: str, created_at: datetime, src_ip: str, dst_ip: str) -> SessionSchema:
    return SessionSchema(
        id=session_id,
        filename=f"{session_id}.pcap",
        created_at=created_at,
        tunnel_id="tunnel-a",
        peer_src_ip=src_ip,
        peer_dst_ip=dst_ip,
    )


def _flow(traffic_type: str, avg_size: float, count: int) -> FlowFindingSchema:
    return FlowFindingSchema(
        flow_key="10.0.0.1->10.0.0.2:spi=0x1",
        predicted_traffic_type=traffic_type,
        confidence=0.9,
        packet_count=count,
        avg_packet_size=avg_size,
        std_packet_size=5.0,
        duration_s=10.0,
    )


def test_single_session_returns_insufficient_history():
    sessions = [_session("s1", datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc), "1.1.1.1", "2.2.2.2")]
    result = build_correlated_findings(sessions, [[]])

    assert len(result) == 1
    assert result[0] == {"category": "insufficient_history", "sessions_needed": 2, "sessions_have": 1}


def test_three_sessions_consistent_time_peer_and_volume_produce_recurrence_findings():
    base_day = datetime(2026, 1, 1, tzinfo=timezone.utc)
    sessions = [
        _session("s1", base_day + timedelta(hours=9, minutes=0), "10.0.0.1", "10.0.0.2"),
        _session("s2", base_day + timedelta(days=1, hours=9, minutes=10), "10.0.0.1", "10.0.0.2"),
        _session("s3", base_day + timedelta(days=2, hours=8, minutes=50), "10.0.0.1", "10.0.0.2"),
    ]
    sessions_flows = [
        [_flow("voip", 160.0, 100)],
        [_flow("voip", 162.0, 99)],
        [_flow("voip", 158.0, 101)],
    ]

    findings = build_correlated_findings(sessions, sessions_flows)
    categories = {f["category"] for f in findings}
    assert categories == {"temporal_pattern", "peer_stability", "volume_signature"}

    temporal = next(f for f in findings if f["category"] == "temporal_pattern")
    assert temporal["confidence"] == 0.7  # consistent -- std well under the 2h threshold

    peer = next(f for f in findings if f["category"] == "peer_stability")
    assert peer["confidence"] == 0.9  # single peer pair across all sessions
    assert peer["evidence"]["distinct_peer_pairs"] == [["10.0.0.1", "10.0.0.2"]]

    volume = next(f for f in findings if f["category"] == "volume_signature")
    assert volume["evidence"]["by_traffic_type"]["voip"]["consistent"] is True


def test_changing_peer_and_erratic_timing_produce_low_confidence_findings():
    sessions = [
        _session("s1", datetime(2026, 1, 1, 2, 0, tzinfo=timezone.utc), "10.0.0.1", "10.0.0.2"),
        _session("s2", datetime(2026, 1, 2, 14, 0, tzinfo=timezone.utc), "10.0.0.5", "10.0.0.9"),
    ]
    findings = build_correlated_findings(sessions, [[], []])

    temporal = next(f for f in findings if f["category"] == "temporal_pattern")
    assert temporal["confidence"] == 0.3

    peer = next(f for f in findings if f["category"] == "peer_stability")
    assert peer["confidence"] == 0.4
    assert len(peer["evidence"]["distinct_peer_pairs"]) == 2
