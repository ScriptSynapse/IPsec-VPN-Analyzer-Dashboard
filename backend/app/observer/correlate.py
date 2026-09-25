"""Multi-session Observer Profile findings.

Descriptive statistics over sessions that share a tunnel_id -- no new
inference beyond aggregating per-session data app/ike/parser.py,
app/flow/extractor.py and app/ml/classifier.py already produced. See
PHASE2.md.
"""

import statistics
from dataclasses import asdict, dataclass

from app.core.schemas import FlowFindingSchema, SessionSchema

MIN_SESSIONS_FOR_CORRELATION = 2

# Time-of-day clustering: sessions whose start-hour standard deviation is at
# or below this (in hours) are treated as showing a recurring pattern.
CONSISTENT_HOUR_STD_THRESHOLD_H = 2.0

# Byte-volume-per-traffic-type coefficient of variation below which we call
# the volume signature for that traffic type "consistent" across sessions.
VOLUME_CV_THRESHOLD = 0.25


@dataclass
class ObserverFinding:
    category: str
    description: str
    confidence: float
    evidence: dict


def insufficient_history(sessions_have: int) -> dict:
    return {
        "category": "insufficient_history",
        "sessions_needed": MIN_SESSIONS_FOR_CORRELATION,
        "sessions_have": sessions_have,
    }


def _temporal_pattern(sessions: list[SessionSchema]) -> ObserverFinding:
    hours = [s.created_at.hour + s.created_at.minute / 60 for s in sessions]
    mean_hour = statistics.mean(hours)
    std_hour = statistics.pstdev(hours) if len(hours) > 1 else 0.0
    consistent = std_hour <= CONSISTENT_HOUR_STD_THRESHOLD_H

    description = (
        f"Across {len(sessions)} sessions, tunnel activity clusters around "
        f"{mean_hour:.1f}:00 UTC (std dev {std_hour:.1f}h) -- "
        + (
            "a recurring time-of-day pattern is observable, which narrows down when "
            "this tunnel is likely to be active without decrypting anything."
            if consistent
            else "no consistent time-of-day pattern is observable from session starts alone."
        )
    )

    return ObserverFinding(
        category="temporal_pattern",
        description=description,
        confidence=0.7 if consistent else 0.3,
        evidence={"session_start_hours_utc": hours, "mean_hour": round(mean_hour, 2), "std_hour": round(std_hour, 2)},
    )


def _peer_stability(sessions: list[SessionSchema]) -> ObserverFinding:
    pairs = {(s.peer_src_ip, s.peer_dst_ip) for s in sessions if s.peer_src_ip and s.peer_dst_ip}

    if not pairs:
        return ObserverFinding(
            category="peer_stability",
            description="Peer IP addresses were not recorded for these sessions.",
            confidence=0.0,
            evidence={"distinct_peer_pairs": []},
        )

    stable = len(pairs) == 1
    description = (
        f"The peer IP pair stayed constant across all {len(sessions)} sessions, making this "
        "tunnel easy to re-identify as the same pair over time."
        if stable
        else f"The peer IP pair changed across sessions ({len(pairs)} distinct pairs observed)."
    )

    return ObserverFinding(
        category="peer_stability",
        description=description,
        confidence=0.9 if stable else 0.4,
        evidence={"distinct_peer_pairs": [list(pair) for pair in pairs]},
    )


def _volume_signature(sessions_flows: list[list[FlowFindingSchema]]) -> ObserverFinding | None:
    by_type: dict[str, list[float]] = {}
    for flows in sessions_flows:
        for flow in flows:
            if flow.predicted_traffic_type == "unknown":
                continue
            total_bytes = flow.avg_packet_size * flow.packet_count
            by_type.setdefault(flow.predicted_traffic_type, []).append(total_bytes)

    signatures = {}
    for traffic_type, volumes in by_type.items():
        if len(volumes) < 2:
            continue
        mean_v = statistics.mean(volumes)
        cv = (statistics.stdev(volumes) / mean_v) if mean_v > 0 else 0.0
        signatures[traffic_type] = {
            "mean_bytes": round(mean_v, 1),
            "coefficient_of_variation": round(cv, 4),
            "consistent": cv < VOLUME_CV_THRESHOLD,
        }

    if not signatures:
        return None

    consistent_types = [t for t, s in signatures.items() if s["consistent"]]
    description = (
        "Byte volume per classified traffic type is consistent across sessions for: "
        f"{', '.join(consistent_types) if consistent_types else 'none'}. A stable volume "
        "signature for a traffic type makes recurring sessions easier to correlate even "
        "without decrypting them."
    )

    return ObserverFinding(
        category="volume_signature",
        description=description,
        confidence=0.6 if consistent_types else 0.2,
        evidence={"by_traffic_type": signatures},
    )


def build_correlated_findings(
    sessions: list[SessionSchema], sessions_flows: list[list[FlowFindingSchema]]
) -> list[dict]:
    """Given all sessions sharing one tunnel_id (+ each session's flows, same
    order), returns temporal_pattern/peer_stability/volume_signature findings,
    or a single insufficient_history object if fewer than 2 sessions exist.
    """
    if len(sessions) < MIN_SESSIONS_FOR_CORRELATION:
        return [insufficient_history(len(sessions))]

    findings = [_temporal_pattern(sessions), _peer_stability(sessions)]
    volume_finding = _volume_signature(sessions_flows)
    if volume_finding:
        findings.append(volume_finding)

    return [asdict(f) for f in findings]
