"""Single-session Observer Profile findings.

This is a read layer only -- it interprets FlowFinding data that
app/ml/classifier.py and app/flow/extractor.py already produce. No new
inference, no new packet parsing, no payload access. See PHASE2.md.
"""

from dataclasses import dataclass

from app.core.schemas import FlowFindingSchema

# Classifier confidence above which we treat a traffic-type identification as
# a real finding worth reporting, not noise. Matches PHASE2.md's default.
TRAFFIC_ID_CONFIDENCE_THRESHOLD = 0.75

# Coefficient of variation (std/mean packet size) below which packet sizes
# look padded/normalized. This is a heuristic: ESP's TFC padding flag itself
# isn't observable on the wire, only its size-masking effect is.
LOW_VARIANCE_CV_THRESHOLD = 0.15


@dataclass
class ObserverFinding:
    category: str
    description: str
    confidence: float
    evidence: dict
    mitigation: str


def traffic_identifiability_findings(flows: list[FlowFindingSchema]) -> list[ObserverFinding]:
    findings = []
    for flow in flows:
        if flow.predicted_traffic_type == "unknown" or flow.confidence < TRAFFIC_ID_CONFIDENCE_THRESHOLD:
            continue

        findings.append(
            ObserverFinding(
                category="traffic_identifiability",
                description=(
                    f"Flow {flow.flow_key} was identified as {flow.predicted_traffic_type} traffic "
                    f"at {flow.confidence:.0%} confidence, from ESP packet size and timing alone -- "
                    "no decryption was performed or is possible."
                ),
                confidence=flow.confidence,
                evidence={
                    "flow_key": flow.flow_key,
                    "predicted_traffic_type": flow.predicted_traffic_type,
                    "packet_count": flow.packet_count,
                    "avg_packet_size": flow.avg_packet_size,
                    "duration_s": flow.duration_s,
                },
                mitigation=(
                    "Pad or shape traffic, or multiplex several traffic types over the same "
                    "tunnel, to reduce the classifier's ability to fingerprint this flow."
                ),
            )
        )
    return findings


def padding_exposure_findings(flows: list[FlowFindingSchema]) -> list[ObserverFinding]:
    findings = []
    for flow in flows:
        if flow.std_packet_size is None or flow.avg_packet_size <= 0:
            continue

        cv = flow.std_packet_size / flow.avg_packet_size
        confidently_classified = (
            flow.predicted_traffic_type != "unknown" and flow.confidence >= TRAFFIC_ID_CONFIDENCE_THRESHOLD
        )

        if cv < LOW_VARIANCE_CV_THRESHOLD:
            description = (
                f"Flow {flow.flow_key} shows low packet-size variance (coefficient of variation "
                f"{cv:.2f}), consistent with TFC padding or otherwise normalized packet sizes. "
                "This is a heuristic inference from size variance, not direct confirmation that "
                "TFC padding was negotiated -- that flag isn't observable on the wire."
            )
            confidence = 0.5
        elif confidently_classified:
            description = (
                f"Flow {flow.flow_key} shows high packet-size variance (coefficient of variation "
                f"{cv:.2f}) correlated with a confident {flow.predicted_traffic_type} "
                f"classification ({flow.confidence:.0%}), suggesting no TFC padding is in effect. "
                "Heuristic, not a direct observation of the padding negotiation."
            )
            confidence = 0.6
        else:
            description = (
                f"Flow {flow.flow_key} shows high packet-size variance (coefficient of variation "
                f"{cv:.2f}) with no confident traffic-type classification; padding status is "
                "inconclusive from this signal alone."
            )
            confidence = 0.3

        findings.append(
            ObserverFinding(
                category="padding_exposure",
                description=description,
                confidence=confidence,
                evidence={
                    "flow_key": flow.flow_key,
                    "coefficient_of_variation": round(cv, 4),
                    "std_packet_size": flow.std_packet_size,
                    "avg_packet_size": flow.avg_packet_size,
                },
                mitigation="Enable ESP TFC padding, if your IPsec stack supports it, to mask true payload sizes.",
            )
        )
    return findings


def build_session_observer_findings(flows: list[FlowFindingSchema]) -> list[ObserverFinding]:
    return traffic_identifiability_findings(flows) + padding_exposure_findings(flows)
