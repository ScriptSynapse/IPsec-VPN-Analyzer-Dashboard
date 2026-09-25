from app.core.schemas import FlowFindingSchema
from app.observer.profile import (
    build_session_observer_findings,
    padding_exposure_findings,
    traffic_identifiability_findings,
)


def _flow(**overrides) -> FlowFindingSchema:
    defaults = dict(
        flow_key="10.0.0.1->10.0.0.2:spi=0xdeadbeef",
        predicted_traffic_type="voip",
        confidence=0.9,
        packet_count=100,
        avg_packet_size=160.0,
        std_packet_size=5.0,
        duration_s=2.0,
    )
    defaults.update(overrides)
    return FlowFindingSchema(**defaults)


def test_confident_flow_produces_traffic_identifiability_finding():
    findings = traffic_identifiability_findings([_flow(confidence=0.9)])
    assert len(findings) == 1
    assert findings[0].category == "traffic_identifiability"
    assert "voip" in findings[0].description
    assert findings[0].confidence == 0.9


def test_low_confidence_flow_produces_no_traffic_identifiability_finding():
    findings = traffic_identifiability_findings([_flow(confidence=0.4)])
    assert findings == []


def test_unknown_traffic_type_produces_no_traffic_identifiability_finding():
    findings = traffic_identifiability_findings([_flow(predicted_traffic_type="unknown", confidence=0.99)])
    assert findings == []


def test_low_variance_flow_reads_as_padding_like():
    flow = _flow(avg_packet_size=1400.0, std_packet_size=10.0)  # cv ~= 0.007
    findings = padding_exposure_findings([flow])
    assert len(findings) == 1
    assert "padding" in findings[0].description.lower()
    assert findings[0].category == "padding_exposure"


def test_high_variance_with_confident_classification_reads_as_no_padding():
    flow = _flow(avg_packet_size=200.0, std_packet_size=150.0, confidence=0.9, predicted_traffic_type="voip")
    findings = padding_exposure_findings([flow])
    assert len(findings) == 1
    assert "no tfc padding" in findings[0].description.lower()


def test_high_variance_without_classification_is_inconclusive():
    flow = _flow(avg_packet_size=200.0, std_packet_size=150.0, confidence=0.2, predicted_traffic_type="unknown")
    findings = padding_exposure_findings([flow])
    assert len(findings) == 1
    assert "inconclusive" in findings[0].description.lower()


def test_build_session_observer_findings_combines_both_categories():
    findings = build_session_observer_findings([_flow(confidence=0.9, std_packet_size=150.0)])
    categories = {f.category for f in findings}
    assert categories == {"traffic_identifiability", "padding_exposure"}
