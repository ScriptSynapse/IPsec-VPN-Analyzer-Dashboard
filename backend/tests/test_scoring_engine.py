from app.ike.schemas import IkeHandshake, SaProposal
from app.scoring.engine import compute_score
from app.scoring.policy import CryptoPolicy


def _strong_handshake() -> IkeHandshake:
    return IkeHandshake(
        ike_version="2",
        proposals=[
            SaProposal(
                proposal_num=1,
                encryption_alg="AES-GCM-16",
                auth_alg="HMAC-SHA2-256-128",
                dh_group="ECP-384",
                lifetime_seconds=3600,
            )
        ],
        pfs_enabled=True,
    )


def _weak_handshake() -> IkeHandshake:
    return IkeHandshake(
        ike_version="1",
        proposals=[
            SaProposal(
                proposal_num=1,
                encryption_alg="DES-CBC",
                auth_alg="HMAC-MD5",
                dh_group="MODP-768",
                lifetime_seconds=604800,
            )
        ],
        pfs_enabled=False,
    )


def test_strong_config_scores_high_and_compliant():
    result = compute_score(_strong_handshake(), flows=[], flow_confidences=[], policy=CryptoPolicy())
    assert result.crypto_strength > 90
    assert result.compliance == 100.0
    assert result.overall_score > 85
    assert result.threat_matrix == []


def test_weak_config_scores_low_and_flags_threats():
    result = compute_score(_weak_handshake(), flows=[], flow_confidences=[], policy=CryptoPolicy())
    assert result.crypto_strength < 20
    assert result.compliance < 50
    assert result.overall_score < 30
    assert len(result.threat_matrix) >= 3


def test_metadata_exposure_reflects_classifier_confidence():
    confident = compute_score(_strong_handshake(), flows=[object()], flow_confidences=[0.95], policy=CryptoPolicy())
    unsure = compute_score(_strong_handshake(), flows=[object()], flow_confidences=[0.3], policy=CryptoPolicy())
    assert confident.metadata_exposure < unsure.metadata_exposure


def test_aead_cipher_with_no_separate_auth_alg_is_not_penalized():
    """A real IKEv2 AES-GCM proposal has no separate Transform Type 3
    (Integrity Algorithm) at all -- confirmed against a real captured
    handshake via Wireshark's own dissector, which showed only ENCR/PRF/KE
    transforms present. auth_alg=None here is correct, RFC 8221-compliant
    behavior, not a missing integrity algorithm -- scoring it as 0 (as an
    earlier version of this engine did) penalized choosing a MODERN cipher.
    """
    handshake = IkeHandshake(
        ike_version="2",
        proposals=[
            SaProposal(
                proposal_num=1,
                encryption_alg="AES-GCM-16",
                auth_alg=None,
                dh_group="ECP-384",
                lifetime_seconds=3600,
            )
        ],
        pfs_enabled=True,
    )
    result = compute_score(handshake, flows=[], flow_confidences=[], policy=CryptoPolicy())
    assert result.crypto_strength > 90
    assert result.compliance == 100.0
    assert not any("Integrity algorithm" in t.finding for t in result.threat_matrix)


def test_metadata_exposure_never_affects_overall_score():
    """PHASE2.md core thesis: a tunnel can be A+ on crypto and F on metadata
    exposure at once -- overall_score must reflect technical posture only.
    """
    low_exposure = compute_score(_strong_handshake(), flows=[object()], flow_confidences=[0.05], policy=CryptoPolicy())
    high_exposure = compute_score(_strong_handshake(), flows=[object()], flow_confidences=[0.95], policy=CryptoPolicy())

    # Same handshake -> identical technical posture -> identical overall_score,
    # regardless of how confidently the traffic type was fingerprinted.
    assert low_exposure.overall_score == high_exposure.overall_score
    assert high_exposure.overall_score > 85  # A+ on crypto/compliance/key management
    assert high_exposure.metadata_exposure < 40  # F on metadata exposure
    assert low_exposure.metadata_exposure > high_exposure.metadata_exposure
