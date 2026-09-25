"""Combines IKE findings + flow findings + policy into category scores and a threat matrix."""

from dataclasses import dataclass

from app.flow.extractor import FlowFeatures
from app.ike.schemas import IkeHandshake
from app.scoring.policy import CryptoPolicy
from app.scoring.rules import (
    CRYPTO_STRENGTH_WEIGHTS,
    PFS_BONUS,
    WEAK_DH_GROUPS,
    score_auth,
    score_dh,
    score_encryption,
    score_lifetime,
)


@dataclass
class ThreatMatrixEntry:
    finding: str
    likelihood: str
    impact: str
    recommendation: str


@dataclass
class ScoreResult:
    crypto_strength: float
    compliance: float
    key_management: float
    metadata_exposure: float
    overall_score: float
    threat_matrix: list[ThreatMatrixEntry]


def _crypto_strength(enc_score: int, auth_score: int, dh_score: int) -> float:
    w = CRYPTO_STRENGTH_WEIGHTS
    return enc_score * w["encryption"] + auth_score * w["auth"] + dh_score * w["dh"]


def _compliance(ike: IkeHandshake, policy: CryptoPolicy, threats: list[ThreatMatrixEntry]) -> float:
    proposal = ike.chosen_proposal
    checks_total = 0
    checks_passed = 0

    def check(passed: bool, finding: str, likelihood: str, impact: str, recommendation: str) -> None:
        nonlocal checks_total, checks_passed
        checks_total += 1
        if passed:
            checks_passed += 1
        else:
            threats.append(ThreatMatrixEntry(finding, likelihood, impact, recommendation))

    if proposal is None:
        return 0.0

    check(
        proposal.encryption_alg not in policy.banned_encryption_algs
        and score_encryption(proposal.encryption_alg) >= policy.min_encryption_score,
        f"Encryption algorithm {proposal.encryption_alg} does not meet policy minimum",
        "High",
        "High",
        "Renegotiate the IPsec SA using an AEAD cipher such as AES-GCM-256.",
    )
    check(
        proposal.auth_alg not in policy.banned_auth_algs
        and score_auth(proposal.auth_alg, proposal.encryption_alg) >= policy.min_auth_score,
        f"Integrity algorithm {proposal.auth_alg} does not meet policy minimum",
        "Medium",
        "High",
        "Switch to HMAC-SHA2-256 or stronger.",
    )
    check(
        score_dh(proposal.dh_group) >= policy.min_dh_score,
        f"DH group {proposal.dh_group} provides insufficient key-exchange strength",
        "Medium" if proposal.dh_group in WEAK_DH_GROUPS else "Low",
        "High",
        "Move to DH group 14 (MODP-2048) or an elliptic-curve group (19/20/21).",
    )
    check(
        (not policy.require_pfs) or bool(ike.pfs_enabled),
        "Perfect Forward Secrecy is not negotiated in Phase 2",
        "Medium",
        "High",
        "Enable PFS so a compromised long-term key cannot decrypt past sessions.",
    )
    check(
        proposal.lifetime_seconds is None or proposal.lifetime_seconds <= policy.max_sa_lifetime_s,
        f"SA lifetime {proposal.lifetime_seconds}s exceeds policy maximum of {policy.max_sa_lifetime_s}s",
        "Low",
        "Medium",
        "Reduce the SA lifetime to shorten the exposure window per key.",
    )

    return (checks_passed / checks_total) * 100 if checks_total else 0.0


def _key_management(ike: IkeHandshake, policy: CryptoPolicy) -> float:
    proposal = ike.chosen_proposal
    if proposal is None:
        return 0.0

    dh_score = score_dh(proposal.dh_group)
    lifetime_score = score_lifetime(proposal.lifetime_seconds, policy.max_sa_lifetime_s)
    pfs_component = 100 if ike.pfs_enabled else max(0, 100 - PFS_BONUS * 4)

    return (dh_score + lifetime_score + pfs_component) / 3


def _metadata_exposure(flows: list[FlowFeatures], confidences: list[float]) -> float:
    if not flows or not confidences:
        return 70.0  # no ESP flows to analyze -> exposure unassessed, neutral score

    avg_confidence = sum(confidences) / len(confidences)
    return max(0.0, 100 - avg_confidence * 100)


def compute_score(
    ike: IkeHandshake,
    flows: list[FlowFeatures],
    flow_confidences: list[float],
    policy: CryptoPolicy | None = None,
) -> ScoreResult:
    policy = policy or CryptoPolicy()
    proposal = ike.chosen_proposal

    enc_score = score_encryption(proposal.encryption_alg if proposal else None)
    auth_score = score_auth(proposal.auth_alg if proposal else None, proposal.encryption_alg if proposal else None)
    dh_score = score_dh(proposal.dh_group if proposal else None)
    crypto_strength = _crypto_strength(enc_score, auth_score, dh_score)

    threats: list[ThreatMatrixEntry] = []
    compliance = _compliance(ike, policy, threats)
    key_management = _key_management(ike, policy)
    metadata_exposure = _metadata_exposure(flows, flow_confidences)

    if metadata_exposure < 40:
        threats.append(
            ThreatMatrixEntry(
                finding="ESP flow metadata (packet size/timing) strongly reveals traffic type",
                likelihood="High",
                impact="Medium",
                recommendation="Consider padding or traffic-shaping to reduce side-channel fingerprinting.",
            )
        )

    # overall_score is technical posture only (crypto/compliance/key management).
    # metadata_exposure is deliberately excluded here -- averaging it in would
    # dilute the exact contradiction the Observer Profile (PHASE2.md) exists to
    # surface: a config can be A+ on crypto and F on metadata exposure at once,
    # and blending the two into one number would hide that split.
    weights = policy.category_weights
    overall = (
        crypto_strength * weights.get("crypto_strength", 0)
        + compliance * weights.get("compliance", 0)
        + key_management * weights.get("key_management", 0)
    )

    return ScoreResult(
        crypto_strength=round(crypto_strength, 2),
        compliance=round(compliance, 2),
        key_management=round(key_management, 2),
        metadata_exposure=round(metadata_exposure, 2),
        overall_score=round(overall, 2),
        threat_matrix=threats,
    )
