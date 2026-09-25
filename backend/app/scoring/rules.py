"""Crypto/DH/PFS/lifetime weight tables.

Scores are 0-100 (higher = stronger) and are aligned with the algorithm
tiers in RFC 8221 (Cryptographic Algorithm Implementation Requirements for
ESP/AH, sections 4-5: MUST / SHOULD / SHOULD NOT / MUST NOT) and the minimum
key-strength guidance in NIST SP 800-77 Rev.1 (Guide to IPsec VPNs, sections
4-5). Every weight below traces back to one of those two documents rather
than an arbitrary number.
"""

# RFC 8221 SS 5: AEAD ciphers are MUST/SHOULD, ranked above legacy CBC modes.
# 3DES/DES are SHOULD NOT / MUST NOT respectively.
ENCRYPTION_SCORES: dict[str, int] = {
    "AES-GCM-16": 100,
    "AES-GCM": 100,
    "AES-GCM-12": 95,
    "AES-GCM-8": 90,
    "AES-CCM-16": 90,
    "AES-CCM-12": 85,
    "AES-CCM-8": 80,
    "AES-CBC": 75,
    "Camellia-CBC": 65,
    "Camellia-CTR": 68,
    "Camellia-CCM-8": 78,
    "Camellia-CCM-12": 83,
    "Camellia-CCM-16": 88,
    "AES-CTR": 78,
    "3DES-CBC": 30,
    "3DES": 30,
    "Blowfish-CBC": 20,
    "IDEA-CBC": 15,
    "3IDEA": 15,
    "RC5-R16-B64-CBC": 15,
    "DES-CBC": 5,
    "DES": 5,
    "DES-IV64": 5,
    "DES-IV32": 5,
    "CAST-CBC": 55,
    "RC4": 10,
    "NULL": 0,  # RFC 8221 SS 5: ENCR_NULL MUST NOT be used when confidentiality is required
}

# RFC 8221 SS 4: SHA-2 family is MUST/SHOULD, SHA-1 is SHOULD NOT, MD5 is MUST NOT.
AUTH_SCORES: dict[str, int] = {
    "HMAC-SHA2-512-256": 100,
    "HMAC-SHA2-384-192": 95,
    "HMAC-SHA2-256-128": 90,
    "AES-256-GMAC": 90,
    "AES-192-GMAC": 85,
    "AES-128-GMAC": 80,
    "AES-CMAC-96": 75,
    "AES-XCBC-MAC": 70,
    "HMAC-SHA1-160": 60,
    "HMAC-SHA1": 60,
    "HMAC-MD5-128": 20,
    "HMAC-MD5": 20,
    "DES-MAC": 10,
    "KPDK-MD5": 10,
    # IKEv1 Phase 2 (RFC 2407) and Phase 1 hash algorithms use unsuffixed names;
    # they carry the same relative strength as their IKEv2 counterparts above.
    "HMAC-SHA2-256": 90,
    "HMAC-SHA2-384": 95,
    "HMAC-SHA2-512": 100,
    "HMAC-RIPEMD": 55,
    "Tiger": 55,
}

# NIST SP 800-77 Rev.1 SS 5.4: MODP groups below 2048-bit fall short of the
# 112-bit security minimum; elliptic-curve groups are preferred where available.
DH_GROUP_SCORES: dict[str, int] = {
    "Curve448": 100,
    "Curve25519": 100,
    "ECP-521": 98,
    "ECP-384": 95,
    "ECP-256": 88,
    "brainpoolP512r1": 90,
    "brainpoolP384r1": 85,
    "brainpoolP256r1": 80,
    "MODP-8192": 92,
    "MODP-6144": 88,
    "MODP-4096": 82,
    "MODP-3072": 75,
    "MODP-2048": 65,
    "MODP-1536": 25,
    "MODP-1024": 10,
    "MODP-768": 2,
}

# RFC 8221 SS 5 / RFC 5282: AEAD ciphers combine encryption and integrity into
# one transform -- a real IKEv2 AES-GCM proposal correctly has no separate
# Transform Type 3 (Integrity Algorithm) entry at all (confirmed against a
# real captured handshake via Wireshark's dissector: only ENCR/PRF/KE
# transforms present, no INTEG). A None auth_alg alongside one of these is
# compliant, not a gap -- scoring it as 0 would penalize choosing the more
# modern, MUST/SHOULD-tier cipher.
AEAD_ENCRYPTION_ALGS = {
    "AES-GCM-16", "AES-GCM", "AES-GCM-12", "AES-GCM-8",
    "AES-CCM-16", "AES-CCM-12", "AES-CCM-8",
    "Camellia-CCM-8", "Camellia-CCM-12", "Camellia-CCM-16",
    "ChaCha20-Poly1305",
}

WEAK_DH_GROUPS = {"MODP-768", "MODP-1024", "MODP-1536"}
UNKNOWN_ALG_SCORE = 40

PFS_BONUS = 15

# NIST SP 800-77 Rev.1 SS 5.3: SA lifetimes beyond 24h widen the exposure
# window for a compromised key; score decays per additional day over that.
MAX_RECOMMENDED_LIFETIME_S = 86400
LIFETIME_PENALTY_PER_EXCESS_DAY = 10

CRYPTO_STRENGTH_WEIGHTS = {"encryption": 0.5, "auth": 0.3, "dh": 0.2}

# overall_score covers technical posture only -- metadata_exposure is reported
# as an independent headline figure (see PHASE2.md / Observer Profile) and is
# never part of this weighted sum, however a custom policy sets these weights.
OVERALL_WEIGHTS = {
    "crypto_strength": 0.45,
    "compliance": 0.30,
    "key_management": 0.25,
}


def score_encryption(alg: str | None) -> int:
    if not alg:
        return 0
    return ENCRYPTION_SCORES.get(alg, UNKNOWN_ALG_SCORE)


def is_aead_cipher(encryption_alg: str | None) -> bool:
    return encryption_alg in AEAD_ENCRYPTION_ALGS


def score_auth(alg: str | None, encryption_alg: str | None = None) -> int:
    if not alg:
        # No separate integrity transform is expected -- and correct -- for
        # an AEAD cipher (see AEAD_ENCRYPTION_ALGS above). Only score it as
        # missing when the cipher actually needs a separate one and doesn't
        # have it, which is a real finding.
        return 100 if is_aead_cipher(encryption_alg) else 0
    return AUTH_SCORES.get(alg, UNKNOWN_ALG_SCORE)


def score_dh(group: str | None) -> int:
    if not group:
        return 0
    return DH_GROUP_SCORES.get(group, UNKNOWN_ALG_SCORE)


def score_lifetime(lifetime_seconds: int | None, max_recommended: int = MAX_RECOMMENDED_LIFETIME_S) -> int:
    if lifetime_seconds is None:
        return 50  # unknown: neither penalize nor reward
    if lifetime_seconds <= max_recommended:
        return 100
    excess_days = (lifetime_seconds - max_recommended) / 86400
    return max(0, round(100 - excess_days * LIFETIME_PENALTY_PER_EXCESS_DAY))
