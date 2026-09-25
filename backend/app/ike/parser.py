"""tshark-backed IKE handshake parser.

IKE Phase 1/2 proposals are negotiated in cleartext -- tshark's mature ISAKMP
dissector already extracts every field we need, so this module only maps
tshark's numeric transform IDs to human-readable names and assembles the
result. No inference happens here.

Field names below were verified against real tshark 4.2 JSON output (`tshark
-G fields`, plus hand-built IKEv1 Main Mode and IKEv2 IKE_SA_INIT packets
decoded with `tshark -T json --no-duplicate-keys`) rather than assumed, since
tshark's default `-T json` silently drops sibling nodes that share a field
name -- `--no-duplicate-keys` turns those into proper arrays instead.
"""

import json
import subprocess
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.ike.schemas import IkeHandshake, SaProposal

PROTO_ID_ISAKMP = "1"  # Phase 1 / IKE SA
PROTO_ID_AH = "2"
PROTO_ID_ESP = "3"  # Phase 2 / Child SA

# RFC 2409 Appendix A: IKEv1 Phase 1 (ISAKMP) encryption algorithm attribute values.
IKEV1_PHASE1_ENCR_ALGS = {
    1: "DES-CBC",
    2: "IDEA-CBC",
    3: "Blowfish-CBC",
    4: "RC5-R16-B64-CBC",
    5: "3DES-CBC",
    6: "CAST-CBC",
    7: "AES-CBC",
    8: "Camellia-CBC",
}

# RFC 2409 Appendix A: IKEv1 Phase 1 hash algorithm attribute values.
IKEV1_PHASE1_HASH_ALGS = {
    1: "HMAC-MD5",
    2: "HMAC-SHA1",
    3: "Tiger",
    4: "HMAC-SHA2-256",
    5: "HMAC-SHA2-384",
    6: "HMAC-SHA2-512",
}

# RFC 2407 SS 4.4.4: IKEv1 Phase 2 (ESP) transform IDs -- for ESP proposals the
# Transform ID field itself IS the encryption algorithm (no attribute needed).
IKEV1_ESP_TRANSFORM_IDS = {
    1: "DES-IV64",
    2: "DES-CBC",
    3: "3DES-CBC",
    4: "RC5-R16-B64-CBC",
    5: "IDEA-CBC",
    6: "CAST-CBC",
    7: "Blowfish-CBC",
    8: "3IDEA",
    9: "DES-IV32",
    10: "RC4",
    11: "NULL",
    12: "AES-CBC",
}

# RFC 2407 SS 4.5: IKEv1 Phase 2 (ESP/AH) authentication algorithm attribute values.
IKEV1_PHASE2_AUTH_ALGS = {
    1: "HMAC-MD5",
    2: "HMAC-SHA1",
    3: "DES-MAC",
    4: "KPDK-MD5",
    5: "HMAC-SHA2-256",
    6: "HMAC-SHA2-384",
    7: "HMAC-SHA2-512",
    8: "HMAC-RIPEMD",
}

# RFC 7296 / IANA IKEv2 Transform Type 1 (Encryption Algorithm). Verified
# against Wireshark's own ISAKMP dissector output on a real negotiated
# handshake (AES-CBC-256 proposal decoded as "ENCR_AES_CBC (12)"), which
# caught this table being off by one across IDs 11-15 in an earlier version
# -- every real AES-CBC config (11 of the 17 testbed variants) was coming
# back mislabeled as AES-CTR.
IKEV2_ENCR_ALGS = {
    1: "DES-IV64",
    2: "DES",
    3: "3DES",
    4: "RC5",
    5: "IDEA",
    6: "CAST",
    7: "Blowfish",
    8: "3IDEA",
    9: "DES-IV32",
    11: "NULL",
    12: "AES-CBC",
    13: "AES-CTR",
    14: "AES-CCM-8",
    15: "AES-CCM-12",
    16: "AES-CCM-16",
    18: "AES-GCM-8",
    19: "AES-GCM-12",
    20: "AES-GCM-16",
    21: "AES-GMAC",
    23: "Camellia-CBC",
    24: "Camellia-CTR",
    25: "Camellia-CCM-8",
    26: "Camellia-CCM-12",
    27: "Camellia-CCM-16",
    28: "ChaCha20-Poly1305",
}

# IANA IKEv2 Transform Type 3 (Integrity Algorithm).
IKEV2_INTEG_ALGS = {
    1: "HMAC-MD5-128",
    2: "HMAC-SHA1-160",
    3: "DES-MAC",
    4: "KPDK-MD5",
    5: "AES-XCBC-MAC",
    6: "HMAC-MD5-128",
    7: "HMAC-SHA1-160",
    8: "AES-CMAC-96",
    9: "AES-128-GMAC",
    10: "AES-192-GMAC",
    11: "AES-256-GMAC",
    12: "HMAC-SHA2-256-128",
    13: "HMAC-SHA2-384-192",
    14: "HMAC-SHA2-512-256",
}

# RFC 3526 / IANA IKE DH group registry -- shared by IKEv1 Group Description
# and IKEv2 Transform Type 4.
DH_GROUPS = {
    1: "MODP-768",
    2: "MODP-1024",
    5: "MODP-1536",
    14: "MODP-2048",
    15: "MODP-3072",
    16: "MODP-4096",
    17: "MODP-6144",
    18: "MODP-8192",
    19: "ECP-256",
    20: "ECP-384",
    21: "ECP-521",
    28: "brainpoolP256r1",
    29: "brainpoolP384r1",
    30: "brainpoolP512r1",
    31: "Curve25519",
    32: "Curve448",
}

WEAK_DH_GROUPS = {1, 2, 5}


class IkeParseError(Exception):
    pass


def _run_tshark(pcap_path: Path) -> list[dict]:
    cmd = [
        settings.tshark_path,
        "-r",
        str(pcap_path),
        "-Y",
        "isakmp",
        "-T",
        "json",
        "--no-duplicate-keys",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
    except FileNotFoundError as exc:
        raise IkeParseError("tshark is not installed or not on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise IkeParseError(f"tshark failed: {exc.stderr.strip()}") from exc
    except subprocess.TimeoutExpired as exc:
        raise IkeParseError("tshark timed out parsing pcap") from exc

    stdout = result.stdout.strip()
    if not stdout:
        return []
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise IkeParseError("could not decode tshark JSON output") from exc


def _collect_isakmp_layers(packets: list[dict]) -> list[dict]:
    layers = []
    for packet in packets:
        isakmp = packet.get("_source", {}).get("layers", {}).get("isakmp")
        if isakmp:
            layers.append(isakmp)
    return layers


def _find_all(node: Any, predicate) -> list[dict]:
    """Recursively collect every dict in the tree for which predicate(node) is True."""
    found = []
    if isinstance(node, dict):
        if predicate(node):
            found.append(node)
        for value in node.values():
            found.extend(_find_all(value, predicate))
    elif isinstance(node, list):
        for item in node:
            found.extend(_find_all(item, predicate))
    return found


def _find_first_value(node: Any, field_name: str) -> str | None:
    matches = _find_all(node, lambda n: field_name in n)
    if not matches:
        return None
    value = matches[0][field_name]
    return value[0] if isinstance(value, list) else value


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0) if value.lower().startswith("0x") else int(value)
    except (ValueError, AttributeError):
        return None


def _parse_ikev2_proposal(proposal_node: dict) -> tuple[SaProposal, bool]:
    """Returns (proposal, has_dh) for an IKEv2 (typed-transform) proposal."""
    transform_nodes = _find_all(proposal_node, lambda n: "isakmp.tf.type" in n)

    encr_id = auth_id = dh_id = key_len = None
    for t in transform_nodes:
        ttype = _to_int(t.get("isakmp.tf.type"))
        if ttype == 1:
            encr_id = _to_int(t.get("isakmp.tf.id.encr"))
            key_len = _to_int(_find_first_value(t, "isakmp.ike2.attr.key_length"))
        elif ttype == 3:
            auth_id = _to_int(t.get("isakmp.tf.id.integ"))
        elif ttype == 4:
            dh_id = _to_int(t.get("isakmp.tf.id.dh"))

    proposal = SaProposal(
        encryption_alg=IKEV2_ENCR_ALGS.get(encr_id) if encr_id else None,
        key_length=key_len,
        auth_alg=IKEV2_INTEG_ALGS.get(auth_id) if auth_id else None,
        dh_group=DH_GROUPS.get(dh_id) if dh_id else None,
    )
    return proposal, dh_id is not None


def _parse_ikev1_phase1_proposal(proposal_node: dict) -> SaProposal:
    attr_nodes = _find_all(proposal_node, lambda n: "isakmp.ike.attr.type" in n)

    encr_id = auth_id = dh_id = key_len = lifetime = None
    for attr in attr_nodes:
        if "isakmp.ike.attr.encryption_algorithm" in attr:
            encr_id = _to_int(attr["isakmp.ike.attr.encryption_algorithm"])
        if "isakmp.ike.attr.hash_algorithm" in attr:
            auth_id = _to_int(attr["isakmp.ike.attr.hash_algorithm"])
        if "isakmp.ike.attr.group_description" in attr:
            dh_id = _to_int(attr["isakmp.ike.attr.group_description"])
        if "isakmp.ike.attr.key_length" in attr:
            key_len = _to_int(attr["isakmp.ike.attr.key_length"])
        if "isakmp.ike.attr.life_duration" in attr:
            lifetime = _to_int(attr["isakmp.ike.attr.life_duration"])

    return SaProposal(
        encryption_alg=IKEV1_PHASE1_ENCR_ALGS.get(encr_id) if encr_id else None,
        key_length=key_len,
        auth_alg=IKEV1_PHASE1_HASH_ALGS.get(auth_id) if auth_id else None,
        dh_group=DH_GROUPS.get(dh_id) if dh_id else None,
        lifetime_seconds=lifetime,
    )


def _parse_ikev1_phase2_proposal(proposal_node: dict) -> tuple[SaProposal, bool]:
    transform_id = _to_int(_find_first_value(proposal_node, "isakmp.trans.id"))
    attr_nodes = _find_all(proposal_node, lambda n: "isakmp.ipsec.attr.type" in n)

    auth_id = dh_id = key_len = lifetime = None
    for attr in attr_nodes:
        if "isakmp.ipsec.attr.auth_algorithm" in attr:
            auth_id = _to_int(attr["isakmp.ipsec.attr.auth_algorithm"])
        if "isakmp.ipsec.attr.group_description" in attr:
            dh_id = _to_int(attr["isakmp.ipsec.attr.group_description"])
        if "isakmp.ipsec.attr.key_length" in attr:
            key_len = _to_int(attr["isakmp.ipsec.attr.key_length"])
        if "isakmp.ipsec.attr.life_duration" in attr:
            lifetime = _to_int(attr["isakmp.ipsec.attr.life_duration"])

    proposal = SaProposal(
        encryption_alg=IKEV1_ESP_TRANSFORM_IDS.get(transform_id) if transform_id else None,
        key_length=key_len,
        auth_alg=IKEV1_PHASE2_AUTH_ALGS.get(auth_id) if auth_id else None,
        dh_group=DH_GROUPS.get(dh_id) if dh_id else None,
        lifetime_seconds=lifetime,
    )
    return proposal, dh_id is not None


def parse_ike(pcap_path: str | Path) -> IkeHandshake:
    """Parse the IKE handshake in a pcap into structured, cleartext fields."""
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise IkeParseError(f"pcap not found: {pcap_path}")

    packets = _run_tshark(pcap_path)
    layers = _collect_isakmp_layers(packets)
    if not layers:
        raise IkeParseError("no ISAKMP/IKE traffic found in capture")

    # A real capture window can contain more than one ISAKMP exchange --
    # DPD probes, a stray DELETE from a prior SA, a rekey -- not just the
    # handshake itself (confirmed against a real strongSwan capture: the
    # first ISAKMP frame in the file was a leftover INFORMATIONAL/DELETE
    # from the previous SA, not the actual IKE_SA_INIT). Report header
    # metadata (exchange type, SPIs) from the first layer that actually
    # carries an SA proposal, not just the first ISAKMP frame in the file.
    header_layer = next(
        (layer for layer in layers if _find_all(layer, lambda n: "isakmp.prop.number" in n)),
        layers[0],
    )
    version_raw = header_layer.get("isakmp.version", "")
    ike_version = "2" if _to_int(version_raw) and _to_int(version_raw) >= 0x20 else "1"
    exchange_type = header_layer.get("isakmp.exchangetype")
    initiator_spi = header_layer.get("isakmp.ispi")
    responder_spi = header_layer.get("isakmp.rspi")
    # The IKE_SA_INIT *request* legitimately carries an all-zero responder
    # SPI per RFC 7296 -- the responder hasn't assigned one yet. Prefer the
    # real value from a later layer (e.g. the matching response) once it's
    # known, instead of reporting the placeholder zero SPI.
    if responder_spi is not None and responder_spi.replace(":", "").strip("0") == "":
        # Must match on initiator SPI too -- a capture with a leftover
        # exchange from a *different* IKE_SA (confirmed above) has its own,
        # unrelated non-zero responder SPI that must not be picked up here.
        real_rspi = next(
            (
                layer.get("isakmp.rspi")
                for layer in layers
                if layer.get("isakmp.ispi") == initiator_spi
                and layer.get("isakmp.rspi") not in (None, responder_spi)
            ),
            None,
        )
        if real_rspi:
            responder_spi = real_rspi

    proposals: list[SaProposal] = []
    vendor_ids: list[str] = []
    pfs_enabled = False

    for layer in layers:
        for vid in _find_all(layer, lambda n: "isakmp.vid_string" in n or "isakmp.vid_bytes" in n):
            value = vid.get("isakmp.vid_string") or vid.get("isakmp.vid_bytes")
            if value:
                vendor_ids.append(value)

        proposal_nodes = _find_all(layer, lambda n: "isakmp.prop.number" in n)
        for prop_node in proposal_nodes:
            proto_id = prop_node.get("isakmp.prop.protoid")
            has_dh = False

            if ike_version == "2":
                proposal, has_dh = _parse_ikev2_proposal(prop_node)
            elif proto_id == PROTO_ID_ISAKMP:
                proposal = _parse_ikev1_phase1_proposal(prop_node)
            elif proto_id in (PROTO_ID_ESP, PROTO_ID_AH):
                proposal, has_dh = _parse_ikev1_phase2_proposal(prop_node)
            else:
                continue

            if proto_id == PROTO_ID_ESP and has_dh:
                pfs_enabled = True

            if proposal.encryption_alg or proposal.dh_group:
                proposals.append(proposal)

    # The request and its matching response both carry the same negotiated
    # proposal in cleartext (confirmed on a real capture: IKE_SA_INIT
    # request + response produced two byte-identical proposals) -- collapse
    # those duplicates rather than reporting the same negotiated algorithm
    # set twice as if two distinct proposals were offered.
    deduped: list[SaProposal] = []
    seen = set()
    for proposal in proposals:
        key = (proposal.encryption_alg, proposal.key_length, proposal.auth_alg, proposal.dh_group, proposal.lifetime_seconds)
        if key in seen:
            continue
        seen.add(key)
        proposal.proposal_num = len(deduped) + 1
        deduped.append(proposal)

    return IkeHandshake(
        ike_version=ike_version,
        exchange_type=exchange_type,
        initiator_spi=initiator_spi,
        responder_spi=responder_spi,
        proposals=deduped,
        pfs_enabled=pfs_enabled,
        vendor_ids=vendor_ids,
        implementation_guess=_guess_implementation(vendor_ids),
    )


_VENDOR_SIGNATURES = {
    "strongswan": "strongSwan",
    "libreswan": "Libreswan",
    "cisco": "Cisco",
    "microsoft": "Microsoft Windows",
    "fortinet": "FortiGate",
}


def _guess_implementation(vendor_ids: list[str]) -> str | None:
    for vid in vendor_ids:
        lowered = vid.lower()
        for signature, name in _VENDOR_SIGNATURES.items():
            if signature in lowered:
                return name
    return None
