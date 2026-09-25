"""Regenerates the hand-built ISAKMP fixture pcaps in this directory.

These are minimal, wire-format-correct IKEv1 Main Mode and IKEv2 IKE_SA_INIT
packets built directly from RFC 2409 / RFC 7296 struct layouts (not captured
from a real strongSwan run) -- they exist to pin down tshark's JSON field
naming for app/ike/parser.py without requiring Docker/strongSwan in CI. The
real testbed in backend/testbed/ produces the actual labeled captures used
for ML training and end-to-end validation.

Run: python -m tests.fixtures.generate_fixtures
"""

import struct
from pathlib import Path

from scapy.all import IP, UDP, Raw, wrpcap

FIXTURES_DIR = Path(__file__).parent


def _tv(attr_type: int, value: int) -> bytes:
    return struct.pack(">HH", 0x8000 | attr_type, value)


def _tlv(attr_type: int, value_bytes: bytes) -> bytes:
    return struct.pack(">HH", attr_type, len(value_bytes)) + value_bytes


def build_ikev2_sa_init() -> bytes:
    """One proposal: ENCR=AES-GCM-16(256-bit), PRF=HMAC-SHA2-256, DH=ECP-384."""
    key_len_attr = _tv(14, 256)
    t1 = struct.pack(">BBHBBH", 3, 0, 8 + len(key_len_attr), 1, 0, 20) + key_len_attr  # ENCR
    t2 = struct.pack(">BBHBBH", 3, 0, 8, 2, 0, 5)  # PRF HMAC-SHA2-256
    t3 = struct.pack(">BBHBBH", 0, 0, 8, 4, 0, 20)  # D-H ECP-384

    transforms = t1 + t2 + t3
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 3) + transforms
    sa_payload = struct.pack(">BBH", 0, 0, 4 + len(proposal)) + proposal

    total_len = 28 + len(sa_payload)
    header = struct.pack(
        ">QQBBBBII",
        0x1111111111111111, 0,
        33,     # next payload = SA
        0x20,   # version 2.0
        34,     # exchange type = IKE_SA_INIT
        0x08,   # flags = initiator
        0,
        total_len,
    )
    return header + sa_payload


def build_ikev1_main_mode() -> bytes:
    """One Phase 1 proposal: AES-CBC/256, SHA2-256, PSK, MODP-2048, 86400s lifetime."""
    attrs = (
        _tv(1, 7)       # Encryption Algorithm = AES-CBC
        + _tv(2, 4)     # Hash Algorithm = SHA2-256
        + _tv(3, 1)     # Auth Method = PSK
        + _tv(4, 14)    # Group Description = MODP-2048
        + _tv(11, 1)    # Life Type = seconds
        + _tlv(12, struct.pack(">I", 86400))  # Life Duration
        + _tv(14, 256)  # Key Length
    )
    transform = struct.pack(">BBHBBH", 0, 0, 8 + len(attrs), 1, 1, 0) + attrs
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
    sa_payload = struct.pack(">BBH", 0, 0, 12 + len(proposal)) + struct.pack(">II", 1, 1) + proposal

    total_len = 28 + len(sa_payload)
    header = struct.pack(
        ">QQBBBBII",
        0x2222222222222222, 0,
        1,      # next payload = SA
        0x10,   # version 1.0
        2,      # exchange type = Main Mode
        0,
        0,
        total_len,
    )
    return header + sa_payload


def main() -> None:
    ikev2_pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500) / Raw(load=build_ikev2_sa_init())
    wrpcap(str(FIXTURES_DIR / "ikev2_sa_init.pcap"), [ikev2_pkt])

    ikev1_pkt = IP(src="10.0.0.3", dst="10.0.0.4") / UDP(sport=500, dport=500) / Raw(load=build_ikev1_main_mode())
    wrpcap(str(FIXTURES_DIR / "ikev1_main_mode.pcap"), [ikev1_pkt])

    print(f"wrote fixtures to {FIXTURES_DIR}")


if __name__ == "__main__":
    main()
