from pathlib import Path

import pytest

from app.ike.parser import IkeParseError, parse_ike

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parses_ikev2_sa_init():
    handshake = parse_ike(FIXTURES_DIR / "ikev2_sa_init.pcap")

    assert handshake.ike_version == "2"
    proposal = handshake.chosen_proposal
    assert proposal is not None
    assert proposal.encryption_alg == "AES-GCM-16"
    assert proposal.key_length == 256
    assert proposal.dh_group == "ECP-384"


def test_parses_ikev1_main_mode():
    handshake = parse_ike(FIXTURES_DIR / "ikev1_main_mode.pcap")

    assert handshake.ike_version == "1"
    proposal = handshake.chosen_proposal
    assert proposal is not None
    assert proposal.encryption_alg == "AES-CBC"
    assert proposal.auth_alg == "HMAC-SHA2-256"
    assert proposal.dh_group == "MODP-2048"
    assert proposal.lifetime_seconds == 86400


def test_missing_pcap_raises():
    with pytest.raises(IkeParseError):
        parse_ike("/nonexistent/path.pcap")


def test_non_ike_pcap_raises(tmp_path):
    from scapy.all import IP, UDP, wrpcap

    pcap = tmp_path / "no_ike.pcap"
    wrpcap(str(pcap), [IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=1234, dport=80)])

    with pytest.raises(IkeParseError):
        parse_ike(pcap)
