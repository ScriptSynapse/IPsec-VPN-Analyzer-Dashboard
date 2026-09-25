from pathlib import Path

from scapy.all import IP, wrpcap
from scapy.layers.ipsec import ESP

from app.flow.extractor import extract_flows


def _make_esp_pcap(path: Path, n_packets: int = 10) -> None:
    packets = []
    for i in range(n_packets):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ESP(spi=0xDEADBEEF, seq=i + 1) / (b"x" * 100)
        pkt.time = i * 0.02
        packets.append(pkt)
    wrpcap(str(path), packets)


def test_extract_flows_basic(tmp_path: Path):
    pcap = tmp_path / "sample.pcap"
    _make_esp_pcap(pcap)

    flows = extract_flows(pcap)
    assert len(flows) == 1

    flow = flows[0]
    assert flow.packet_count == 10
    assert flow.seq_gap_ratio == 0.0
    assert flow.avg_packet_size > 0
    assert flow.duration_s > 0
