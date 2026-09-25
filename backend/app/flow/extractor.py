"""Per-flow feature extraction from ESP packets, using only observable metadata.

We never attempt to decrypt ESP payloads. Every feature here comes from packet
sizes, timing, and the cleartext SPI/sequence-number fields defined by RFC 4303
— the same side-channel signals a passive observer on the wire would see.
"""

import statistics
from dataclasses import dataclass, field
from pathlib import Path

from scapy.all import rdpcap
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import ESP

from app.flow.features import FEATURE_COLUMNS


class FlowExtractionError(Exception):
    pass


@dataclass
class _RawFlow:
    spi: int
    src: str
    dst: str
    sizes: list[int] = field(default_factory=list)
    timestamps: list[float] = field(default_factory=list)
    sequence_numbers: list[int] = field(default_factory=list)

    @property
    def flow_key(self) -> str:
        return f"{self.src}->{self.dst}:spi={self.spi:#010x}"


@dataclass
class FlowFeatures:
    flow_key: str
    packet_count: int
    duration_s: float
    avg_packet_size: float
    std_packet_size: float
    min_packet_size: float
    max_packet_size: float
    avg_inter_arrival_ms: float
    std_inter_arrival_ms: float
    bytes_per_second: float
    packets_per_second: float
    burstiness: float
    seq_gap_ratio: float

    def as_feature_dict(self) -> dict[str, float]:
        return {name: getattr(self, name) for name in FEATURE_COLUMNS}


def _safe_stdev(values: list[float]) -> float:
    return statistics.stdev(values) if len(values) > 1 else 0.0


def _burstiness(inter_arrivals: list[float]) -> float:
    if len(inter_arrivals) < 2:
        return 0.0
    mean = statistics.mean(inter_arrivals)
    std = _safe_stdev(inter_arrivals)
    denom = std + mean
    return (std - mean) / denom if denom > 0 else 0.0


def _seq_gap_ratio(sequence_numbers: list[int]) -> float:
    if len(sequence_numbers) < 2:
        return 0.0
    ordered = sorted(sequence_numbers)
    gaps = sum(
        1 for prev, cur in zip(ordered, ordered[1:]) if cur - prev != 1
    )
    return gaps / (len(ordered) - 1)


def _summarize(flow: _RawFlow) -> FlowFeatures:
    sizes = flow.sizes
    timestamps = sorted(flow.timestamps)
    duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
    inter_arrivals_ms = [
        (b - a) * 1000 for a, b in zip(timestamps, timestamps[1:])
    ]

    return FlowFeatures(
        flow_key=flow.flow_key,
        packet_count=len(sizes),
        duration_s=duration,
        avg_packet_size=statistics.mean(sizes),
        std_packet_size=_safe_stdev(sizes),
        min_packet_size=min(sizes),
        max_packet_size=max(sizes),
        avg_inter_arrival_ms=statistics.mean(inter_arrivals_ms) if inter_arrivals_ms else 0.0,
        std_inter_arrival_ms=_safe_stdev(inter_arrivals_ms),
        bytes_per_second=sum(sizes) / duration if duration > 0 else float(sum(sizes)),
        packets_per_second=len(sizes) / duration if duration > 0 else float(len(sizes)),
        burstiness=_burstiness(inter_arrivals_ms),
        seq_gap_ratio=_seq_gap_ratio(flow.sequence_numbers),
    )


def extract_flows(pcap_path: str | Path, min_packets: int = 3) -> list[FlowFeatures]:
    """Extract one FlowFeatures per ESP flow (identified by src/dst/SPI)."""
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FlowExtractionError(f"pcap not found: {pcap_path}")

    try:
        packets = rdpcap(str(pcap_path))
    except Exception as exc:
        raise FlowExtractionError(f"failed to read pcap: {exc}") from exc

    flows: dict[tuple[str, str, int], _RawFlow] = {}

    for packet in packets:
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        esp_layer = packet.getlayer(ESP)
        if ip_layer is None or esp_layer is None:
            continue

        key = (ip_layer.src, ip_layer.dst, int(esp_layer.spi))
        flow = flows.setdefault(
            key, _RawFlow(spi=int(esp_layer.spi), src=ip_layer.src, dst=ip_layer.dst)
        )
        flow.sizes.append(len(packet))
        flow.timestamps.append(float(packet.time))
        flow.sequence_numbers.append(int(esp_layer.seq))

    return [
        _summarize(flow) for flow in flows.values() if len(flow.sizes) >= min_packets
    ]
