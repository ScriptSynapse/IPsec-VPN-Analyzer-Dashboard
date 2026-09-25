"""Shared pcap read/write helpers."""

import shutil
from pathlib import Path

from fastapi import UploadFile

from app.core.config import settings

PCAP_MAGIC_NUMBERS = {
    b"\xd4\xc3\xb2\xa1",  # classic pcap, little-endian
    b"\xa1\xb2\xc3\xd4",  # classic pcap, big-endian
    b"\x0a\x0d\x0d\x0a",  # pcapng
}


class InvalidPcapError(Exception):
    pass


def validate_pcap_magic(path: Path) -> None:
    with open(path, "rb") as f:
        header = f.read(4)
    if header not in PCAP_MAGIC_NUMBERS:
        raise InvalidPcapError("uploaded file is not a valid pcap/pcapng capture")


def save_upload(upload: UploadFile, session_id: str) -> Path:
    settings.pcap_storage_dir.mkdir(parents=True, exist_ok=True)
    suffix = Path(upload.filename or "capture.pcap").suffix or ".pcap"
    dest = settings.pcap_storage_dir / f"{session_id}{suffix}"

    with open(dest, "wb") as out:
        shutil.copyfileobj(upload.file, out)

    try:
        validate_pcap_magic(dest)
    except InvalidPcapError:
        dest.unlink(missing_ok=True)
        raise

    return dest


def get_first_packet_ips(pcap_path: str | Path) -> tuple[str, str] | None:
    """Returns (src, dst) of the first IP/IPv6 packet in the capture, if any.

    Used only to populate SessionRecord.peer_src_ip/peer_dst_ip for the
    Observer Profile's peer_stability finding (PHASE2.md) -- this reads a
    field that's already in every capture, it doesn't add new parsing logic.
    """
    from scapy.all import rdpcap
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    packets = rdpcap(str(pcap_path))
    for packet in packets:
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is not None:
            return ip_layer.src, ip_layer.dst
    return None
