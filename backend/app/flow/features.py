"""Feature name constants for ESP flow-level side-channel features.

These are the only signals available for encrypted ESP traffic: sizes, timing,
and header/sequence metadata. Never derived from decrypted payload content.
"""

FLOW_KEY = "flow_key"
LABEL = "traffic_type"
# Which pcap a row came from -- not a training feature, used only to group
# train/test splits so flows from the same capture never leak across the
# split (PLAN.md M4: "hold out entire pcaps not just rows").
SOURCE_PCAP = "source_pcap"

FEATURE_COLUMNS = [
    "packet_count",
    "duration_s",
    "avg_packet_size",
    "std_packet_size",
    "min_packet_size",
    "max_packet_size",
    "avg_inter_arrival_ms",
    "std_inter_arrival_ms",
    "bytes_per_second",
    "packets_per_second",
    "burstiness",
    "seq_gap_ratio",
]

ALL_COLUMNS = [FLOW_KEY, *FEATURE_COLUMNS, LABEL, SOURCE_PCAP]

TRAFFIC_TYPES = ["voip", "web", "video", "email", "icmp", "messaging"]

# "messaging" is a documented approximation, not real captured traffic: a real
# WhatsApp-style app can't be captured in an isolated lab testbed (no internet
# egress, no real client pairing). See testbed/README.md and docs/dataset_card.md
# for the honesty note on this label -- don't present it as literal WhatsApp
# traffic to judges.
APPROXIMATED_TRAFFIC_TYPES = ["messaging"]
