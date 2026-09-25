"""Builds a labeled flow-feature dataset from testbed pcaps.

The pcap filename IS the ground-truth label (see CLAUDE.md naming convention:
`{mode}_{cipher}_{dh}_{pfs}_{iptype}_{traffic}_{timestamp}.pcap`). This module
only extracts observable ESP flow metadata per app/flow/extractor.py and tags
each row with the traffic type parsed from the filename -- it never looks at
payload content.
"""

import re
from pathlib import Path

import pandas as pd

from app.core.config import settings
from app.flow.extractor import FlowExtractionError, extract_flows
from app.flow.features import ALL_COLUMNS, FLOW_KEY, LABEL, SOURCE_PCAP

FILENAME_PATTERN = re.compile(
    r"^(?P<mode>[a-z]+)_(?P<cipher>[a-z0-9]+)_(?P<dh>dh\d+)_(?P<pfs>pfson|pfsoff)_"
    r"(?P<iptype>ipv4|ipv6)_(?P<traffic>[a-z]+)_(?P<timestamp>\d{8}T\d{4})\.pcap$"
)


class DatasetBuildError(Exception):
    pass


def parse_label_from_filename(filename: str) -> str:
    match = FILENAME_PATTERN.match(filename)
    if not match:
        raise DatasetBuildError(f"filename does not match naming convention: {filename}")
    return match.group("traffic")


def build_dataset(pcap_dir: Path | None = None) -> pd.DataFrame:
    pcap_dir = pcap_dir or settings.pcap_storage_dir
    rows = []

    for pcap_path in sorted(Path(pcap_dir).glob("*.pcap")):
        try:
            label = parse_label_from_filename(pcap_path.name)
        except DatasetBuildError:
            continue  # not a labeled testbed capture (e.g. a user-uploaded session)

        try:
            flows = extract_flows(pcap_path)
        except FlowExtractionError:
            continue

        for flow in flows:
            row = flow.as_feature_dict()
            row[FLOW_KEY] = flow.flow_key
            row[LABEL] = label
            row[SOURCE_PCAP] = pcap_path.name
            rows.append(row)

    if not rows:
        return pd.DataFrame(columns=ALL_COLUMNS)
    return pd.DataFrame(rows, columns=ALL_COLUMNS)


def save_dataset(df: pd.DataFrame, out_path: Path | None = None) -> Path:
    out_path = out_path or (settings.dataset_dir / "flow_features.csv")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    return out_path


if __name__ == "__main__":
    dataset = build_dataset()
    written_path = save_dataset(dataset)
    print(f"wrote {len(dataset)} labeled flow rows to {written_path}")
