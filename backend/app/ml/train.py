"""Trains the ESP traffic-type classifier.

RandomForest first, per CLAUDE.md M4 -- an explainable baseline whose feature
importances can be shown to judges as the basis for the AI Confidence Score,
before anything fancier is tried.
"""

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import GroupShuffleSplit, train_test_split

from app.core.config import settings
from app.flow.features import FEATURE_COLUMNS, LABEL, SOURCE_PCAP
from app.ml.dataset import build_dataset, save_dataset

MODEL_FILENAME = "traffic_classifier.joblib"
MIN_ROWS = 10
MIN_CLASSES = 2


class TrainingDataError(Exception):
    pass


def train(dataset_path: Path | None = None, artifact_dir: Path | None = None) -> dict:
    artifact_dir = artifact_dir or settings.ml_artifacts_dir
    artifact_dir.mkdir(parents=True, exist_ok=True)

    if dataset_path is not None and Path(dataset_path).exists():
        df = pd.read_csv(dataset_path)
    else:
        df = build_dataset()
        save_dataset(df)

    if len(df) < MIN_ROWS or df[LABEL].nunique() < MIN_CLASSES:
        raise TrainingDataError(
            "Not enough labeled flow data to train a classifier. Run the testbed "
            "(backend/testbed/) to generate captures across multiple traffic types, "
            f"then re-run `python -m app.ml.dataset`. Found {len(df)} rows across "
            f"{df[LABEL].nunique() if len(df) else 0} classes; need at least "
            f"{MIN_ROWS} rows and {MIN_CLASSES} classes."
        )

    X = df[FEATURE_COLUMNS]
    y = df[LABEL]

    if SOURCE_PCAP in df.columns and df[SOURCE_PCAP].nunique() >= 2:
        # Hold out entire pcaps, not just rows -- flows from the same capture
        # must never end up split across train and test (PLAN.md M4).
        splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
        train_idx, test_idx = next(splitter.split(X, y, groups=df[SOURCE_PCAP]))
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
    else:
        # Fallback for a hand-built dataset with no source_pcap column, or one
        # covering only a single capture -- can't group-split meaningfully,
        # so this falls back to a stratified row-level split (which risks
        # flow-level leakage if rows from one pcap land on both sides).
        stratify = y if y.value_counts().min() >= 2 else None
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=stratify
        )

    model = RandomForestClassifier(
        n_estimators=200, max_depth=8, random_state=42, class_weight="balanced"
    )
    model.fit(X_train, y_train)

    report = classification_report(y_test, model.predict(X_test), output_dict=True, zero_division=0)
    importances = dict(zip(FEATURE_COLUMNS, model.feature_importances_.tolist()))

    artifact = {
        "model": model,
        "feature_columns": FEATURE_COLUMNS,
        "classes": sorted(y.unique().tolist()),
        "feature_importances": importances,
        "classification_report": report,
    }
    artifact_path = artifact_dir / MODEL_FILENAME
    joblib.dump(artifact, artifact_path)

    return {"artifact_path": str(artifact_path), "report": report, "importances": importances}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the ESP traffic-type classifier")
    parser.add_argument("--dataset", type=Path, default=None, help="Path to a pre-built feature CSV")
    args = parser.parse_args()

    outcome = train(dataset_path=args.dataset)
    print(f"Saved model to {outcome['artifact_path']}")
    print(f"Feature importances: {outcome['importances']}")
