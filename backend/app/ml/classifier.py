"""Loads the trained traffic-type classifier and predicts with a confidence score.

Falls back to an explicit "unknown" / 0.0-confidence result when no artifact
has been trained yet, rather than crashing the API -- a fresh checkout with no
testbed captures should still serve every endpoint.
"""

from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd

from app.core.config import settings
from app.flow.extractor import FlowFeatures
from app.flow.features import FEATURE_COLUMNS
from app.ml.train import MODEL_FILENAME

UNKNOWN_LABEL = "unknown"


class ClassifierUnavailable(Exception):
    pass


@lru_cache(maxsize=1)
def _load_artifact() -> dict:
    path = settings.ml_artifacts_dir / MODEL_FILENAME
    if not path.exists():
        raise ClassifierUnavailable(
            f"no trained model artifact at {path}; run `python -m app.ml.train` "
            "after generating labeled testbed captures"
        )
    return joblib.load(path)


def reset_cache() -> None:
    _load_artifact.cache_clear()


def predict(features: FlowFeatures) -> tuple[str, float]:
    try:
        artifact = _load_artifact()
    except ClassifierUnavailable:
        return UNKNOWN_LABEL, 0.0

    model = artifact["model"]
    row = pd.DataFrame([features.as_feature_dict()], columns=FEATURE_COLUMNS)
    proba = model.predict_proba(row)[0]
    classes = model.classes_
    best_idx = proba.argmax()
    return str(classes[best_idx]), float(proba[best_idx])


def feature_importances() -> dict[str, float]:
    try:
        artifact = _load_artifact()
    except ClassifierUnavailable:
        return {}
    return artifact.get("feature_importances", {})


def is_model_available() -> bool:
    try:
        _load_artifact()
        return True
    except ClassifierUnavailable:
        return False
