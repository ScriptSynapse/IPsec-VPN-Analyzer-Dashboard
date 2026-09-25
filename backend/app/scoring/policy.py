"""User-uploadable compliance policy: YAML schema + diff against the default."""

import yaml
from pydantic import BaseModel, Field

from app.scoring.rules import MAX_RECOMMENDED_LIFETIME_S, OVERALL_WEIGHTS


class CryptoPolicy(BaseModel):
    min_encryption_score: int = 60
    min_auth_score: int = 50
    min_dh_score: int = 60
    require_pfs: bool = True
    max_sa_lifetime_s: int = MAX_RECOMMENDED_LIFETIME_S
    banned_encryption_algs: list[str] = Field(
        default_factory=lambda: ["DES-CBC", "DES", "DES-IV64", "DES-IV32"]
    )
    banned_auth_algs: list[str] = Field(
        default_factory=lambda: ["HMAC-MD5", "HMAC-MD5-128", "DES-MAC", "KPDK-MD5"]
    )
    # Weights for overall_score (technical posture only). A metadata_exposure
    # key here is accepted but ignored -- see PHASE2.md: metadata exposure is
    # always reported separately, never blended into overall_score.
    category_weights: dict[str, float] = Field(default_factory=lambda: dict(OVERALL_WEIGHTS))


class PolicyParseError(Exception):
    pass


def parse_policy_yaml(raw_yaml: str) -> CryptoPolicy:
    try:
        data = yaml.safe_load(raw_yaml) or {}
    except yaml.YAMLError as exc:
        raise PolicyParseError(f"invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyParseError("policy YAML must be a mapping at the top level")

    try:
        return CryptoPolicy(**data)
    except Exception as exc:
        raise PolicyParseError(f"invalid policy schema: {exc}") from exc


def diff_policy(custom: CryptoPolicy, default: CryptoPolicy | None = None) -> dict[str, dict[str, object]]:
    default = default or CryptoPolicy()
    diffs: dict[str, dict[str, object]] = {}
    for field_name in CryptoPolicy.model_fields:
        custom_value = getattr(custom, field_name)
        default_value = getattr(default, field_name)
        if custom_value != default_value:
            diffs[field_name] = {"default": default_value, "custom": custom_value}
    return diffs
