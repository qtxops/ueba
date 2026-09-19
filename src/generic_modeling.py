"""Modeling and explainability for normalized public UEBA datasets."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from .generic_features import GENERIC_DEVIATION_BASES, GENERIC_MODEL_FEATURES
from .modeling import _pipeline, _risk_band


GENERIC_EXPLANATIONS = {
    "event_count": "unusual activity volume",
    "after_hours_count": "activity outside normal hours",
    "failed_event_count": "unusual number of failed actions",
    "unique_ips": "access from many IP addresses",
    "unique_resources": "unusual resource diversity",
    "unique_actions": "unusual action diversity",
    "unique_ports": "unusual port diversity",
    "unique_devices": "access through many network devices",
    "privileged_action_count": "unusual privileged operations",
    "new_ip_count": "previously unseen IP addresses",
    "new_resource_count": "previously unseen resources",
    "new_device_count": "previously unseen devices",
    "max_events_per_minute": "a concentrated burst of activity",
    "file_access_count": "unusual file activity",
    "removable_file_count": "unusual removable-media activity",
    "sensitive_file_count": "unusual sensitive-file access",
    "executable_file_count": "unusual executable or script access",
    "bytes_accessed": "unusual data volume",
}


def train_generic_model(features: pd.DataFrame, train_fraction: float = 0.70) -> dict[str, Any]:
    days = np.sort(features["day"].dropna().unique())
    if len(days) < 10:
        raise ValueError("At least 10 distinct activity days are required")
    split_index = max(1, min(len(days) - 1, int(len(days) * train_fraction)))
    split_day = pd.Timestamp(days[split_index])
    train_mask = features["day"] < split_day
    pipeline = _pipeline()
    pipeline.fit(features.loc[train_mask, GENERIC_MODEL_FEATURES])
    scores = -pipeline.score_samples(features.loc[train_mask, GENERIC_MODEL_FEATURES])
    lower = float(np.quantile(scores, 0.05))
    upper = float(np.quantile(scores, 0.99))
    return {
        "pipeline": pipeline,
        "feature_columns": GENERIC_MODEL_FEATURES,
        "score_lower": lower,
        "score_upper": upper if upper > lower else lower + 1e-6,
        "split_day": split_day.isoformat(),
        "train_rows": int(train_mask.sum()),
    }


def _explain(row: pd.Series) -> str:
    candidates: list[tuple[float, str]] = []
    for base in GENERIC_DEVIATION_BASES:
        score = max(float(row.get(f"personal_z_{base}", 0)), float(row.get(f"peer_z_{base}", 0)))
        if score >= 1.5:
            candidates.append((score, GENERIC_EXPLANATIONS[base]))
    candidates.sort(reverse=True)
    reasons = []
    for _, text in candidates:
        if text not in reasons:
            reasons.append(text)
        if len(reasons) == 3:
            break
    return "; ".join(reasons) if reasons else "combined behavior differs from the learned baseline"


def _rule_layer(features: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    """Return an independent deterministic score and explanation."""
    components = pd.DataFrame(
        {
            "after-hours volume": np.minimum(features["after_hours_count"] / 10, 1),
            "failed actions": np.minimum(features["failed_event_count"] / 10, 1),
            "privileged actions": np.minimum(features["privileged_action_count"] / 100, 1),
            "activity burst": np.minimum(features["max_events_per_minute"] / 25, 1),
            "removable-media transfer": np.minimum(features["removable_file_count"] / 50, 1),
            "sensitive-file access": np.minimum(features["sensitive_file_count"] / 100, 1),
            "seven-day removable-media accumulation": np.minimum(
                features["rolling_7d_removable_file_count"] / 100, 1
            ),
            "seven-day sensitive-file accumulation": np.minimum(
                features["rolling_7d_sensitive_file_count"] / 150, 1
            ),
            "new devices": np.minimum(features["new_device_count"] / 2, 1),
            "rapid seven-day growth": np.minimum(
                np.maximum(features["event_trend_7d_vs_30d"] - 1, 0) / 3, 1
            ),
        },
        index=features.index,
    ).fillna(0)
    score = np.round(100 * components.max(axis=1)).astype(int)
    reason = components.idxmax(axis=1)
    reason = reason.where(score.gt(0), "no fixed rule matched")
    return score, reason


def score_generic_features(features: pd.DataFrame, bundle: dict[str, Any]) -> pd.DataFrame:
    result = features.copy().sort_values(["day", "user"]).reset_index(drop=True)
    raw = -bundle["pipeline"].score_samples(result[bundle["feature_columns"]])
    anomaly = np.clip((raw - bundle["score_lower"]) / (bundle["score_upper"] - bundle["score_lower"]), 0, 1)
    result["anomaly_score"] = anomaly
    persistence = pd.Series(anomaly, index=result.index).groupby(result["user"]).transform(
        lambda x: x.shift().rolling(3, min_periods=1).max()
    ).fillna(0)
    result["ml_risk_score"] = np.round(100 * (0.95 * anomaly + 0.05 * persistence)).clip(0, 100).astype(int)
    result["rule_score"], result["rule_explanation"] = _rule_layer(result)
    result["ml_alert"] = (result["ml_risk_score"] >= 70).astype(int)
    result["rule_alert"] = (result["rule_score"] >= 70).astype(int)
    result["case_priority_score"] = result[["ml_risk_score", "rule_score"]].max(axis=1)
    result["case_severity"] = result["case_priority_score"].map(_risk_band)
    # Compatibility names now refer only to the anomaly model; rule evidence is
    # intentionally kept separate and is never blended into the ML risk score.
    result["risk_score"] = result["ml_risk_score"]
    result["severity"] = result["risk_score"].map(_risk_band)
    result["is_alert"] = result["ml_alert"]
    result["baseline_alert"] = result["rule_alert"]
    result["explanation"] = result.apply(_explain, axis=1)
    return result
