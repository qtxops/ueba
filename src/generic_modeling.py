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


def score_generic_features(features: pd.DataFrame, bundle: dict[str, Any]) -> pd.DataFrame:
    result = features.copy().sort_values(["day", "user"]).reset_index(drop=True)
    raw = -bundle["pipeline"].score_samples(result[bundle["feature_columns"]])
    anomaly = np.clip((raw - bundle["score_lower"]) / (bundle["score_upper"] - bundle["score_lower"]), 0, 1)
    result["anomaly_score"] = anomaly
    context = (
        np.minimum(result["after_hours_count"] / 3, 1) * 0.20
        + np.minimum(result["failed_event_count"] / 5, 1) * 0.20
        + np.minimum(result["privileged_action_count"] / 20, 1) * 0.25
        + np.minimum(result["new_ip_count"] / 3, 1) * 0.15
        + np.minimum(result["max_events_per_minute"] / 10, 1) * 0.20
    ).clip(0, 1)
    preliminary = 0.80 * anomaly + 0.20 * context
    persistence = preliminary.groupby(result["user"]).transform(
        lambda x: x.shift().rolling(3, min_periods=1).max()
    ).fillna(0)
    result["risk_score"] = np.round(100 * (0.90 * preliminary + 0.10 * persistence)).clip(0, 100).astype(int)
    result["severity"] = result["risk_score"].map(_risk_band)
    result["is_alert"] = (result["risk_score"] >= 70).astype(int)
    result["baseline_alert"] = (
        (result["after_hours_count"] > 10)
        | (result["failed_event_count"] > 10)
        | (result["privileged_action_count"] > 100)
        | (result["max_events_per_minute"] > 25)
    ).astype(int)
    result["explanation"] = result.apply(_explain, axis=1)
    return result

