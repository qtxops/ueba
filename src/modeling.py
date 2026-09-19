"""Isolation Forest training, scoring, risk calculation, and evaluation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler

from .config import MODEL_FEATURES, RISK_BANDS


EXPLANATION_MAP = {
    "after_hours_logons": "after-hours login activity",
    "unique_pcs": "use of an unusual number of computers",
    "device_connect_count": "removable-device connections",
    "file_access_count": "unusually high file activity",
    "removable_file_count": "files copied to removable media",
    "sensitive_file_count": "sensitive files accessed",
    "executable_file_count": "executable or script files accessed",
    "bytes_accessed": "unusually large data volume",
    "total_events": "overall activity volume",
    "logon_count": "unusual login frequency",
}


def _pipeline(random_state: int = 42) -> Pipeline:
    return Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", RobustScaler()),
            (
                "model",
                IsolationForest(
                    n_estimators=350,
                    max_samples="auto",
                    contamination="auto",
                    random_state=random_state,
                    n_jobs=-1,
                ),
            ),
        ]
    )


def train_model(features: pd.DataFrame, train_fraction: float = 0.70) -> dict[str, Any]:
    unique_days = np.sort(features["day"].dropna().unique())
    if len(unique_days) < 10:
        raise ValueError("At least 10 distinct activity days are required for training")
    split_index = max(1, min(len(unique_days) - 1, int(len(unique_days) * train_fraction)))
    split_day = pd.Timestamp(unique_days[split_index])
    train_mask = features["day"] < split_day
    pipeline = _pipeline()
    pipeline.fit(features.loc[train_mask, MODEL_FEATURES])
    raw_train_scores = -pipeline.score_samples(features.loc[train_mask, MODEL_FEATURES])
    lower = float(np.quantile(raw_train_scores, 0.05))
    upper = float(np.quantile(raw_train_scores, 0.99))
    if upper <= lower:
        upper = lower + 1e-6
    return {
        "pipeline": pipeline,
        "feature_columns": MODEL_FEATURES,
        "score_lower": lower,
        "score_upper": upper,
        "split_day": split_day.isoformat(),
        "train_rows": int(train_mask.sum()),
    }


def _risk_band(score: float) -> str:
    for lower, label in RISK_BANDS:
        if score >= lower:
            return label
    return "Low"


def _explain_row(row: pd.Series) -> str:
    candidates: list[tuple[float, str]] = []
    for base, phrase in EXPLANATION_MAP.items():
        value = float(row.get(f"personal_z_{base}", 0))
        org_value = float(row.get(f"org_z_{base}", 0))
        strength = max(value, org_value)
        if strength >= 1.5:
            candidates.append((strength, phrase))
    if float(row.get("after_hours_logons", 0)) > 0:
        candidates.append((5.0, "login outside normal working hours"))
    candidates.sort(reverse=True)
    reasons: list[str] = []
    for _, phrase in candidates:
        if phrase not in reasons:
            reasons.append(phrase)
        if len(reasons) == 3:
            break
    return "; ".join(reasons) if reasons else "combined behavior differs from the learned baseline"


def score_features(features: pd.DataFrame, bundle: dict[str, Any]) -> pd.DataFrame:
    result = features.copy().sort_values(["day", "user"]).reset_index(drop=True)
    raw = -bundle["pipeline"].score_samples(result[bundle["feature_columns"]])
    normalized = np.clip((raw - bundle["score_lower"]) / (bundle["score_upper"] - bundle["score_lower"]), 0, 1)
    result["anomaly_score"] = normalized

    severity = (
        np.minimum(result["after_hours_logons"], 1) * 0.25
        + np.minimum(result["removable_file_count"] / 20, 1) * 0.30
        + np.minimum(result["sensitive_file_count"] / 50, 1) * 0.25
        + np.minimum(result["executable_file_count"] / 5, 1) * 0.20
    ).clip(0, 1)
    preliminary = 0.75 * normalized + 0.25 * severity
    prior_high = preliminary.groupby(result["user"]).transform(
        lambda values: values.shift().rolling(3, min_periods=1).max()
    ).fillna(0)
    result["risk_score"] = np.round(100 * (0.90 * preliminary + 0.10 * prior_high)).clip(0, 100).astype(int)
    result["severity"] = result["risk_score"].map(_risk_band)
    result["is_alert"] = (result["risk_score"] >= 70).astype(int)
    # Deliberately rigid baseline: useful for comparison, but unable to adapt to
    # individual users or gradual changes in behavior.
    result["baseline_alert"] = (
        (result["file_access_count"] > 200)
        | (result["removable_file_count"] > 100)
        | (result["executable_file_count"] > 15)
        | (result["after_hours_logons"] > 2)
    ).astype(int)
    result["explanation"] = result.apply(_explain_row, axis=1)
    return result


def evaluate(scored: pd.DataFrame, split_day: str) -> dict[str, float | int | str]:
    test = scored[scored["day"] >= pd.Timestamp(split_day)].copy()
    labels = test["is_malicious"].astype(int)
    predictions = test["is_alert"].astype(int)
    metrics: dict[str, float | int | str] = {
        "split_day": pd.Timestamp(split_day).date().isoformat(),
        "test_rows": int(len(test)),
        "malicious_rows": int(labels.sum()),
        "alerts": int(predictions.sum()),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "false_alerts_per_1000": float(1000 * ((predictions == 1) & (labels == 0)).sum() / max(1, (labels == 0).sum())),
    }
    metrics["pr_auc"] = float(average_precision_score(labels, test["risk_score"])) if labels.nunique() > 1 else 0.0
    top_k = min(10, len(test))
    metrics["malicious_in_top_10"] = int(test.nlargest(top_k, "risk_score")["is_malicious"].sum())
    baseline = test["baseline_alert"].astype(int)
    metrics["baseline_alerts"] = int(baseline.sum())
    metrics["baseline_precision"] = float(precision_score(labels, baseline, zero_division=0))
    metrics["baseline_recall"] = float(recall_score(labels, baseline, zero_division=0))
    metrics["baseline_f1"] = float(f1_score(labels, baseline, zero_division=0))
    return metrics


def save_bundle(bundle: dict[str, Any], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, target)


def load_bundle(path: str | Path) -> dict[str, Any]:
    return joblib.load(path)
