"""Repeatable held-out-seed evaluation for the complete canonical pipeline."""

from __future__ import annotations

import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

from .adapters import load_cert_events
from .demo_data import generate_demo_logs
from .generic_features import build_generic_feature_table
from .generic_modeling import score_generic_features, train_generic_model
from .modeling import evaluate


def ranking_metrics(scored: pd.DataFrame, split_day: str) -> dict[str, float | int]:
    test = scored[scored["day"] >= pd.Timestamp(split_day)].copy()
    malicious = test["is_malicious"].astype(bool)
    malicious_scores = test.loc[malicious, "ml_risk_score"]
    if malicious_scores.empty:
        return {"alerts_to_catch_all_attacks": 0, "alert_budget_fraction": 0.0, "incident_recall": 0.0}
    catch_all_threshold = int(malicious_scores.min())
    alerts_needed = int(test["ml_risk_score"].ge(catch_all_threshold).sum())
    incidents = test.loc[malicious, ["user", "scenario"]].drop_duplicates()
    detected = test.loc[malicious & test["ml_alert"].eq(1), ["user", "scenario"]].drop_duplicates()
    return {
        "alerts_to_catch_all_attacks": alerts_needed,
        "alert_budget_fraction": alerts_needed / max(1, len(test)),
        "incident_recall": len(detected) / max(1, len(incidents)),
    }


def evaluate_demo_seeds(seeds: tuple[int, ...] = (7, 19, 42, 91, 123)) -> tuple[pd.DataFrame, dict]:
    rows: list[dict] = []
    for seed in seeds:
        with tempfile.TemporaryDirectory(prefix="sentinel-ueba-eval-") as directory:
            raw = Path(directory) / "raw"
            generate_demo_logs(raw, seed=seed)
            features = build_generic_feature_table(load_cert_events(raw))
            bundle = train_generic_model(features)
            scored = score_generic_features(features, bundle)
            metrics = evaluate(scored, bundle["split_day"])
            metrics.update(ranking_metrics(scored, bundle["split_day"]))
            metrics["seed"] = seed
            rows.append(metrics)
    per_seed = pd.DataFrame(rows)
    numeric = [
        "precision", "recall", "f1", "pr_auc", "malicious_in_top_10",
        "alerts_to_catch_all_attacks", "alert_budget_fraction", "incident_recall",
        "baseline_precision", "baseline_recall", "baseline_f1",
    ]
    summary = {
        "seeds": list(seeds),
        "runs": len(seeds),
        "mean": {column: float(per_seed[column].mean()) for column in numeric},
        "std": {column: float(per_seed[column].std(ddof=0)) for column in numeric},
        "minimum": {column: float(per_seed[column].min()) for column in numeric},
        "maximum": {column: float(per_seed[column].max()) for column in numeric},
    }
    return per_seed, summary
