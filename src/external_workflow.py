"""Build artifacts for the two public Kaggle UEBA datasets."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .adapters import load_game_admin_events, load_network_events
from .generic_features import build_generic_feature_table
from .generic_modeling import score_generic_features, train_generic_model
from .modeling import evaluate, save_bundle


def run_game_admin_workflow(csv_path: str | Path, output_dir: str | Path) -> dict:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    events = load_game_admin_events(csv_path)
    features = build_generic_feature_table(events)
    bundle = train_generic_model(features)
    scored = score_generic_features(features, bundle)
    metrics = evaluate(scored, bundle["split_day"])
    metrics.update({"event_rows": len(events), "users": events["user"].nunique(), "dataset": "game_admin"})
    scored.to_csv(output / "game_admin_scored.csv", index=False)
    save_bundle(bundle, output / "game_admin_model.joblib")
    (output / "game_admin_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def run_network_workflow(csv_path: str | Path, output_dir: str | Path) -> dict:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    events = load_network_events(csv_path, has_target=True)
    features = build_generic_feature_table(events)
    bundle = train_generic_model(features)
    scored = score_generic_features(features, bundle)
    correlation = scored[["risk_score", "provided_risk_mean"]].corr(method="spearman").iloc[0, 1]
    metrics = {
        "dataset": "network_access",
        "event_rows": len(events),
        "user_days": len(scored),
        "users": events["user"].nunique(),
        "groups": events["group"].nunique(),
        "alerts": int(scored["is_alert"].sum()),
        "split_day": pd.Timestamp(bundle["split_day"]).date().isoformat(),
        "risk_ret_spearman": None if pd.isna(correlation) else float(correlation),
        "note": "ret is an undocumented supplied score used only for comparison, not model training",
    }
    scored.to_csv(output / "network_scored.csv", index=False)
    save_bundle(bundle, output / "network_model.joblib")
    (output / "network_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics

