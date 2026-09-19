"""End-to-end workflow used by scripts and the dashboard."""

from __future__ import annotations

import json
from pathlib import Path

from .demo_data import generate_demo_logs
from .features import build_feature_table
from .modeling import evaluate, save_bundle, score_features, train_model


def run_workflow(raw_dir: str | Path, output_dir: str | Path) -> dict:
    raw = Path(raw_dir)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    features = build_feature_table(raw)
    bundle = train_model(features)
    scored = score_features(features, bundle)
    metrics = evaluate(scored, bundle["split_day"])

    features.to_csv(output / "features.csv", index=False)
    scored.to_csv(output / "scored_activity.csv", index=False)
    save_bundle(bundle, output / "isolation_forest.joblib")
    (output / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def bootstrap_demo(project_root: str | Path, force: bool = False) -> dict:
    root = Path(project_root)
    raw = root / "data" / "demo" / "raw"
    artifacts = root / "artifacts"
    expected = artifacts / "scored_activity.csv"
    if force or not expected.exists():
        generate_demo_logs(raw)
        return run_workflow(raw, artifacts)
    metrics_path = artifacts / "metrics.json"
    return json.loads(metrics_path.read_text(encoding="utf-8"))

