"""End-to-end workflow used by scripts and the dashboard."""

from __future__ import annotations

import json
from pathlib import Path

from .adapters import load_cert_events
from .demo_data import generate_demo_logs
from .generic_features import build_generic_feature_table
from .generic_modeling import score_generic_features, train_generic_model
from .incidents import apply_policy, correlate_alerts, ensure_policy
from .modeling import evaluate, save_bundle
from .storage import clear_source_data, connect_database, database_summary, ingest_events, persist_model_run


def run_workflow(raw_dir: str | Path, output_dir: str | Path, replace_source: bool = False) -> dict:
    raw = Path(raw_dir)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    events = load_cert_events(raw)
    features = build_generic_feature_table(events)
    bundle = train_generic_model(features)
    scored = score_generic_features(features, bundle)
    metrics = evaluate(scored, bundle["split_day"])

    source_dataset = str(events["source_dataset"].iloc[0])
    model_version = f"{source_dataset}-{metrics['split_day']}-core-v2"
    with connect_database(output / "sentinel_ueba.db") as connection:
        if replace_source:
            clear_source_data(connection, source_dataset)
        inserted = ingest_events(connection, events)
        persist_model_run(connection, bundle, scored, metrics, source_dataset, model_version)
        ensure_policy(connection, source_dataset)
        metrics["policy_alerts"] = apply_policy(connection, source_dataset)
        metrics["incident_operations"] = correlate_alerts(connection)
        metrics["database"] = database_summary(connection)
        metrics["new_events_ingested"] = inserted
        metrics["model_version"] = model_version

    events.to_csv(output / "normalized_events.csv", index=False)
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
    database = artifacts / "sentinel_ueba.db"
    if force or not expected.exists() or not database.exists():
        generate_demo_logs(raw)
        return run_workflow(raw, artifacts, replace_source=force)
    metrics_path = artifacts / "metrics.json"
    return json.loads(metrics_path.read_text(encoding="utf-8"))
