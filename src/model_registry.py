"""Candidate, promotion, and rollback lifecycle for anomaly models."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from .engine import _safe_name, load_source_events, process_event_batch
from .generic_features import build_generic_feature_table
from .generic_modeling import score_generic_features, train_generic_model
from .modeling import evaluate, save_bundle
from .storage import connect_database


def _metrics(scored: pd.DataFrame, split_day: Any) -> dict[str, Any]:
    if scored["is_malicious"].nunique() > 1:
        return evaluate(scored, split_day)
    return {
        "split_day": pd.Timestamp(split_day).date().isoformat(),
        "alerts": int(scored["ml_alert"].sum()),
        "rule_alerts": int(scored["rule_alert"].sum()),
        "note": "No usable binary labels; ranking metrics were not calculated",
    }


def build_candidate(database_path: Path, artifact_dir: Path, source_dataset: str) -> dict[str, Any]:
    with connect_database(database_path) as connection:
        history = load_source_events(connection, source_dataset)
    if history.empty:
        raise ValueError("Source has no stored events")
    features = build_generic_feature_table(history)
    bundle = train_generic_model(features)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    version = f"{_safe_name(source_dataset)}-{stamp}"
    bundle["model_version"] = version
    bundle["source_dataset"] = source_dataset
    scored = score_generic_features(features, bundle)
    metrics = _metrics(scored, bundle["split_day"])
    candidate_dir = Path(artifact_dir) / "candidates" / _safe_name(source_dataset)
    candidate_dir.mkdir(parents=True, exist_ok=True)
    path = candidate_dir / f"{version}.joblib"
    save_bundle(bundle, path)
    with connect_database(database_path) as connection:
        connection.execute(
            """INSERT INTO model_registry (
                   model_version, source_dataset, status, artifact_path, metrics_json, created_at
               ) VALUES (?, ?, 'candidate', ?, ?, ?)""",
            (version, source_dataset, str(path), json.dumps(metrics), datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()
    return {"model_version": version, "source_dataset": source_dataset, "status": "candidate", "metrics": metrics}


def promote_model(
    database_path: Path,
    artifact_dir: Path,
    model_version: str,
    promoted_by: str,
) -> dict[str, Any]:
    with connect_database(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM model_registry WHERE model_version = ?", (model_version,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Model {model_version} does not exist")
        record = dict(row)
    candidate_path = Path(record["artifact_path"])
    if not candidate_path.exists():
        raise ValueError(f"Artifact for {model_version} is missing")
    active_path = Path(artifact_dir) / f"{_safe_name(record['source_dataset'])}_active_model.joblib"
    active_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = active_path.with_suffix(".promotion-backup.joblib")
    had_active = active_path.exists()
    if had_active:
        shutil.copy2(active_path, backup_path)
    try:
        shutil.copy2(candidate_path, active_path)
        with connect_database(database_path) as connection:
            history = load_source_events(connection, record["source_dataset"])
        result = process_event_batch(
            history, database_path, artifact_dir, retrain=False, force_rescore=True
        )
    except Exception:
        if had_active and backup_path.exists():
            shutil.copy2(backup_path, active_path)
        elif active_path.exists():
            active_path.unlink()
        raise
    finally:
        if backup_path.exists():
            backup_path.unlink()
    now = datetime.now(timezone.utc).isoformat()
    with connect_database(database_path) as connection:
        connection.execute(
            "UPDATE model_registry SET status = 'archived' WHERE source_dataset = ? AND status = 'active'",
            (record["source_dataset"],),
        )
        connection.execute(
            """UPDATE model_registry SET status = 'active', promoted_at = ?, promoted_by = ?
               WHERE model_version = ?""",
            (now, promoted_by, model_version),
        )
        connection.commit()
    return {**result, "promoted_model": model_version}


def list_models(database_path: Path, source_dataset: str | None = None) -> list[dict[str, Any]]:
    with connect_database(database_path) as connection:
        if source_dataset:
            rows = connection.execute(
                "SELECT * FROM model_registry WHERE source_dataset = ? ORDER BY created_at DESC",
                (source_dataset,),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM model_registry ORDER BY created_at DESC"
            ).fetchall()
    models = []
    for row in rows:
        model = dict(row)
        model["metrics"] = json.loads(model.pop("metrics_json"))
        models.append(model)
    return models
