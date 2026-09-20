"""Incremental ingestion and automatic rescoring for SentinelUEBA."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from .event_schema import normalize_events
from .generic_features import build_generic_feature_table
from .generic_modeling import score_generic_features, train_generic_model
from .incidents import apply_policy, correlate_alerts, ensure_policy
from .modeling import evaluate, load_bundle, save_bundle
from .storage import begin_ingestion, connect_database, finish_ingestion, ingest_events, persist_model_run


def _safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("_") or "events"


def load_source_events(connection, source_dataset: str) -> pd.DataFrame:
    frame = pd.read_sql_query(
        """SELECT event_id, event_time, user_id AS user, group_name AS `group`, event_kind,
                  action, source_ip, device, resource, port, vlan, status, bytes,
                  is_removable, is_sensitive, is_executable, is_malicious, scenario,
                  provided_risk, source_dataset
           FROM events WHERE source_dataset = ? ORDER BY event_time""",
        connection,
        params=(source_dataset,),
    )
    return normalize_events(frame)


def process_event_batch(
    events: pd.DataFrame,
    database_path: str | Path,
    artifact_dir: str | Path,
    retrain: bool = False,
    force_rescore: bool = False,
) -> dict[str, Any]:
    """Persist new events and automatically score the affected source.

    Duplicate source/event IDs are ignored. The current model is reused unless
    retraining is requested or no model has been registered for this source.
    """
    normalized = normalize_events(events)
    sources = normalized["source_dataset"].dropna().unique()
    if len(sources) != 1:
        raise ValueError("Each incremental batch must contain exactly one source_dataset")
    source_dataset = str(sources[0])
    output = Path(artifact_dir)
    output.mkdir(parents=True, exist_ok=True)
    model_path = output / f"{_safe_name(source_dataset)}_active_model.joblib"

    with connect_database(database_path) as connection:
        ingestion_id = begin_ingestion(connection, source_dataset, len(normalized))
        try:
            inserted = ingest_events(connection, normalized)
            if inserted == 0 and not retrain and not force_rescore:
                finish_ingestion(connection, ingestion_id, 0, message="All received events were duplicates")
                return {
                    "ingestion_id": ingestion_id,
                    "source_dataset": source_dataset,
                    "received_events": len(normalized),
                    "inserted_events": 0,
                    "status": "completed",
                    "rescored": False,
                }

            history = load_source_events(connection, source_dataset)
            features = build_generic_feature_table(history)
            trained_now = retrain or not model_path.exists()
            if trained_now:
                bundle = train_generic_model(features)
                trained_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                bundle["model_version"] = f"{_safe_name(source_dataset)}-{trained_stamp}"
                bundle["source_dataset"] = source_dataset
                save_bundle(bundle, model_path)
            else:
                bundle = load_bundle(model_path)
            model_version = bundle.get(
                "model_version", f"{_safe_name(source_dataset)}-{pd.Timestamp(bundle['split_day']).date()}-active"
            )
            scored = score_generic_features(features, bundle)
            if scored["is_malicious"].nunique() > 1:
                metrics: dict[str, Any] = evaluate(scored, bundle["split_day"])
            else:
                metrics = {
                    "split_day": pd.Timestamp(bundle["split_day"]).date().isoformat(),
                    "alerts": int(scored["ml_alert"].sum()),
                    "rule_alerts": int(scored["rule_alert"].sum()),
                    "note": "No usable binary labels; ranking metrics were not calculated",
                }
            persist_model_run(connection, bundle, scored, metrics, source_dataset, model_version)
            ensure_policy(connection, source_dataset)
            policy_result = apply_policy(connection, source_dataset)
            incident_result = correlate_alerts(connection)
            latest_path = output / f"{_safe_name(source_dataset)}_latest_scores.csv"
            scored.to_csv(latest_path, index=False)
            finish_ingestion(connection, ingestion_id, inserted)
            return {
                "ingestion_id": ingestion_id,
                "source_dataset": source_dataset,
                "received_events": len(normalized),
                "inserted_events": inserted,
                "stored_events": len(history),
                "scored_user_days": len(scored),
                "ml_alerts": int(scored["ml_alert"].sum()),
                "rule_alerts": int(scored["rule_alert"].sum()),
                "policy_open_ml_alerts": policy_result["open_ml_alerts"],
                "policy_open_rule_alerts": policy_result["open_rule_alerts"],
                "open_incidents": incident_result["open_incidents"],
                "alert_to_incident_ratio": incident_result["compression_ratio"],
                "model_version": model_version,
                "model_retrained": trained_now,
                "status": "completed",
                "scores_path": str(latest_path),
            }
        except Exception as exc:
            finish_ingestion(connection, ingestion_id, 0, status="failed", message=str(exc))
            raise
