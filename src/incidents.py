"""Detection policies, alert correlation, incidents, and suppressions."""

from __future__ import annotations

import math
import sqlite3
from datetime import date, datetime, timedelta, timezone
from typing import Any

import pandas as pd

from .storage import create_case


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def calibrate_policy(
    connection: sqlite3.Connection,
    source_dataset: str,
    review_budget_fraction: float,
    rule_enabled: bool = True,
    rule_threshold: int = 70,
    correlation_window_days: int = 3,
) -> dict[str, Any]:
    """Set an ML threshold from an explicit historical review budget."""
    if not 0 < review_budget_fraction <= 1:
        raise ValueError("Review budget must be greater than 0 and at most 1")
    if not 1 <= correlation_window_days <= 30:
        raise ValueError("Correlation window must be between 1 and 30 days")
    latest = connection.execute(
        """SELECT model_version FROM model_runs WHERE source_dataset = ?
           ORDER BY trained_at DESC LIMIT 1""",
        (source_dataset,),
    ).fetchone()
    if latest is None:
        raise ValueError(f"No model run exists for {source_dataset}")
    model_version = latest["model_version"]
    split_day = connection.execute(
        "SELECT split_day FROM model_runs WHERE model_version = ?", (model_version,)
    ).fetchone()["split_day"][:10]
    scores = pd.read_sql_query(
        """SELECT score_day, ml_risk_score, rule_score, is_malicious FROM entity_scores
           WHERE source_dataset = ? AND model_version = ?""",
        connection,
        params=(source_dataset, model_version),
    )
    if scores.empty:
        raise ValueError(f"No entity scores exist for {source_dataset}")
    baseline = scores[scores["score_day"] < split_day]
    if baseline.empty:
        raise ValueError(f"No pre-split baseline scores exist for {source_dataset}")
    budget_rows = max(1, math.ceil(len(baseline) * review_budget_fraction))
    ml_threshold = int(baseline["ml_risk_score"].nlargest(budget_rows).min())
    ml_threshold = max(1, min(100, ml_threshold))
    connection.execute(
        """INSERT INTO detection_policies (
               source_dataset, ml_threshold, rule_threshold, rule_enabled,
               correlation_window_days, review_budget_fraction, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(source_dataset) DO UPDATE SET
               ml_threshold = excluded.ml_threshold,
               rule_threshold = excluded.rule_threshold,
               rule_enabled = excluded.rule_enabled,
               correlation_window_days = excluded.correlation_window_days,
               review_budget_fraction = excluded.review_budget_fraction,
               updated_at = excluded.updated_at""",
        (
            source_dataset, ml_threshold, int(rule_threshold), int(rule_enabled),
            correlation_window_days, review_budget_fraction, _now(),
        ),
    )
    connection.commit()
    evaluation = scores[scores["score_day"] >= split_day]
    predicted = evaluation["ml_risk_score"].ge(ml_threshold)
    result: dict[str, Any] = {
        "source_dataset": source_dataset,
        "model_version": model_version,
        "ml_threshold": ml_threshold,
        "rule_threshold": int(rule_threshold),
        "rule_enabled": bool(rule_enabled),
        "correlation_window_days": correlation_window_days,
        "target_review_budget": review_budget_fraction,
        "historical_ml_alerts": int(predicted.sum()),
        "historical_rows": len(evaluation),
        "actual_review_fraction": float(predicted.mean()),
    }
    labels = evaluation["is_malicious"].astype(bool)
    if labels.any() and (~labels).any():
        true_positives = int((predicted & labels).sum())
        result["precision"] = true_positives / max(1, int(predicted.sum()))
        result["recall"] = true_positives / int(labels.sum())
    return result


def list_policies(connection: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query(
        "SELECT * FROM detection_policies ORDER BY source_dataset", connection
    )


def ensure_policy(connection: sqlite3.Connection, source_dataset: str) -> dict[str, Any] | None:
    existing = connection.execute(
        "SELECT 1 FROM detection_policies WHERE source_dataset = ?", (source_dataset,)
    ).fetchone()
    if existing:
        return None
    defaults = {
        "cert_style": (0.05, True, 3),
        "game_admin": (0.10, True, 2),
        "network_access": (0.02, False, 3),
    }
    budget, rule_enabled, window = defaults.get(source_dataset, (0.02, True, 3))
    return calibrate_policy(connection, source_dataset, budget, rule_enabled, 70, window)


def apply_policy(connection: sqlite3.Connection, source_dataset: str) -> dict[str, int]:
    policy = connection.execute(
        "SELECT * FROM detection_policies WHERE source_dataset = ?", (source_dataset,)
    ).fetchone()
    if policy is None:
        raise ValueError(f"No detection policy exists for {source_dataset}")
    latest = connection.execute(
        """SELECT model_version FROM model_runs WHERE source_dataset = ?
           ORDER BY trained_at DESC LIMIT 1""",
        (source_dataset,),
    ).fetchone()
    if latest is None:
        raise ValueError(f"No model run exists for {source_dataset}")
    version = latest["model_version"]
    split_day = connection.execute(
        "SELECT split_day FROM model_runs WHERE model_version = ?", (version,)
    ).fetchone()["split_day"][:10]
    ml_threshold = int(policy["ml_threshold"])
    rule_threshold = int(policy["rule_threshold"])

    connection.execute(
        """UPDATE alerts SET status = 'superseded'
           WHERE source_dataset = ? AND model_version <> ? AND status = 'open'""",
        (source_dataset, version),
    )

    connection.execute(
        """UPDATE alerts SET status = 'below_policy'
           WHERE source_dataset = ? AND model_version = ? AND alert_type = 'ml_anomaly'
             AND score < ? AND status = 'open'""",
        (source_dataset, version, ml_threshold),
    )
    connection.execute(
        """INSERT OR IGNORE INTO alerts (
               source_dataset, user_id, score_day, model_version, alert_type, score, status, created_at
           ) SELECT source_dataset, user_id, score_day, model_version, 'ml_anomaly', ml_risk_score, 'open', ?
             FROM entity_scores
            WHERE source_dataset = ? AND model_version = ? AND score_day >= ? AND ml_risk_score >= ?""",
        (_now(), source_dataset, version, split_day, ml_threshold),
    )
    connection.execute(
        """UPDATE alerts SET status = 'open'
           WHERE source_dataset = ? AND model_version = ? AND alert_type = 'ml_anomaly'
             AND score >= ? AND status = 'below_policy'""",
        (source_dataset, version, ml_threshold),
    )

    if int(policy["rule_enabled"]):
        connection.execute(
            """UPDATE alerts SET status = 'below_policy'
               WHERE source_dataset = ? AND model_version = ? AND alert_type = 'rule_match'
                 AND score < ? AND status = 'open'""",
            (source_dataset, version, rule_threshold),
        )
        connection.execute(
            """INSERT OR IGNORE INTO alerts (
                   source_dataset, user_id, score_day, model_version, alert_type, score, status, created_at
               ) SELECT source_dataset, user_id, score_day, model_version, 'rule_match', rule_score, 'open', ?
                 FROM entity_scores
                WHERE source_dataset = ? AND model_version = ? AND score_day >= ? AND rule_score >= ?""",
            (_now(), source_dataset, version, split_day, rule_threshold),
        )
        connection.execute(
            """UPDATE alerts SET status = 'open'
               WHERE source_dataset = ? AND model_version = ? AND alert_type = 'rule_match'
                 AND score >= ? AND status IN ('below_policy', 'policy_disabled')""",
            (source_dataset, version, rule_threshold),
        )
    else:
        connection.execute(
            """UPDATE alerts SET status = 'policy_disabled'
               WHERE source_dataset = ? AND model_version = ? AND alert_type = 'rule_match'
                 AND status IN ('open', 'below_policy')""",
            (source_dataset, version),
        )
    connection.commit()
    counts = connection.execute(
        """SELECT
               SUM(CASE WHEN alert_type = 'ml_anomaly' AND status = 'open' THEN 1 ELSE 0 END),
               SUM(CASE WHEN alert_type = 'rule_match' AND status = 'open' THEN 1 ELSE 0 END)
           FROM alerts WHERE source_dataset = ? AND model_version = ?""",
        (source_dataset, version),
    ).fetchone()
    return {"open_ml_alerts": int(counts[0] or 0), "open_rule_alerts": int(counts[1] or 0)}


def _refresh_incident(connection: sqlite3.Connection, incident_id: int) -> None:
    alerts = pd.read_sql_query(
        """SELECT a.alert_type, a.score, a.score_day, a.status
           FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.alert_id
           WHERE ia.incident_id = ? AND a.status NOT IN ('suppressed', 'below_policy', 'policy_disabled', 'dismissed')""",
        connection,
        params=(incident_id,),
    )
    if alerts.empty:
        connection.execute(
            "UPDATE incidents SET status = 'filtered', alert_count = 0, updated_at = ? WHERE incident_id = ?",
            (_now(), incident_id),
        )
        return
    ml_peak = int(alerts.loc[alerts["alert_type"].eq("ml_anomaly"), "score"].max()) if (alerts["alert_type"] == "ml_anomaly").any() else 0
    rule_peak = int(alerts.loc[alerts["alert_type"].eq("rule_match"), "score"].max()) if (alerts["alert_type"] == "rule_match").any() else 0
    distinct_days = int(alerts["score_day"].nunique())
    both_signals = ml_peak > 0 and rule_peak > 0
    priority = min(100, max(ml_peak, rule_peak) + min(10, 3 * (distinct_days - 1)) + (5 if both_signals else 0))
    signals = "ML and rule signals" if both_signals else ("ML anomalies" if ml_peak else "rule matches")
    summary = f"{signals} across {distinct_days} day(s); peak ML {ml_peak}, peak rule {rule_peak}"
    connection.execute(
        """UPDATE incidents SET start_day = ?, end_day = ?, priority_score = ?, ml_peak = ?,
                  rule_peak = ?, alert_count = ?, distinct_days = ?, summary = ?, updated_at = ?
                  , status = CASE WHEN status = 'filtered' THEN 'open' ELSE status END
           WHERE incident_id = ?""",
        (
            str(alerts["score_day"].min()), str(alerts["score_day"].max()), priority, ml_peak,
            rule_peak, len(alerts), distinct_days, summary, _now(), incident_id,
        ),
    )


def correlate_alerts(connection: sqlite3.Connection) -> dict[str, int | float]:
    policies = {
        row["source_dataset"]: int(row["correlation_window_days"])
        for row in connection.execute("SELECT * FROM detection_policies").fetchall()
    }
    unlinked = connection.execute(
        """SELECT a.* FROM alerts a
           LEFT JOIN incident_alerts ia ON ia.alert_id = a.alert_id
           WHERE ia.alert_id IS NULL AND a.status = 'open'
             AND NOT EXISTS (
                 SELECT 1 FROM suppressions s
                 WHERE s.active = 1 AND s.source_dataset = a.source_dataset
                   AND (s.user_id = '' OR s.user_id = a.user_id)
                   AND (s.alert_type = '' OR s.alert_type = a.alert_type)
                   AND (s.expires_at IS NULL OR DATE(s.expires_at) >= DATE('now'))
             )
           ORDER BY a.source_dataset, a.user_id, a.score_day, a.alert_id"""
    ).fetchall()
    affected: set[int] = set()
    latest_incident: dict[tuple[str, str], tuple[int, date]] = {}
    for row in connection.execute(
        """SELECT incident_id, source_dataset, user_id, end_day FROM incidents
           WHERE status = 'open' ORDER BY end_day"""
    ).fetchall():
        latest_incident[(row["source_dataset"], row["user_id"])] = (
            int(row["incident_id"]), date.fromisoformat(row["end_day"]),
        )

    created = 0
    for alert in unlinked:
        key = (alert["source_dataset"], alert["user_id"])
        alert_day = date.fromisoformat(alert["score_day"])
        window = policies.get(alert["source_dataset"], 3)
        current = latest_incident.get(key)
        if current and alert_day <= current[1] + timedelta(days=window):
            incident_id = current[0]
        else:
            now = _now()
            cursor = connection.execute(
                """INSERT INTO incidents (
                       source_dataset, user_id, start_day, end_day, status, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, 'open', ?, ?)""",
                (alert["source_dataset"], alert["user_id"], alert["score_day"], alert["score_day"], now, now),
            )
            incident_id = int(cursor.lastrowid)
            created += 1
        connection.execute(
            "INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
            (incident_id, int(alert["alert_id"])),
        )
        latest_incident[key] = (incident_id, max(alert_day, current[1]) if current and current[0] == incident_id else alert_day)
        affected.add(incident_id)
    for incident_id in affected:
        _refresh_incident(connection, incident_id)
    connection.commit()
    metrics = operations_metrics(connection)
    metrics["new_incidents"] = created
    metrics["newly_correlated_alerts"] = len(unlinked)
    return metrics


def list_incidents(connection: sqlite3.Connection, status: str | None = "open") -> pd.DataFrame:
    where = "WHERE status = ?" if status else ""
    params = (status,) if status else ()
    return pd.read_sql_query(
        f"""SELECT * FROM incidents {where}
            ORDER BY priority_score DESC, end_day DESC""",
        connection,
        params=params,
    )


def get_incident(connection: sqlite3.Connection, incident_id: int) -> tuple[dict[str, Any], pd.DataFrame]:
    incident = connection.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if incident is None:
        raise ValueError(f"Incident {incident_id} does not exist")
    alerts = pd.read_sql_query(
        """SELECT a.* FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.alert_id
           WHERE ia.incident_id = ? ORDER BY a.score_day, a.score DESC""",
        connection,
        params=(incident_id,),
    )
    return dict(incident), alerts


def promote_incident_to_case(connection: sqlite3.Connection, incident_id: int, assigned_to: str = "") -> int:
    incident, alerts = get_incident(connection, incident_id)
    eligible = alerts[~alerts["status"].isin(["suppressed", "dismissed", "below_policy", "policy_disabled"])]
    case_id = create_case(
        connection,
        eligible["alert_id"].astype(int).tolist(),
        f"Incident #{incident_id}: {incident['user_id']} behavioral anomaly",
        assigned_to,
    )
    connection.execute("UPDATE incidents SET status = 'in_case', updated_at = ? WHERE incident_id = ?", (_now(), incident_id))
    connection.commit()
    return case_id


def create_suppression(
    connection: sqlite3.Connection,
    source_dataset: str,
    reason: str,
    user_id: str = "",
    alert_type: str = "",
    expires_at: str | None = None,
) -> int:
    if not reason.strip():
        raise ValueError("A suppression reason is required")
    cursor = connection.execute(
        """INSERT INTO suppressions (
               source_dataset, user_id, alert_type, reason, expires_at, active, created_at
           ) VALUES (?, ?, ?, ?, ?, 1, ?)""",
        (source_dataset, user_id.strip(), alert_type.strip(), reason.strip(), expires_at, _now()),
    )
    conditions = ["source_dataset = ?", "status = 'open'"]
    params: list[Any] = [source_dataset]
    if user_id.strip():
        conditions.append("user_id = ?")
        params.append(user_id.strip())
    if alert_type.strip():
        conditions.append("alert_type = ?")
        params.append(alert_type.strip())
    incident_ids = [
        row[0]
        for row in connection.execute(
            f"""SELECT DISTINCT ia.incident_id FROM incident_alerts ia JOIN alerts a ON a.alert_id = ia.alert_id
                 WHERE {' AND '.join('a.' + item if item != "status = 'open'" else "a.status = 'open'" for item in conditions)}""",
            params,
        ).fetchall()
    ]
    connection.execute(f"UPDATE alerts SET status = 'suppressed' WHERE {' AND '.join(conditions)}", params)
    for incident_id in incident_ids:
        _refresh_incident(connection, incident_id)
    connection.commit()
    return int(cursor.lastrowid)


def list_suppressions(connection: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query(
        "SELECT * FROM suppressions ORDER BY active DESC, created_at DESC", connection
    )


def deactivate_suppression(connection: sqlite3.Connection, suppression_id: int) -> None:
    connection.execute("UPDATE suppressions SET active = 0 WHERE suppression_id = ?", (suppression_id,))
    connection.commit()


def operations_metrics(connection: sqlite3.Connection) -> dict[str, int | float]:
    open_alerts = int(connection.execute("SELECT COUNT(*) FROM alerts WHERE status = 'open'").fetchone()[0])
    open_incidents = int(connection.execute("SELECT COUNT(*) FROM incidents WHERE status = 'open'").fetchone()[0])
    suppressed = int(connection.execute("SELECT COUNT(*) FROM alerts WHERE status = 'suppressed'").fetchone()[0])
    return {
        "open_alerts": open_alerts,
        "open_incidents": open_incidents,
        "suppressed_alerts": suppressed,
        "compression_ratio": open_alerts / max(1, open_incidents),
    }
