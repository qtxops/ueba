"""SQLite persistence for events, model runs, scores, alerts, and cases."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from .event_schema import EVENT_COLUMNS


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS events (
    source_dataset TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_time TEXT NOT NULL,
    user_id TEXT NOT NULL,
    group_name TEXT,
    event_kind TEXT,
    action TEXT,
    source_ip TEXT,
    device TEXT,
    resource TEXT,
    port REAL,
    vlan REAL,
    status TEXT,
    bytes REAL,
    is_removable INTEGER,
    is_sensitive INTEGER,
    is_executable INTEGER,
    is_malicious INTEGER,
    scenario TEXT,
    provided_risk REAL,
    PRIMARY KEY (source_dataset, event_id)
);

CREATE INDEX IF NOT EXISTS idx_events_user_time ON events(user_id, event_time);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(event_time);

CREATE TABLE IF NOT EXISTS model_runs (
    model_version TEXT PRIMARY KEY,
    source_dataset TEXT NOT NULL,
    trained_at TEXT NOT NULL,
    split_day TEXT NOT NULL,
    train_rows INTEGER NOT NULL,
    feature_columns_json TEXT NOT NULL,
    metrics_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entity_scores (
    source_dataset TEXT NOT NULL,
    user_id TEXT NOT NULL,
    score_day TEXT NOT NULL,
    model_version TEXT NOT NULL,
    ml_risk_score INTEGER NOT NULL,
    rule_score INTEGER NOT NULL,
    case_priority_score INTEGER NOT NULL,
    ml_explanation TEXT NOT NULL,
    rule_explanation TEXT NOT NULL,
    is_malicious INTEGER NOT NULL DEFAULT 0,
    scenario TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (source_dataset, user_id, score_day, model_version),
    FOREIGN KEY (model_version) REFERENCES model_runs(model_version)
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_dataset TEXT NOT NULL,
    user_id TEXT NOT NULL,
    score_day TEXT NOT NULL,
    model_version TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    score INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    UNIQUE (source_dataset, user_id, score_day, model_version, alert_type)
);

CREATE TABLE IF NOT EXISTS cases (
    case_id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    user_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    disposition TEXT,
    analyst_notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_alerts (
    case_id INTEGER NOT NULL,
    alert_id INTEGER NOT NULL,
    PRIMARY KEY (case_id, alert_id),
    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
);

CREATE TABLE IF NOT EXISTS analyst_feedback (
    feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    analyst TEXT NOT NULL DEFAULT '',
    comment TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
);

CREATE TABLE IF NOT EXISTS ingestion_runs (
    ingestion_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_dataset TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    received_events INTEGER NOT NULL,
    inserted_events INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS detection_policies (
    source_dataset TEXT PRIMARY KEY,
    ml_threshold INTEGER NOT NULL DEFAULT 70,
    rule_threshold INTEGER NOT NULL DEFAULT 70,
    rule_enabled INTEGER NOT NULL DEFAULT 1,
    correlation_window_days INTEGER NOT NULL DEFAULT 3,
    review_budget_fraction REAL NOT NULL DEFAULT 0.02,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_dataset TEXT NOT NULL,
    user_id TEXT NOT NULL,
    start_day TEXT NOT NULL,
    end_day TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    priority_score INTEGER NOT NULL DEFAULT 0,
    ml_peak INTEGER NOT NULL DEFAULT 0,
    rule_peak INTEGER NOT NULL DEFAULT 0,
    alert_count INTEGER NOT NULL DEFAULT 0,
    distinct_days INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_queue
ON incidents(status, priority_score DESC, end_day DESC);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id INTEGER NOT NULL,
    alert_id INTEGER NOT NULL UNIQUE,
    PRIMARY KEY (incident_id, alert_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
);

CREATE TABLE IF NOT EXISTS suppressions (
    suppression_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_dataset TEXT NOT NULL,
    user_id TEXT NOT NULL DEFAULT '',
    alert_type TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL,
    expires_at TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
"""


def connect_database(path: str | Path) -> sqlite3.Connection:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(target)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    case_columns = {row[1] for row in connection.execute("PRAGMA table_info(cases)").fetchall()}
    if "assigned_to" not in case_columns:
        connection.execute("ALTER TABLE cases ADD COLUMN assigned_to TEXT NOT NULL DEFAULT ''")
        connection.commit()
    return connection


def _clean(value: Any) -> Any:
    if pd.isna(value):
        return None
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if hasattr(value, "item"):
        return value.item()
    return value


def ingest_events(connection: sqlite3.Connection, events: pd.DataFrame) -> int:
    """Idempotently add normalized events and return the inserted row count."""
    before = connection.total_changes
    sql = """
        INSERT OR IGNORE INTO events (
            event_id, event_time, user_id, group_name, event_kind, action, source_ip, device,
            resource, port, vlan, status, bytes, is_removable, is_sensitive, is_executable,
            is_malicious, scenario, provided_risk, source_dataset
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    columns = [
        "event_id", "event_time", "user", "group", "event_kind", "action", "source_ip", "device",
        "resource", "port", "vlan", "status", "bytes", "is_removable", "is_sensitive", "is_executable",
        "is_malicious", "scenario", "provided_risk", "source_dataset",
    ]
    missing = set(EVENT_COLUMNS) - set(events.columns)
    if missing:
        raise ValueError(f"Cannot persist events; canonical columns are missing: {sorted(missing)}")
    connection.executemany(sql, ([ _clean(value) for value in row ] for row in events[columns].itertuples(index=False, name=None)))
    connection.commit()
    return connection.total_changes - before


def clear_source_data(connection: sqlite3.Connection, source_dataset: str) -> None:
    """Replace one source safely without touching other ingested datasets."""
    model_versions = [
        row[0]
        for row in connection.execute(
            "SELECT model_version FROM model_runs WHERE source_dataset = ?", (source_dataset,)
        ).fetchall()
    ]
    alert_ids = [
        row[0]
        for row in connection.execute(
            "SELECT alert_id FROM alerts WHERE source_dataset = ?", (source_dataset,)
        ).fetchall()
    ]
    if alert_ids:
        placeholders = ",".join("?" for _ in alert_ids)
        case_ids = [
            row[0]
            for row in connection.execute(
                f"SELECT DISTINCT case_id FROM case_alerts WHERE alert_id IN ({placeholders})", alert_ids
            ).fetchall()
        ]
        connection.execute(f"DELETE FROM analyst_feedback WHERE alert_id IN ({placeholders})", alert_ids)
        connection.execute(f"DELETE FROM case_alerts WHERE alert_id IN ({placeholders})", alert_ids)
        incident_ids = [
            row[0]
            for row in connection.execute(
                f"SELECT DISTINCT incident_id FROM incident_alerts WHERE alert_id IN ({placeholders})", alert_ids
            ).fetchall()
        ]
        connection.execute(f"DELETE FROM incident_alerts WHERE alert_id IN ({placeholders})", alert_ids)
        if incident_ids:
            incident_placeholders = ",".join("?" for _ in incident_ids)
            connection.execute(f"DELETE FROM incidents WHERE incident_id IN ({incident_placeholders})", incident_ids)
        if case_ids:
            case_placeholders = ",".join("?" for _ in case_ids)
            connection.execute(
                f"DELETE FROM cases WHERE case_id IN ({case_placeholders}) AND NOT EXISTS "
                "(SELECT 1 FROM case_alerts WHERE case_alerts.case_id = cases.case_id)",
                case_ids,
            )
    connection.execute("DELETE FROM alerts WHERE source_dataset = ?", (source_dataset,))
    connection.execute("DELETE FROM entity_scores WHERE source_dataset = ?", (source_dataset,))
    for model_version in model_versions:
        connection.execute("DELETE FROM model_runs WHERE model_version = ?", (model_version,))
    connection.execute("DELETE FROM events WHERE source_dataset = ?", (source_dataset,))
    connection.execute("DELETE FROM detection_policies WHERE source_dataset = ?", (source_dataset,))
    connection.execute("DELETE FROM suppressions WHERE source_dataset = ?", (source_dataset,))
    connection.commit()


def persist_model_run(
    connection: sqlite3.Connection,
    bundle: dict[str, Any],
    scored: pd.DataFrame,
    metrics: dict[str, Any],
    source_dataset: str,
    model_version: str,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    connection.execute(
        """INSERT INTO model_runs VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(model_version) DO UPDATE SET
               trained_at = excluded.trained_at,
               split_day = excluded.split_day,
               train_rows = excluded.train_rows,
               feature_columns_json = excluded.feature_columns_json,
               metrics_json = excluded.metrics_json""",
        (
            model_version,
            source_dataset,
            now,
            str(bundle["split_day"]),
            int(bundle["train_rows"]),
            json.dumps(bundle["feature_columns"]),
            json.dumps(metrics),
        ),
    )
    score_sql = """
        INSERT OR REPLACE INTO entity_scores (
            source_dataset, user_id, score_day, model_version, ml_risk_score, rule_score,
            case_priority_score, ml_explanation, rule_explanation, is_malicious, scenario
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    score_rows = []
    alert_rows = []
    split_day = pd.Timestamp(bundle["split_day"])
    for row in scored.itertuples(index=False):
        day = pd.Timestamp(row.day).date().isoformat()
        score_rows.append((
            source_dataset, str(row.user), day, model_version, int(row.ml_risk_score), int(row.rule_score),
            int(row.case_priority_score), str(row.explanation), str(row.rule_explanation),
            int(row.is_malicious), str(row.scenario),
        ))
        is_operational_period = pd.Timestamp(row.day) >= split_day
        if is_operational_period and int(row.ml_alert):
            alert_rows.append((source_dataset, str(row.user), day, model_version, "ml_anomaly", int(row.ml_risk_score), now))
        if is_operational_period and int(row.rule_alert):
            alert_rows.append((source_dataset, str(row.user), day, model_version, "rule_match", int(row.rule_score), now))
    connection.executemany(score_sql, score_rows)
    connection.executemany(
        """INSERT INTO alerts (
            source_dataset, user_id, score_day, model_version, alert_type, score, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_dataset, user_id, score_day, model_version, alert_type)
        DO UPDATE SET score = excluded.score""",
        alert_rows,
    )
    connection.commit()


def database_summary(connection: sqlite3.Connection) -> dict[str, int]:
    return {
        table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table in ["events", "model_runs", "entity_scores", "alerts", "incidents", "cases", "suppressions"]
    }


def list_alerts(connection: sqlite3.Connection, status: str | None = "open", limit: int = 500) -> pd.DataFrame:
    where = "WHERE a.status = ?" if status else ""
    parameters: tuple[Any, ...] = (status, limit) if status else (limit,)
    return pd.read_sql_query(
        f"""SELECT a.alert_id, a.source_dataset, a.user_id, a.score_day, a.alert_type,
                   a.score, a.status, a.created_at,
                   CASE WHEN ca.case_id IS NULL THEN 0 ELSE ca.case_id END AS case_id
            FROM alerts a
            LEFT JOIN case_alerts ca ON ca.alert_id = a.alert_id
            {where}
            ORDER BY a.score DESC, a.score_day DESC
            LIMIT ?""",
        connection,
        params=parameters,
    )


def create_case(
    connection: sqlite3.Connection,
    alert_ids: list[int],
    title: str,
    assigned_to: str = "",
) -> int:
    if not alert_ids:
        raise ValueError("Select at least one alert")
    placeholders = ",".join("?" for _ in alert_ids)
    alerts = connection.execute(
        f"SELECT alert_id, user_id FROM alerts WHERE alert_id IN ({placeholders})", alert_ids
    ).fetchall()
    if len(alerts) != len(set(alert_ids)):
        raise ValueError("One or more selected alerts do not exist")
    users = {row["user_id"] for row in alerts}
    if len(users) != 1:
        raise ValueError("A case can contain alerts for only one entity")
    now = datetime.now(timezone.utc).isoformat()
    cursor = connection.execute(
        """INSERT INTO cases (title, user_id, status, disposition, analyst_notes, created_at, updated_at, assigned_to)
           VALUES (?, ?, 'open', NULL, '', ?, ?, ?)""",
        (title.strip() or f"Investigation for {next(iter(users))}", next(iter(users)), now, now, assigned_to.strip()),
    )
    case_id = int(cursor.lastrowid)
    connection.executemany(
        "INSERT INTO case_alerts (case_id, alert_id) VALUES (?, ?)",
        [(case_id, alert_id) for alert_id in set(alert_ids)],
    )
    connection.executemany(
        "UPDATE alerts SET status = 'in_case' WHERE alert_id = ?",
        [(alert_id,) for alert_id in set(alert_ids)],
    )
    connection.commit()
    return case_id


def list_cases(connection: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query(
        """SELECT c.case_id, c.title, c.user_id, c.status, c.assigned_to, c.disposition,
                  c.updated_at, COUNT(ca.alert_id) AS alert_count, COALESCE(MAX(a.score), 0) AS highest_score
           FROM cases c
           LEFT JOIN case_alerts ca ON ca.case_id = c.case_id
           LEFT JOIN alerts a ON a.alert_id = ca.alert_id
           GROUP BY c.case_id
           ORDER BY CASE c.status WHEN 'open' THEN 0 WHEN 'investigating' THEN 1 ELSE 2 END,
                    highest_score DESC, c.updated_at DESC""",
        connection,
    )


def get_case(connection: sqlite3.Connection, case_id: int) -> tuple[dict[str, Any], pd.DataFrame, pd.DataFrame]:
    case = connection.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    if case is None:
        raise ValueError(f"Case {case_id} does not exist")
    alerts = pd.read_sql_query(
        """SELECT a.* FROM alerts a JOIN case_alerts ca ON ca.alert_id = a.alert_id
           WHERE ca.case_id = ? ORDER BY a.score DESC""",
        connection,
        params=(case_id,),
    )
    feedback = pd.read_sql_query(
        """SELECT f.* FROM analyst_feedback f JOIN case_alerts ca ON ca.alert_id = f.alert_id
           WHERE ca.case_id = ? ORDER BY f.created_at DESC""",
        connection,
        params=(case_id,),
    )
    return dict(case), alerts, feedback


def update_case(
    connection: sqlite3.Connection,
    case_id: int,
    status: str,
    assigned_to: str,
    disposition: str,
    analyst_notes: str,
) -> None:
    if status not in {"open", "investigating", "resolved", "closed"}:
        raise ValueError("Invalid case status")
    allowed_dispositions = {"", "confirmed_threat", "false_positive", "benign_expected", "inconclusive"}
    if disposition not in allowed_dispositions:
        raise ValueError("Invalid case disposition")
    now = datetime.now(timezone.utc).isoformat()
    cursor = connection.execute(
        """UPDATE cases SET status = ?, assigned_to = ?, disposition = ?, analyst_notes = ?, updated_at = ?
           WHERE case_id = ?""",
        (status, assigned_to.strip(), disposition or None, analyst_notes, now, case_id),
    )
    if cursor.rowcount != 1:
        raise ValueError(f"Case {case_id} does not exist")
    if status in {"resolved", "closed"}:
        connection.execute(
            """UPDATE alerts SET status = 'closed' WHERE alert_id IN
               (SELECT alert_id FROM case_alerts WHERE case_id = ?)""",
            (case_id,),
        )
    connection.commit()


def record_feedback(
    connection: sqlite3.Connection,
    alert_id: int,
    verdict: str,
    analyst: str = "",
    comment: str = "",
) -> None:
    if verdict not in {"confirmed_threat", "false_positive", "benign_expected", "needs_more_information"}:
        raise ValueError("Invalid analyst verdict")
    exists = connection.execute("SELECT 1 FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if exists is None:
        raise ValueError(f"Alert {alert_id} does not exist")
    now = datetime.now(timezone.utc).isoformat()
    connection.execute(
        "INSERT INTO analyst_feedback (alert_id, verdict, analyst, comment, created_at) VALUES (?, ?, ?, ?, ?)",
        (alert_id, verdict, analyst.strip(), comment, now),
    )
    if verdict in {"false_positive", "benign_expected"}:
        connection.execute("UPDATE alerts SET status = 'dismissed' WHERE alert_id = ?", (alert_id,))
    elif verdict == "confirmed_threat":
        connection.execute("UPDATE alerts SET status = 'confirmed' WHERE alert_id = ?", (alert_id,))
    connection.commit()


def begin_ingestion(connection: sqlite3.Connection, source_dataset: str, received_events: int) -> int:
    cursor = connection.execute(
        """INSERT INTO ingestion_runs (source_dataset, started_at, received_events, status)
           VALUES (?, ?, ?, 'running')""",
        (source_dataset, datetime.now(timezone.utc).isoformat(), received_events),
    )
    connection.commit()
    return int(cursor.lastrowid)


def finish_ingestion(
    connection: sqlite3.Connection,
    ingestion_id: int,
    inserted_events: int,
    status: str = "completed",
    message: str = "",
) -> None:
    connection.execute(
        """UPDATE ingestion_runs SET completed_at = ?, inserted_events = ?, status = ?, message = ?
           WHERE ingestion_id = ?""",
        (datetime.now(timezone.utc).isoformat(), inserted_events, status, message, ingestion_id),
    )
    connection.commit()
