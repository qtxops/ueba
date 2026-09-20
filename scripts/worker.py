#!/usr/bin/env python3
"""Periodically reconcile detection policy and incident state."""

from __future__ import annotations

import argparse
import json
import signal
import time
from datetime import datetime, timezone
from pathlib import Path

from src.incidents import apply_policy, correlate_alerts
from src.service_config import ServiceSettings
from src.storage import connect_database


running = True


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stop_worker(*_args) -> None:
    global running
    running = False


def run_once(database_path: Path) -> dict:
    with connect_database(database_path) as connection:
        started_at = utc_now()
        cursor = connection.execute(
            "INSERT INTO job_runs (job_name, status, started_at) VALUES ('reconcile', 'running', ?)",
            (started_at,),
        )
        job_id = int(cursor.lastrowid)
        connection.commit()
        try:
            sources = [
                row[0] for row in connection.execute(
                    "SELECT source_dataset FROM detection_policies ORDER BY source_dataset"
                ).fetchall()
            ]
            policy_results = {source: apply_policy(connection, source) for source in sources}
            incidents = correlate_alerts(connection)
            result = {"sources": policy_results, "incidents": incidents}
            connection.execute(
                "UPDATE job_runs SET status = 'completed', details_json = ?, completed_at = ? WHERE job_id = ?",
                (json.dumps(result), utc_now(), job_id),
            )
            connection.commit()
            return {"job_id": job_id, **result}
        except Exception as exc:
            connection.execute(
                "UPDATE job_runs SET status = 'failed', details_json = ?, completed_at = ? WHERE job_id = ?",
                (json.dumps({"error": str(exc)}), utc_now(), job_id),
            )
            connection.commit()
            raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=None)
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.interval < 5 and not args.once:
        parser.error("--interval must be at least five seconds")
    settings = ServiceSettings.from_environment()
    database_path = args.database or settings.database_path
    signal.signal(signal.SIGTERM, stop_worker)
    signal.signal(signal.SIGINT, stop_worker)
    while running:
        print(json.dumps(run_once(database_path), default=str), flush=True)
        if args.once:
            break
        deadline = time.monotonic() + args.interval
        while running and time.monotonic() < deadline:
            time.sleep(min(1, max(0, deadline - time.monotonic())))


if __name__ == "__main__":
    main()
