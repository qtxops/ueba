#!/usr/bin/env python3
"""Calibrate source policies and correlate raw alerts into incidents."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.incidents import apply_policy, correlate_alerts, ensure_policy, list_policies  # noqa: E402
from src.storage import connect_database  # noqa: E402


def main() -> None:
    database = ROOT / "artifacts" / "sentinel_ueba.db"
    with connect_database(database) as connection:
        sources = [row[0] for row in connection.execute("SELECT DISTINCT source_dataset FROM model_runs")]
        applied = {}
        for source in sources:
            ensure_policy(connection, source)
            applied[source] = apply_policy(connection, source)
        correlation = correlate_alerts(connection)
        policies = list_policies(connection).to_dict(orient="records")
    print(json.dumps({"policies": policies, "applied": applied, "correlation": correlation}, indent=2))


if __name__ == "__main__":
    main()
