#!/usr/bin/env python3
"""Incrementally ingest and score a directory of CERT-style CSV logs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.adapters import load_cert_events  # noqa: E402
from src.engine import process_event_batch  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--source", required=True, help="Stable source name used for deduplication and model reuse")
    parser.add_argument("--database", type=Path, default=ROOT / "artifacts" / "sentinel_ueba.db")
    parser.add_argument("--artifact-dir", type=Path, default=ROOT / "artifacts" / "live")
    parser.add_argument("--retrain", action="store_true")
    args = parser.parse_args()

    events = load_cert_events(args.raw_dir)
    events["source_dataset"] = args.source
    result = process_event_batch(events, args.database, args.artifact_dir, retrain=args.retrain)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
