"""Canonical event contract used by every SentinelUEBA data source."""

from __future__ import annotations

import hashlib

import numpy as np
import pandas as pd


EVENT_COLUMNS = [
    "event_id",
    "event_time",
    "user",
    "group",
    "event_kind",
    "action",
    "source_ip",
    "device",
    "resource",
    "port",
    "vlan",
    "status",
    "bytes",
    "is_removable",
    "is_sensitive",
    "is_executable",
    "is_malicious",
    "scenario",
    "provided_risk",
    "source_dataset",
]

STRING_COLUMNS = [
    "event_id",
    "user",
    "group",
    "event_kind",
    "action",
    "source_ip",
    "device",
    "resource",
    "status",
    "scenario",
    "source_dataset",
]

NUMERIC_COLUMNS = [
    "port",
    "vlan",
    "bytes",
    "is_removable",
    "is_sensitive",
    "is_executable",
    "is_malicious",
    "provided_risk",
]


def _stable_event_id(row: pd.Series) -> str:
    payload = "|".join(
        str(row.get(column, ""))
        for column in ["source_dataset", "event_time", "user", "event_kind", "action", "device", "resource"]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def normalize_events(frame: pd.DataFrame) -> pd.DataFrame:
    """Validate, type, deduplicate, and order events from any adapter."""
    result = frame.copy()
    for column in EVENT_COLUMNS:
        if column not in result:
            result[column] = np.nan if column in NUMERIC_COLUMNS else ""

    result["event_time"] = pd.to_datetime(result["event_time"], errors="coerce", utc=True).dt.tz_localize(None)
    result = result.dropna(subset=["event_time", "user"])
    for column in STRING_COLUMNS:
        result[column] = result[column].fillna("").astype(str).str.strip()
    result = result[result["user"].ne("")]
    for column in NUMERIC_COLUMNS:
        result[column] = pd.to_numeric(result[column], errors="coerce")
    for column in ["port", "vlan", "bytes", "is_removable", "is_sensitive", "is_executable", "is_malicious"]:
        result[column] = result[column].fillna(0)
    for column in ["is_removable", "is_sensitive", "is_executable", "is_malicious"]:
        result[column] = result[column].clip(0, 1).astype(int)
    result["bytes"] = result["bytes"].clip(lower=0)

    missing_ids = result["event_id"].eq("")
    if missing_ids.any():
        result.loc[missing_ids, "event_id"] = result.loc[missing_ids].apply(_stable_event_id, axis=1)
    result = result.drop_duplicates(subset=["source_dataset", "event_id"], keep="first")
    return result[EVENT_COLUMNS].sort_values(["event_time", "user", "event_id"]).reset_index(drop=True)
