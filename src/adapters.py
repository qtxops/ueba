"""Adapters from public UEBA datasets into a common event schema."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


NORMALIZED_EVENT_COLUMNS = [
    "event_time",
    "user",
    "group",
    "action",
    "source_ip",
    "resource",
    "port",
    "vlan",
    "device",
    "status",
    "is_malicious",
    "provided_risk",
    "source_dataset",
]


def _validate(frame: pd.DataFrame, required: set[str], source: Path) -> None:
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"{source.name} is missing required columns: {sorted(missing)}")


def _finalize(frame: pd.DataFrame) -> pd.DataFrame:
    result = frame.copy()
    result["event_time"] = pd.to_datetime(result["event_time"], errors="coerce")
    result = result.dropna(subset=["event_time", "user"])
    for column in ["user", "group", "action", "source_ip", "resource", "device", "status", "source_dataset"]:
        result[column] = result[column].fillna("").astype(str)
    for column in ["port", "vlan", "is_malicious", "provided_risk"]:
        result[column] = pd.to_numeric(result[column], errors="coerce")
    result["port"] = result["port"].fillna(0)
    result["vlan"] = result["vlan"].fillna(0)
    result["is_malicious"] = result["is_malicious"].fillna(0).astype(int)
    return result[NORMALIZED_EVENT_COLUMNS].sort_values("event_time").reset_index(drop=True)


def load_game_admin_events(csv_path: str | Path) -> pd.DataFrame:
    source = Path(csv_path)
    raw = pd.read_csv(source)
    _validate(raw, {"timestamp", "admin_id", "action", "ip_address", "status", "is_attack"}, source)
    normalized = pd.DataFrame(
        {
            "event_time": raw["timestamp"],
            "user": raw["admin_id"],
            "group": "game_administrators",
            "action": raw["action"],
            "source_ip": raw["ip_address"],
            "resource": raw["action"],
            "port": 0,
            "vlan": 0,
            "device": raw["ip_address"],
            "status": raw["status"],
            "is_malicious": raw["is_attack"],
            "provided_risk": np.nan,
            "source_dataset": "game_admin",
        }
    )
    return _finalize(normalized)


def load_network_events(csv_path: str | Path, has_target: bool = True) -> pd.DataFrame:
    source = Path(csv_path)
    # The source is GB18030. Reading it as UTF-8 corrupts the department names.
    raw = pd.read_csv(source, encoding="gb18030")
    required = {"account", "group", "IP", "url", "port", "vlan", "switchIP", "time"}
    if has_target:
        required.add("ret")
    _validate(raw, required, source)
    normalized = pd.DataFrame(
        {
            "event_time": raw["time"],
            "user": raw["account"],
            "group": raw["group"],
            "action": "web_access",
            "source_ip": raw["IP"],
            "resource": raw["url"],
            "port": raw["port"],
            "vlan": raw["vlan"],
            "device": raw["switchIP"],
            "status": "Success",
            "is_malicious": 0,
            "provided_risk": raw["ret"] if has_target else np.nan,
            "source_dataset": "network_access",
        }
    )
    return _finalize(normalized)

