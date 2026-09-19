"""Adapters from public UEBA datasets into a common event schema."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from .event_schema import EVENT_COLUMNS, normalize_events

NORMALIZED_EVENT_COLUMNS = EVENT_COLUMNS


def _validate(frame: pd.DataFrame, required: set[str], source: Path) -> None:
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"{source.name} is missing required columns: {sorted(missing)}")


def load_game_admin_events(csv_path: str | Path) -> pd.DataFrame:
    source = Path(csv_path)
    raw = pd.read_csv(source)
    _validate(raw, {"timestamp", "admin_id", "action", "ip_address", "status", "is_attack"}, source)
    normalized = pd.DataFrame(
        {
            "event_id": raw.index.map(lambda value: f"game-admin-{value}"),
            "event_time": raw["timestamp"],
            "user": raw["admin_id"],
            "group": "game_administrators",
            "event_kind": "admin_action",
            "action": raw["action"],
            "source_ip": raw["ip_address"],
            "resource": raw["action"],
            "port": 0,
            "vlan": 0,
            "device": raw["ip_address"],
            "status": raw["status"],
            "bytes": 0,
            "is_removable": 0,
            "is_sensitive": 0,
            "is_executable": 0,
            "is_malicious": raw["is_attack"],
            "scenario": np.where(raw["is_attack"].astype(bool), "labeled administrator attack", ""),
            "provided_risk": np.nan,
            "source_dataset": "game_admin",
        }
    )
    return normalize_events(normalized)


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
            "event_id": raw["id"].astype(str) if "id" in raw else raw.index.map(lambda value: f"network-{value}"),
            "event_time": raw["time"],
            "user": raw["account"],
            "group": raw["group"],
            "event_kind": "network_access",
            "action": "web_access",
            "source_ip": raw["IP"],
            "resource": raw["url"],
            "port": raw["port"],
            "vlan": raw["vlan"],
            "device": raw["switchIP"],
            "status": "Success",
            "bytes": 0,
            "is_removable": 0,
            "is_sensitive": 0,
            "is_executable": 0,
            "is_malicious": 0,
            "scenario": "",
            "provided_risk": raw["ret"] if has_target else np.nan,
            "source_dataset": "network_access",
        }
    )
    return normalize_events(normalized)


def _read_cert_file(path: Path, required: set[str]) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=sorted(required))
    frame = pd.read_csv(path).drop_duplicates()
    _validate(frame, required, path)
    return frame


def load_cert_events(raw_dir: str | Path) -> pd.DataFrame:
    """Adapt CERT-style login, device, and file logs to the common event contract."""
    raw = Path(raw_dir)
    logon = _read_cert_file(raw / "logon.csv", {"date", "user", "pc", "activity"})
    device = _read_cert_file(raw / "device.csv", {"date", "user", "pc", "activity"})
    files = _read_cert_file(raw / "file.csv", {"date", "user", "pc", "filename", "activity"})
    admin = _read_cert_file(raw / "admin.csv", {"date", "user", "pc", "action", "status", "resource"})
    parts: list[pd.DataFrame] = []

    if not logon.empty:
        parts.append(pd.DataFrame({
            "event_id": logon["id"].astype(str) if "id" in logon else "",
            "event_time": logon["date"], "user": logon["user"], "group": "workforce",
            "event_kind": "authentication", "action": logon["activity"], "source_ip": "",
            "device": logon["pc"], "resource": logon["pc"], "status": "Success",
            "source_dataset": "cert_style",
        }))
    if not device.empty:
        device_resource = device["device_id"] if "device_id" in device else device["pc"]
        parts.append(pd.DataFrame({
            "event_id": device["id"].astype(str) if "id" in device else "",
            "event_time": device["date"], "user": device["user"], "group": "workforce",
            "event_kind": "device", "action": device["activity"], "source_ip": "",
            "device": device["pc"], "resource": device_resource, "status": "Success",
            "is_removable": device["activity"].astype(str).str.lower().eq("connect").astype(int),
            "source_dataset": "cert_style",
        }))
    if not files.empty:
        byte_values = files["bytes"] if "bytes" in files else 0
        removable = files["to_removable_media"] if "to_removable_media" in files else False
        if not isinstance(removable, pd.Series):
            removable = pd.Series(removable, index=files.index)
        removable = removable.astype(str).str.lower().isin({"true", "1", "yes"}).astype(int)
        lower_names = files["filename"].fillna("").astype(str).str.lower()
        parts.append(pd.DataFrame({
            "event_id": files["id"].astype(str) if "id" in files else "",
            "event_time": files["date"], "user": files["user"], "group": "workforce",
            "event_kind": "file", "action": files["activity"], "source_ip": "",
            "device": files["pc"], "resource": files["filename"], "status": "Success",
            "bytes": byte_values, "is_removable": removable,
            "is_sensitive": lower_names.str.contains(r"confidential|secret|salary|credential|customer", regex=True).astype(int),
            "is_executable": lower_names.str.endswith((".exe", ".bat", ".ps1", ".sh")).astype(int),
            "source_dataset": "cert_style",
        }))
    if not admin.empty:
        parts.append(pd.DataFrame({
            "event_id": admin["id"].astype(str) if "id" in admin else "",
            "event_time": admin["date"], "user": admin["user"], "group": "workforce",
            "event_kind": "admin_action", "action": admin["action"], "source_ip": "",
            "device": admin["pc"], "resource": admin["resource"], "status": admin["status"],
            "source_dataset": "cert_style",
        }))
    if not parts:
        raise ValueError(f"No usable CERT-style events found in {raw}")

    events = normalize_events(pd.concat(parts, ignore_index=True))
    labels_path = raw / "labels.csv"
    if labels_path.exists():
        labels = pd.read_csv(labels_path)
        _validate(labels, {"user", "date", "is_malicious"}, labels_path)
        labels["day"] = pd.to_datetime(labels["date"], errors="coerce").dt.normalize()
        label_lookup = labels.set_index([labels["user"].astype(str), "day"])["is_malicious"]
        scenario_lookup = (
            labels.assign(scenario=labels.get("scenario", "")).set_index([labels["user"].astype(str), "day"])["scenario"]
        )
        keys = pd.MultiIndex.from_arrays([events["user"], events["event_time"].dt.normalize()])
        events["is_malicious"] = label_lookup.reindex(keys).fillna(0).astype(int).to_numpy()
        events["scenario"] = scenario_lookup.reindex(keys).fillna("").astype(str).to_numpy()
    return events
