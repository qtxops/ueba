"""Raw log validation, daily aggregation, and behavioral features."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from .config import DEVIATION_BASES, RAW_FEATURES


REQUIRED_COLUMNS = {
    "logon": {"date", "user", "pc", "activity"},
    "device": {"date", "user", "pc", "activity"},
    "file": {"date", "user", "pc", "filename", "activity"},
}


def _read_event_file(path: Path, kind: str) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=sorted(REQUIRED_COLUMNS[kind]))
    frame = pd.read_csv(path)
    missing = REQUIRED_COLUMNS[kind] - set(frame.columns)
    if missing:
        raise ValueError(f"{path.name} is missing required columns: {sorted(missing)}")
    frame = frame.drop_duplicates().copy()
    frame["timestamp"] = pd.to_datetime(frame["date"], errors="coerce")
    frame = frame.dropna(subset=["timestamp", "user"])
    frame["user"] = frame["user"].astype(str)
    frame["day"] = frame["timestamp"].dt.normalize()
    frame["hour"] = frame["timestamp"].dt.hour + frame["timestamp"].dt.minute / 60
    return frame


def aggregate_daily(raw_dir: str | Path) -> pd.DataFrame:
    raw = Path(raw_dir)
    logon = _read_event_file(raw / "logon.csv", "logon")
    device = _read_event_file(raw / "device.csv", "device")
    file_events = _read_event_file(raw / "file.csv", "file")

    if logon.empty and device.empty and file_events.empty:
        raise ValueError(f"No usable events found in {raw}")

    parts: list[pd.DataFrame] = []
    if not logon.empty:
        login_only = logon[logon["activity"].str.lower() == "logon"].copy()
        login_only["after_hours"] = ((login_only["hour"] < 6) | (login_only["hour"] >= 20)).astype(int)
        logon_daily = login_only.groupby(["user", "day"], as_index=False).agg(
            logon_count=("activity", "size"),
            after_hours_logons=("after_hours", "sum"),
            unique_pcs=("pc", "nunique"),
            first_login_hour=("hour", "min"),
        )
        last_activity = logon.groupby(["user", "day"], as_index=False)["hour"].max().rename(columns={"hour": "last_activity_hour"})
        parts.append(logon_daily.merge(last_activity, on=["user", "day"], how="left"))

    if not device.empty:
        connects = device[device["activity"].str.lower() == "connect"]
        parts.append(
            connects.groupby(["user", "day"], as_index=False).agg(device_connect_count=("activity", "size"))
        )

    if not file_events.empty:
        byte_values = file_events["bytes"] if "bytes" in file_events else pd.Series(0, index=file_events.index)
        file_events["bytes"] = pd.to_numeric(byte_values, errors="coerce").fillna(0)
        removable = file_events.get("to_removable_media", False)
        if not isinstance(removable, pd.Series):
            removable = pd.Series(False, index=file_events.index)
        if removable.dtype == object:
            removable = removable.astype(str).str.lower().isin({"true", "1", "yes"})
        file_events["is_removable"] = removable.astype(int)
        file_events["is_sensitive"] = file_events["filename"].str.lower().str.contains(
            r"confidential|secret|salary|credential|customer", regex=True
        ).astype(int)
        file_events["is_executable"] = file_events["filename"].str.lower().str.endswith(
            (".exe", ".bat", ".ps1", ".sh")
        ).astype(int)
        parts.append(
            file_events.groupby(["user", "day"], as_index=False).agg(
                file_access_count=("activity", "size"),
                removable_file_count=("is_removable", "sum"),
                sensitive_file_count=("is_sensitive", "sum"),
                executable_file_count=("is_executable", "sum"),
                bytes_accessed=("bytes", "sum"),
            )
        )

    daily = parts[0]
    for part in parts[1:]:
        daily = daily.merge(part, on=["user", "day"], how="outer")
    for column in RAW_FEATURES:
        if column not in daily:
            daily[column] = 0.0
    count_columns = [column for column in RAW_FEATURES if column not in {"first_login_hour", "last_activity_hour"}]
    daily[count_columns] = daily[count_columns].fillna(0)
    daily["first_login_hour"] = daily["first_login_hour"].fillna(12.0)
    daily["last_activity_hour"] = daily["last_activity_hour"].fillna(daily["first_login_hour"])
    daily["total_events"] = (
        daily["logon_count"] + daily["device_connect_count"] + daily["file_access_count"]
    )
    return daily.sort_values(["day", "user"]).reset_index(drop=True)


def add_behavioral_features(daily: pd.DataFrame) -> pd.DataFrame:
    """Add past-only personal z-scores and same-day organization z-scores."""
    result = daily.sort_values(["user", "day"]).copy()
    for column in DEVIATION_BASES:
        grouped = result.groupby("user", sort=False)[column]
        historical_mean = grouped.transform(lambda values: values.shift().expanding(min_periods=5).mean())
        historical_std = grouped.transform(lambda values: values.shift().expanding(min_periods=5).std())
        personal_z = (result[column] - historical_mean) / historical_std.replace(0, np.nan)
        result[f"personal_z_{column}"] = personal_z.clip(-12, 12).fillna(0)

        org_mean = result.groupby("day")[column].transform("mean")
        org_std = result.groupby("day")[column].transform("std").replace(0, np.nan)
        result[f"org_z_{column}"] = ((result[column] - org_mean) / org_std).clip(-12, 12).fillna(0)
    return result.sort_values(["day", "user"]).reset_index(drop=True)


def attach_labels(features: pd.DataFrame, raw_dir: str | Path) -> pd.DataFrame:
    label_path = Path(raw_dir) / "labels.csv"
    result = features.copy()
    if not label_path.exists():
        result["is_malicious"] = 0
        result["scenario"] = ""
        return result
    labels = pd.read_csv(label_path)
    required = {"user", "date", "is_malicious"}
    if not required.issubset(labels.columns):
        raise ValueError(f"labels.csv is missing required columns: {sorted(required - set(labels.columns))}")
    labels["day"] = pd.to_datetime(labels["date"], errors="coerce").dt.normalize()
    if "scenario" not in labels:
        labels["scenario"] = ""
    else:
        labels["scenario"] = labels["scenario"].fillna("")
    result = result.merge(labels[["user", "day", "is_malicious", "scenario"]], on=["user", "day"], how="left")
    result["is_malicious"] = result["is_malicious"].fillna(0).astype(int)
    result["scenario"] = result["scenario"].fillna("")
    return result


def build_feature_table(raw_dir: str | Path) -> pd.DataFrame:
    return attach_labels(add_behavioral_features(aggregate_daily(raw_dir)), raw_dir)
