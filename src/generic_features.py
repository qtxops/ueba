"""Leakage-safe daily and multi-day features for canonical UEBA events."""

from __future__ import annotations

import numpy as np
import pandas as pd


GENERIC_RAW_FEATURES = [
    "event_count", "logon_count", "after_hours_count", "weekend_count", "failed_event_count",
    "unique_ips", "unique_resources", "unique_actions", "unique_ports", "unique_devices",
    "device_connect_count", "file_access_count", "removable_file_count", "sensitive_file_count",
    "executable_file_count", "bytes_accessed", "privileged_action_count", "new_ip_count",
    "new_resource_count", "new_device_count", "max_events_per_minute", "dominant_ip_fraction",
]

GENERIC_DEVIATION_BASES = [
    "event_count", "after_hours_count", "failed_event_count", "unique_ips", "unique_resources",
    "unique_actions", "unique_ports", "unique_devices", "privileged_action_count", "new_ip_count",
    "new_resource_count", "new_device_count", "max_events_per_minute", "file_access_count",
    "removable_file_count", "sensitive_file_count", "executable_file_count", "bytes_accessed",
]

ROLLING_SUM_BASES = [
    "event_count", "after_hours_count", "failed_event_count", "privileged_action_count",
    "new_ip_count", "new_resource_count", "new_device_count", "file_access_count",
    "removable_file_count", "sensitive_file_count", "executable_file_count", "bytes_accessed",
]

ROLLING_FEATURES = (
    [f"rolling_7d_{name}" for name in ROLLING_SUM_BASES]
    + [f"rolling_30d_{name}" for name in ROLLING_SUM_BASES]
    + ["active_days_7d", "active_days_30d", "event_trend_7d_vs_30d", "sensitive_trend_7d_vs_30d"]
)

GENERIC_MODEL_FEATURES = (
    GENERIC_RAW_FEATURES
    + ROLLING_FEATURES
    + [f"personal_z_{name}" for name in GENERIC_DEVIATION_BASES]
    + [f"peer_z_{name}" for name in GENERIC_DEVIATION_BASES]
)


def _mark_first_seen(events: pd.DataFrame, column: str, output: str) -> None:
    values = events[column].fillna("").astype(str)
    valid = values.ne("") & values.ne("0")
    occurrence = events.assign(_value=values).groupby(["user", "_value"], sort=False).cumcount()
    events[output] = (valid & occurrence.eq(0)).astype(int)


def _complete_daily_grid(daily: pd.DataFrame) -> pd.DataFrame:
    """Add zero-activity dates so rolling windows represent calendar days."""
    start, end = daily["day"].min(), daily["day"].max()
    users = daily[["user", "group", "source_dataset"]].drop_duplicates("user")
    grid = users.assign(_key=1).merge(
        pd.DataFrame({"day": pd.date_range(start, end), "_key": 1}), on="_key", how="inner"
    ).drop(columns="_key")
    result = grid.merge(daily, on=["user", "group", "source_dataset", "day"], how="left")
    for column in GENERIC_RAW_FEATURES + ["attack_event_count", "is_malicious"]:
        result[column] = result[column].fillna(0)
    result["scenario"] = result["scenario"].fillna("")
    return result.sort_values(["day", "user"]).reset_index(drop=True)


def aggregate_normalized_events(events: pd.DataFrame) -> pd.DataFrame:
    if events.empty:
        raise ValueError("The normalized event table is empty")
    work = events.sort_values(["user", "event_time"]).copy()
    work["day"] = work["event_time"].dt.normalize()
    work["hour"] = work["event_time"].dt.hour + work["event_time"].dt.minute / 60
    work["after_hours"] = ((work["hour"] < 6) | (work["hour"] >= 20)).astype(int)
    work["weekend"] = (work["event_time"].dt.dayofweek >= 5).astype(int)
    work["failed"] = work["status"].str.lower().isin({"fail", "failed", "denied", "error"}).astype(int)
    work["privileged"] = work["action"].str.lower().str.contains(
        r"ban|unban|reset|modify|delete|grant|admin|sudo|permission", regex=True
    ).astype(int)
    work["logon"] = (
        work["event_kind"].eq("authentication") & work["action"].str.lower().eq("logon")
    ).astype(int)
    work["login_hour"] = work["hour"].where(work["logon"].eq(1))
    work["device_connect"] = (
        work["event_kind"].eq("device") & work["action"].str.lower().eq("connect")
    ).astype(int)
    work["file_access"] = work["event_kind"].eq("file").astype(int)
    _mark_first_seen(work, "source_ip", "new_ip")
    _mark_first_seen(work, "resource", "new_resource")
    _mark_first_seen(work, "device", "new_device")
    work["minute"] = work["event_time"].dt.floor("min")
    work["events_this_minute"] = work.groupby(["user", "minute"])["user"].transform("size")

    keys = ["user", "day"]
    daily = work.groupby(keys, as_index=False).agg(
        group=("group", "first"), source_dataset=("source_dataset", "first"),
        event_count=("action", "size"), logon_count=("logon", "sum"),
        after_hours_count=("after_hours", "sum"), weekend_count=("weekend", "sum"),
        failed_event_count=("failed", "sum"),
        unique_ips=("source_ip", lambda values: values[values.ne("")].nunique()),
        unique_resources=("resource", lambda values: values[values.ne("")].nunique()),
        unique_actions=("action", "nunique"),
        unique_ports=("port", lambda values: values[values.ne(0)].nunique()),
        unique_devices=("device", lambda values: values[values.ne("")].nunique()),
        device_connect_count=("device_connect", "sum"), file_access_count=("file_access", "sum"),
        removable_file_count=("is_removable", "sum"), sensitive_file_count=("is_sensitive", "sum"),
        executable_file_count=("is_executable", "sum"), bytes_accessed=("bytes", "sum"),
        privileged_action_count=("privileged", "sum"), new_ip_count=("new_ip", "sum"),
        new_resource_count=("new_resource", "sum"), new_device_count=("new_device", "sum"),
        max_events_per_minute=("events_this_minute", "max"), first_login_hour=("login_hour", "min"),
        last_activity_hour=("hour", "max"), is_malicious=("is_malicious", "max"),
        attack_event_count=("is_malicious", "sum"),
        scenario=("scenario", lambda values: next((value for value in values if value), "")),
        provided_risk_mean=("provided_risk", "mean"), provided_risk_max=("provided_risk", "max"),
    )
    valid_ip = work[work["source_ip"].ne("")]
    if valid_ip.empty:
        daily["dominant_ip_fraction"] = 0.0
    else:
        dominant = (
            valid_ip.groupby(keys + ["source_ip"]).size().groupby(level=[0, 1]).max()
            / work.groupby(keys).size()
        ).rename("dominant_ip_fraction").reset_index()
        daily = daily.merge(dominant, on=keys, how="left")
        daily["dominant_ip_fraction"] = daily["dominant_ip_fraction"].fillna(0)
    return _complete_daily_grid(daily)


def add_rolling_features(daily: pd.DataFrame) -> pd.DataFrame:
    result = daily.sort_values(["user", "day"]).copy()
    for column in ROLLING_SUM_BASES:
        grouped = result.groupby("user", sort=False)[column]
        result[f"rolling_7d_{column}"] = grouped.transform(lambda values: values.rolling(7, min_periods=1).sum())
        result[f"rolling_30d_{column}"] = grouped.transform(lambda values: values.rolling(30, min_periods=1).sum())
    active = result["event_count"].gt(0).astype(int)
    result["active_days_7d"] = active.groupby(result["user"]).transform(
        lambda values: values.rolling(7, min_periods=1).sum()
    )
    result["active_days_30d"] = active.groupby(result["user"]).transform(
        lambda values: values.rolling(30, min_periods=1).sum()
    )
    result["event_trend_7d_vs_30d"] = (
        result["rolling_7d_event_count"] / 7
    ) / (result["rolling_30d_event_count"] / 30).replace(0, np.nan)
    result["sensitive_trend_7d_vs_30d"] = (
        result["rolling_7d_sensitive_file_count"] / 7
    ) / (result["rolling_30d_sensitive_file_count"] / 30).replace(0, np.nan)
    for column in ["event_trend_7d_vs_30d", "sensitive_trend_7d_vs_30d"]:
        result[column] = result[column].replace([np.inf, -np.inf], np.nan).fillna(0).clip(0, 12)
    return result


def add_generic_deviations(daily: pd.DataFrame) -> pd.DataFrame:
    result = daily.sort_values(["user", "day"]).copy()
    for column in GENERIC_DEVIATION_BASES:
        grouped = result.groupby("user", sort=False)[column]
        history_mean = grouped.transform(lambda x: x.shift().expanding(min_periods=5).mean())
        history_std = grouped.transform(lambda x: x.shift().expanding(min_periods=5).std()).replace(0, np.nan)
        result[f"personal_z_{column}"] = ((result[column] - history_mean) / history_std).clip(-12, 12).fillna(0)
        peer_mean = result.groupby(["day", "group"])[column].transform("mean")
        peer_std = result.groupby(["day", "group"])[column].transform("std").replace(0, np.nan)
        result[f"peer_z_{column}"] = ((result[column] - peer_mean) / peer_std).clip(-12, 12).fillna(0)
    return result.sort_values(["day", "user"]).reset_index(drop=True)


def add_compatibility_aliases(features: pd.DataFrame) -> pd.DataFrame:
    """Keep the current UI/API stable while it migrates to canonical names."""
    result = features.copy()
    result["after_hours_logons"] = result["after_hours_count"]
    result["unique_pcs"] = result["unique_devices"]
    result["total_events"] = result["event_count"]
    result["first_login_hour"] = result["first_login_hour"].fillna(12.0)
    result["last_activity_hour"] = result["last_activity_hour"].fillna(result["first_login_hour"])
    return result


def build_generic_feature_table(events: pd.DataFrame) -> pd.DataFrame:
    daily = aggregate_normalized_events(events)
    return add_compatibility_aliases(add_generic_deviations(add_rolling_features(daily)))
