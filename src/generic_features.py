"""Behavioral features shared by normalized event datasets."""

from __future__ import annotations

import numpy as np
import pandas as pd


GENERIC_RAW_FEATURES = [
    "event_count",
    "after_hours_count",
    "weekend_count",
    "failed_event_count",
    "unique_ips",
    "unique_resources",
    "unique_actions",
    "unique_ports",
    "unique_devices",
    "privileged_action_count",
    "new_ip_count",
    "new_resource_count",
    "new_device_count",
    "max_events_per_minute",
    "dominant_ip_fraction",
]

GENERIC_DEVIATION_BASES = [
    "event_count",
    "after_hours_count",
    "failed_event_count",
    "unique_ips",
    "unique_resources",
    "unique_actions",
    "unique_ports",
    "unique_devices",
    "privileged_action_count",
    "new_ip_count",
    "new_resource_count",
    "new_device_count",
    "max_events_per_minute",
]

GENERIC_MODEL_FEATURES = (
    GENERIC_RAW_FEATURES
    + [f"personal_z_{name}" for name in GENERIC_DEVIATION_BASES]
    + [f"peer_z_{name}" for name in GENERIC_DEVIATION_BASES]
)


def _mark_first_seen(events: pd.DataFrame, column: str, output: str) -> None:
    values = events[column].fillna("").astype(str)
    valid = values.ne("") & values.ne("0")
    occurrence = events.assign(_value=values).groupby(["user", "_value"], sort=False).cumcount()
    events[output] = (valid & occurrence.eq(0)).astype(int)


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
        r"ban|unban|reset|modify|delete|grant|admin", regex=True
    ).astype(int)
    _mark_first_seen(work, "source_ip", "new_ip")
    _mark_first_seen(work, "resource", "new_resource")
    _mark_first_seen(work, "device", "new_device")
    work["minute"] = work["event_time"].dt.floor("min")
    work["events_this_minute"] = work.groupby(["user", "minute"])["user"].transform("size")

    keys = ["user", "day"]
    daily = work.groupby(keys, as_index=False).agg(
        group=("group", "first"),
        source_dataset=("source_dataset", "first"),
        event_count=("action", "size"),
        after_hours_count=("after_hours", "sum"),
        weekend_count=("weekend", "sum"),
        failed_event_count=("failed", "sum"),
        unique_ips=("source_ip", "nunique"),
        unique_resources=("resource", "nunique"),
        unique_actions=("action", "nunique"),
        unique_ports=("port", "nunique"),
        unique_devices=("device", "nunique"),
        privileged_action_count=("privileged", "sum"),
        new_ip_count=("new_ip", "sum"),
        new_resource_count=("new_resource", "sum"),
        new_device_count=("new_device", "sum"),
        max_events_per_minute=("events_this_minute", "max"),
        is_malicious=("is_malicious", "max"),
        attack_event_count=("is_malicious", "sum"),
        provided_risk_mean=("provided_risk", "mean"),
        provided_risk_max=("provided_risk", "max"),
    )
    dominant = (
        work.groupby(keys + ["source_ip"]).size().groupby(level=[0, 1]).max()
        / work.groupby(keys).size()
    ).rename("dominant_ip_fraction").reset_index()
    return daily.merge(dominant, on=keys, how="left").sort_values(["day", "user"]).reset_index(drop=True)


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


def build_generic_feature_table(events: pd.DataFrame) -> pd.DataFrame:
    return add_generic_deviations(aggregate_normalized_events(events))

