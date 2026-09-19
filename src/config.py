"""Shared model and feature configuration."""

RAW_FEATURES = [
    "logon_count",
    "after_hours_logons",
    "unique_pcs",
    "first_login_hour",
    "last_activity_hour",
    "device_connect_count",
    "file_access_count",
    "removable_file_count",
    "sensitive_file_count",
    "executable_file_count",
    "bytes_accessed",
    "total_events",
]

DEVIATION_BASES = [
    "logon_count",
    "after_hours_logons",
    "unique_pcs",
    "device_connect_count",
    "file_access_count",
    "removable_file_count",
    "sensitive_file_count",
    "executable_file_count",
    "bytes_accessed",
    "total_events",
]

PERSONAL_DEVIATION_FEATURES = [f"personal_z_{name}" for name in DEVIATION_BASES]
ORG_DEVIATION_FEATURES = [f"org_z_{name}" for name in DEVIATION_BASES]
MODEL_FEATURES = RAW_FEATURES + PERSONAL_DEVIATION_FEATURES + ORG_DEVIATION_FEATURES

RISK_BANDS = [
    (85, "Critical"),
    (70, "High"),
    (45, "Medium"),
    (0, "Low"),
]

