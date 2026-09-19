"""Generate deterministic, CERT-like activity logs for the local demo."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


def generate_demo_logs(output_dir: str | Path, seed: int = 42) -> dict[str, Path]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)

    users = [f"ACM{i:04d}" for i in range(1, 25)]
    dates = pd.date_range("2026-01-05", periods=60, freq="D")
    logons: list[dict] = []
    devices: list[dict] = []
    files: list[dict] = []
    labels: list[dict] = []
    event_id = 1

    attacks = {
        ("ACM0003", pd.Timestamp("2026-02-25")): "After-hours USB exfiltration",
        ("ACM0011", pd.Timestamp("2026-02-27")): "Bulk sensitive-file collection",
        ("ACM0018", pd.Timestamp("2026-03-02")): "Compromised account on unusual host",
    }

    for user_index, user in enumerate(users):
        home_pc = f"PC-{100 + user_index:03d}"
        normal_files = int(rng.integers(8, 22))
        start_hour = float(rng.normal(8.8, 0.45))

        for day in dates:
            malicious_scenario = attacks.get((user, day), "")
            is_weekend = day.dayofweek >= 5
            is_active = rng.random() < (0.20 if is_weekend else 0.96)
            labels.append(
                {
                    "user": user,
                    "date": day.date().isoformat(),
                    "is_malicious": int(bool(malicious_scenario)),
                    "scenario": malicious_scenario,
                }
            )
            if not is_active and not malicious_scenario:
                continue

            login_hour = float(np.clip(rng.normal(start_hour, 0.55), 6.0, 11.0))
            pc = home_pc
            file_count = max(1, int(rng.poisson(normal_files)))
            usb_connects = int(rng.random() < 0.035)
            removable_count = 0
            sensitive_count = int(rng.poisson(0.2))
            executable_count = int(rng.random() < 0.03)
            bytes_scale = 90_000

            if malicious_scenario == "After-hours USB exfiltration":
                login_hour = 2.15
                file_count = 190
                usb_connects = 2
                removable_count = 150
                sensitive_count = 75
                bytes_scale = 3_000_000
            elif malicious_scenario == "Bulk sensitive-file collection":
                login_hour = 21.4
                file_count = 280
                sensitive_count = 160
                bytes_scale = 1_800_000
            elif malicious_scenario == "Compromised account on unusual host":
                login_hour = 1.35
                pc = "PC-999"
                file_count = 135
                sensitive_count = 45
                executable_count = 12
                bytes_scale = 900_000

            login_time = day + pd.to_timedelta(login_hour, unit="h")
            logout_time = login_time + pd.to_timedelta(float(rng.uniform(7.0, 9.5)), unit="h")
            logons.append(
                {"id": f"L{event_id}", "date": login_time.isoformat(), "user": user, "pc": pc, "activity": "Logon"}
            )
            event_id += 1
            logons.append(
                {"id": f"L{event_id}", "date": logout_time.isoformat(), "user": user, "pc": pc, "activity": "Logoff"}
            )
            event_id += 1

            for device_number in range(usb_connects):
                device_time = login_time + pd.to_timedelta(float(rng.uniform(0.3, 4.0)), unit="h")
                devices.append(
                    {
                        "id": f"D{event_id}",
                        "date": device_time.isoformat(),
                        "user": user,
                        "pc": pc,
                        "activity": "Connect",
                        "device_id": f"USB-{user_index:02d}-{device_number}",
                    }
                )
                event_id += 1

            for file_number in range(file_count):
                file_time = login_time + pd.to_timedelta(float(rng.uniform(0.1, 7.0)), unit="h")
                is_sensitive = file_number < sensitive_count
                is_executable = file_number < executable_count
                to_removable = file_number < removable_count
                if is_executable:
                    extension = ".exe"
                elif is_sensitive:
                    extension = rng.choice([".docx", ".xlsx", ".pdf"])
                else:
                    extension = rng.choice([".txt", ".pdf", ".docx", ".csv"])
                prefix = "confidential_" if is_sensitive else "document_"
                activity = "Copy" if to_removable else "Open"
                files.append(
                    {
                        "id": f"F{event_id}",
                        "date": file_time.isoformat(),
                        "user": user,
                        "pc": pc,
                        "filename": f"{prefix}{file_number:04d}{extension}",
                        "activity": activity,
                        "bytes": int(max(500, rng.lognormal(np.log(bytes_scale), 0.65))),
                        "to_removable_media": to_removable,
                    }
                )
                event_id += 1

    paths = {
        "logon": output / "logon.csv",
        "device": output / "device.csv",
        "file": output / "file.csv",
        "labels": output / "labels.csv",
    }
    pd.DataFrame(logons).to_csv(paths["logon"], index=False)
    pd.DataFrame(devices).to_csv(paths["device"], index=False)
    pd.DataFrame(files).to_csv(paths["file"], index=False)
    pd.DataFrame(labels).to_csv(paths["labels"], index=False)
    return paths

