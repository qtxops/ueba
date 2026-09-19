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
    admin_events: list[dict] = []
    labels: list[dict] = []
    event_id = 1

    attack_windows = {
        "ACM0003": (pd.Timestamp("2026-02-24"), pd.Timestamp("2026-02-28"), "Slow removable-media exfiltration"),
        "ACM0011": (pd.Timestamp("2026-02-26"), pd.Timestamp("2026-03-03"), "Gradual privilege escalation"),
        "ACM0018": (pd.Timestamp("2026-03-01"), pd.Timestamp("2026-03-04"), "Low-volume activity from a new host"),
    }

    for user_index, user in enumerate(users):
        home_pc = f"PC-{100 + user_index:03d}"
        normal_files = int(rng.integers(8, 22))
        start_hour = float(rng.normal(8.8, 0.45))

        for day in dates:
            attack = attack_windows.get(user)
            malicious_scenario = attack[2] if attack and attack[0] <= day <= attack[1] else ""
            attack_day = (day - attack[0]).days + 1 if malicious_scenario else 0
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

            if malicious_scenario == "Slow removable-media exfiltration":
                login_hour = 18.6 + 0.22 * attack_day
                file_count += 8 + 2 * attack_day
                usb_connects = 1
                removable_count = 3 + attack_day
                sensitive_count = 4 + attack_day
                bytes_scale = 240_000 + 35_000 * attack_day
            elif malicious_scenario == "Gradual privilege escalation":
                file_count += 2 * attack_day
                sensitive_count = 1 + attack_day
                bytes_scale = 140_000
                for privilege_number in range(attack_day):
                    admin_time = day + pd.to_timedelta(10 + privilege_number * 0.4, unit="h")
                    admin_events.append(
                        {
                            "id": f"A{event_id}", "date": admin_time.isoformat(), "user": user, "pc": pc,
                            "action": "grant_permission", "status": "Success",
                            "resource": f"role-{privilege_number % 3}",
                        }
                    )
                    event_id += 1
            elif malicious_scenario == "Low-volume activity from a new host":
                pc = "PC-999"
                file_count += 5
                sensitive_count = 2 + attack_day
                executable_count = 1
                bytes_scale = 180_000

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
        "admin": output / "admin.csv",
        "labels": output / "labels.csv",
    }
    pd.DataFrame(logons).to_csv(paths["logon"], index=False)
    pd.DataFrame(devices).to_csv(paths["device"], index=False)
    pd.DataFrame(files).to_csv(paths["file"], index=False)
    pd.DataFrame(admin_events).to_csv(paths["admin"], index=False)
    pd.DataFrame(labels).to_csv(paths["labels"], index=False)
    return paths
