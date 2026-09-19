# SentinelUEBA

SentinelUEBA is an explainable User and Entity Behavior Analytics prototype for
insider-threat investigation. It converts login, removable-device, and file
activity logs into daily behavioral profiles, trains an unsupervised Isolation
Forest, and ranks suspicious user-days with a 0-100 risk score and human-readable
reasons.

The repository includes a deterministic synthetic dataset so the complete demo
works without downloading private or very large security logs. The same pipeline
can be adapted to the CERT Insider Threat dataset by mapping its three source
files to the documented schemas below.

## What the demo does

1. Generates realistic activity for 24 users over 60 days.
2. Injects several labeled insider-threat scenarios into the final portion.
3. Aggregates raw events into one record per user per day.
4. Creates leakage-safe personal and organization deviation features.
5. Trains an Isolation Forest only on the earlier chronological period.
6. Produces anomaly scores, 0-100 risk scores, severity bands, and explanations.
7. Displays alerts, user timelines, and evaluation results in Streamlit.

## Quick start

Python 3.10-3.13 is recommended because scientific Python packages may lag behind
brand-new Python releases.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/bootstrap_demo.py
streamlit run app.py
```

The dashboard opens at `http://localhost:8501`.

## Public Kaggle datasets

The project also supports two public datasets through a normalized event adapter:

- `game_admin_logs.csv`: timestamped administrator actions with binary attack labels.
- `train_data.csv`: GB18030-encoded account, group, IP, URL, port, VLAN, switch and time records with an undocumented continuous `ret` score.

After placing them under `data/external/kaggle/` in the directory structure used by
the project, build their artifacts with:

```bash
python scripts/build_external_datasets.py
```

The network dataset's `ret` value is never used as a model feature. It is retained
only for post-hoc comparison because the source does not document it as an attack
label or calibrated probability.

Run the tests with:

```bash
python -m unittest discover -s tests -v
```

## Raw input schemas

Place files in one directory and pass it to the preprocessing pipeline.

### `logon.csv`

| Column | Meaning |
|---|---|
| `id` | Unique event identifier |
| `date` | Event timestamp |
| `user` | User/entity identifier |
| `pc` | Computer identifier |
| `activity` | `Logon` or `Logoff` |

### `device.csv`

| Column | Meaning |
|---|---|
| `id` | Unique event identifier |
| `date` | Event timestamp |
| `user` | User/entity identifier |
| `pc` | Computer identifier |
| `activity` | `Connect` or `Disconnect` |

### `file.csv`

| Column | Meaning |
|---|---|
| `id` | Unique event identifier |
| `date` | Event timestamp |
| `user` | User/entity identifier |
| `pc` | Computer identifier |
| `filename` | Accessed filename |
| `activity` | File operation, such as `Open` or `Copy` |
| `bytes` | Approximate bytes accessed or copied |
| `to_removable_media` | Boolean indicating removable-media transfer |

An optional `labels.csv` containing `user`, `date`, `is_malicious`, and
`scenario` is used only for evaluation. Labels are never passed to the anomaly
model as training targets.

## Useful commands

```bash
# Regenerate all demo artifacts
python scripts/bootstrap_demo.py --force

# Train from a different raw-data directory
python scripts/train_model.py --raw-dir data/demo/raw --output-dir artifacts
```

## Project boundaries

This is a lab prototype, not a production SIEM replacement. A high risk score
means that observed behavior is unusual and worth investigating; it does not
prove malicious intent. Production deployment would additionally require secure
ingestion, access controls, drift monitoring, analyst feedback, privacy review,
and organization-specific calibration.
