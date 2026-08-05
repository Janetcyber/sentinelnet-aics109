# SentinelNet AI Defense Fabric

**An end-to-end defensive AI pipeline for network intrusion detection, alert fusion, and safe response.**

Built for **AICS-109 - AI for Advanced Network Defense** (ICDFA AI-Driven Cybersecurity & Digital Forensics Fellowship).

---

## What this is

SentinelNet ingests network-flow telemetry, trains three families of machine-learning models, correlates their output with Zeek and Suricata sensor logs, produces prioritized MITRE ATT&CK-mapped alerts, and generates safe, dry-run response recommendations. It is strictly defensive, it runs on synthetic lab data and never scans, blocks, or disrupts any network.

## Architecture

The pipeline has five layers:

1. **Telemetry** — synthetic network flows + Zeek/Suricata sample logs
2. **Data/schema** — profiling, feature engineering, normalization
3. **Models** — supervised classifier, anomaly detectors, sequence detector
4. **Fusion** — multi-sensor correlation, risk scoring, ATT&CK mapping
5. **Response** — dry-run containment recommendations with human-in-the-loop

## Models & Results

| Model | Type | Key Result |
|---|---|---|
| Residual MLP | Supervised multiclass IDS | Macro F1 **0.9994** |
| Autoencoder | Unsupervised anomaly | Precision **1.00**, Recall 0.13 (95th pct) |
| Isolation Forest | Unsupervised baseline | Recall **0.98**, Precision 0.70 |
| GRU (per-host) | Sequence / temporal | Macro F1 ~0.10 *(see note)* |

**Fusion:** Zeek + Suricata logs joined on (src, dst); C2 beacon (risk 100, T1071) correctly outranked port scan (risk 75, T1046), both corroborated by two sensors.

**Streaming:** ~486 flows/second; dry-run response recommendations by risk tier.

> **Note on the GRU:** the sequence model scored low *by design of the data, not the model*. The synthetic dataset has no realistic per-host temporal structure, so a GRU has no temporal signal to learn. This is documented as a key finding - see [`CAPSTONE_REPORT.md`](CAPSTONE_REPORT.md).

## Improvements over the shipped pipeline

This project didn't just run the provided code — it identified and fixed three gaps (full detail in [`CHANGES.md`](CHANGES.md)):

1. **Config-driven anomaly threshold** — fixed an 85th-vs-95th percentile mismatch between the script and `config.json`.
2. **Genuine per-host PyTorch GRU** — replaced a mislabeled MLP placeholder with a real GRU sequence model.
3. **Real Zeek/Suricata telemetry fusion** — the shipped sample logs were unused; added a script that parses and joins them.

## How to run

```bash
python scripts/00_generate_synthetic_network_data.py --rows 12000
python scripts/01_profile_dataset.py
python scripts/02_train_supervised_ids.py --epochs 12
python scripts/03_train_autoencoder_anomaly.py --epochs 12
python scripts/04_train_sequence_gru.py --epochs 10 --window 8
python scripts/05_run_streaming_detector.py --input data/synthetic_flows.csv --limit 2000
python scripts/08_fuse_telemetry.py
python scripts/07_response_simulator.py --dry-run
python scripts/06_generate_incident_report.py
```

Requirements: Python 3.10+, PyTorch, scikit-learn, pandas (see `requirements.txt`).

## Repository structure

- `scripts/` — pipeline source code
- `sample_logs/` — Zeek & Suricata sample telemetry
- `outputs/` — generated evidence artefacts (metrics, alerts, reports)
- `*.pt`, `*.joblib` — trained model files
- [`CAPSTONE_REPORT.md`](CAPSTONE_REPORT.md) — full analysis, results, and limitations
- [`CHANGES.md`](CHANGES.md) — documented improvements over the shipped code

## Safety

Response actions are **dry-run by default**. This project is for defensive, authorized lab use only. It does not perform scanning, exploitation, or network disruption.
