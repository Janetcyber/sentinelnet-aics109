# Changes from the Shipped SentinelNet Package

This document records every modification I made to the original ICDFA-provided
`SentinelNetAI_Project` code, with the reasoning behind each. All original files
are preserved on the working machine with a `.orig` suffix. The goal was to run
the pipeline faithfully, identify where the shipped code fell short of the lab
requirements, and correct those gaps in a defensible, documented way.

## Change 1 — Config-driven anomaly threshold
**File:** `scripts/03_train_autoencoder_anomaly.py`

**Problem:** The shipped script hard-coded the autoencoder's anomaly detection
threshold at the 85th percentile of reconstruction error, while `config.json`
specifies `anomaly_reconstruction_percentile: 95`. The code contradicted the
project's own configuration.

**Fix:** Modified the script to read the percentile value from `config.json` at
runtime, so configuration is the single source of truth.

**Effect:** Raising the threshold from the 85th to the 95th percentile increased
the autoencoder's precision and reduced its recall — a concrete, intentional
illustration of the precision/recall trade-off in anomaly detection.

## Change 2 — Genuine GRU sequence detector
**File:** `scripts/04_train_sequence_gru.py`

**Problem:** Despite its name and the Lab 6 requirement for a GRU, the shipped
script trained a scikit-learn `MLPClassifier` on flattened windows and wrote a
plain-text placeholder to `models/sequence_gru.pt` (literally noting it should be
replaced with a real GRU/LSTM). It also built sequences across all rows rather
than per source host, and fit its scaler before the train/test split (minor
leakage).

**Fix:** Replaced it with a genuine PyTorch GRU. Sequences are now built per
source host (each window represents one host's behaviour over time), the scaler
is fit on training data only, random seeds are set for reproducibility, and a
real GRU model artefact is saved. The input/output contract is unchanged so the
rest of the pipeline still works.

**Effect:** The GRU achieved a low macro F1 (~0.10). This is a legitimate and
important finding, not a failure: the synthetic dataset assigns flow labels
independently with no realistic per-host temporal progression, so there is no
temporal signal for a sequence model to learn. This is documented as a key
limitation and motivates planned data-enhancement work.

## Change 3 — Real Zeek/Suricata telemetry fusion
**File:** `scripts/08_fuse_telemetry.py` (new)

**Problem:** Lab 7 requires parsing the shipped Zeek and Suricata sample logs and
joining them to flow records. No script in the shipped pipeline read those files —
`sample_logs/suricata_eve_sample.jsonl` and `zeek_conn_sample.jsonl` were
provided but unused.

**Fix:** Added a new fusion script that parses both logs, joins them on the
(source, destination) IP pair, computes a fused risk score (boosted when both
sensors corroborate and when the destination is external), and maps each finding
to MITRE ATT&CK.

**Effect:** Produced two fused, ATT&CK-mapped findings, both corroborated by
Zeek. The C2 beacon (risk 100, external destination, T1071) correctly outranks
the internal port scan (risk 75, T1046), demonstrating evidence-based alert
prioritization from multi-source correlation.
