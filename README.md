# AICS-109 - AI for Advanced Network Defense

## Project: SentinelNet AI Defense Fabric

This is a safe defensive AI network defense project for the AI-Driven Cybersecurity and Digital Forensics Fellowship. It includes synthetic data generation, model training, streaming detection, alert fusion, and lab-only response simulation.

Run:

```bash
python scripts/00_generate_synthetic_network_data.py --rows 12000
python scripts/01_profile_dataset.py
python scripts/02_train_supervised_ids.py --epochs 8
python scripts/03_train_autoencoder_anomaly.py --epochs 8
python scripts/04_train_sequence_gru.py --epochs 6
python scripts/05_run_streaming_detector.py --input data/synthetic_flows.csv --limit 200
python scripts/06_generate_incident_report.py
python scripts/07_response_simulator.py --dry-run
```

Safety: response is dry-run by default. Do not use this project to scan or disrupt networks.
