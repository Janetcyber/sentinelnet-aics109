# SentinelNet AI Defense Fabric - Incident and Model Report

Generated: 2026-08-04T11:30:21.275107Z

## Model Summary
- Supervised weighted F1: 0.999666716955155
- Supervised macro F1: 0.9993875979647692
- Sequence macro F1: 0.09684604405047287
- Autoencoder threshold: 3.3318569660186768

## Alert Summary
- Total streaming alerts: 136

## Top Alerts
- 2026-08-03T09:48:21.107639 10.10.5.108 -> 10.10.7.248 | DDoS | risk=100 | T1498 Network Denial of Service
- 2026-08-03T09:51:46.107639 10.10.2.109 -> 10.10.6.47 | DDoS | risk=100 | T1498 Network Denial of Service
- 2026-08-03T10:00:16.107639 10.10.5.139 -> 10.10.1.240 | DDoS | risk=100 | T1498 Network Denial of Service
- 2026-08-03T10:01:53.107639 10.10.3.244 -> 10.10.7.119 | DDoS | risk=100 | T1498 Network Denial of Service
- 2026-08-03T10:03:37.107639 10.10.1.197 -> 10.10.7.127 | DDoS | risk=100 | T1498 Network Denial of Service
- 2026-08-03T10:04:27.107639 10.10.6.247 -> 10.10.8.17 | DDoS | risk=96 | T1498 Network Denial of Service
- 2026-08-03T09:55:30.107639 10.10.4.244 -> 10.10.3.150 | DDoS | risk=92 | T1498 Network Denial of Service
- 2026-08-03T09:58:11.107639 10.10.1.180 -> 10.10.6.4 | DDoS | risk=92 | T1498 Network Denial of Service
- 2026-08-03T09:55:54.107639 10.10.7.139 -> 10.10.7.173 | PortScan | risk=88 | T1046 Network Service Discovery
- 2026-08-03T09:57:10.107639 10.10.5.180 -> 10.10.2.203 | PortScan | risk=88 | T1046 Network Service Discovery

## Analyst Notes
- Validate high-risk alerts with raw telemetry before containment.
- Compare model prediction with Suricata/Zeek context and asset criticality.
- Document false positives and update thresholds responsibly.
