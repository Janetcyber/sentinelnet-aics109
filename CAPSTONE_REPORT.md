# SentinelNet AI Defense Fabric — Capstone Report
**Course:** AICS-109 — AI for Advanced Network Defense
**Programme:** ICDFA AI-Driven Cybersecurity and Digital Forensics Fellowship
**Author:** Janet (GitHub: Janetcyber)

---

## 1. Overview

SentinelNet AI Defense Fabric is a defensive AI pipeline for a SOC. It ingests
network-flow telemetry, trains three families of machine-learning models,
correlates their output with Zeek and Suricata sensor logs, produces prioritized
and MITRE ATT&CK-mapped alerts, and generates safe, dry-run response
recommendations. The system is strictly defensive: it operates on synthetic lab
data and never scans, blocks, or disrupts any network.

The pipeline has five layers: telemetry, data/schema, models, fusion, and
response. This report summarizes what was built at each layer, the results, and
an honest assessment of limitations.

## 2. Data and Schema

A synthetic dataset of 12,000 network-flow records was generated across six
classes: Benign, PortScan, DDoS, BruteForce, Exfiltration, and C2Beacon. The
class distribution is deliberately imbalanced (Benign ~61%, attack classes 6–10%
each), reflecting real network traffic where benign flows dominate.

Profiling confirmed zero missing values and 14 numeric features spanning volume,
behaviour, temporal, protocol, and risk dimensions. Key data-quality findings:

- **Severe class imbalance** — makes accuracy misleading and mandates macro-F1 as
  the primary supervised metric.
- **Extreme feature skew** — `bytes_out` ranges from 41 to ~40 million with a
  standard deviation far exceeding its mean, requiring feature normalization.
- **Clean class separation** — the generator ties specific features to specific
  labels (e.g. very large `bytes_out` almost exclusively indicates Exfiltration),
  which inflates model scores and is discussed under Limitations.

## 3. Feature Engineering

Fourteen features were used. Correlation analysis showed the strongest pair was
`bytes_per_sec`–`packets_per_sec` (0.82), with most pairs well below 0.5,
indicating low redundancy. Notably, `beacon_score` and `asset_criticality` were
near-independent of all volume features — a strength, since they capture timing
periodicity and business context respectively, dimensions the volume features
cannot see.

Six features were selected as most defensible for network defense:
`bytes_out`/`outbound_ratio` (exfiltration), `unique_dst_ports_5m` (port scanning,
T1046), `failed_conn_5m` (brute force), `packets_per_sec`/`burst_score` (DDoS,
T1498), `beacon_score` (C2 beaconing, T1071), and `asset_criticality`
(risk weighting).

## 4. Models

### 4.1 Supervised — Residual MLP Classifier
A residual multilayer perceptron with batch normalization, dropout, and
class-weighted loss was trained for 12 epochs. It achieved **macro F1 0.9994 /
weighted F1 0.9997**, with a confusion matrix that was almost perfectly diagonal
(a single PortScan→BruteForce misclassification out of ~3,000 test samples). The
one error is the most plausible confusion in the matrix — both scanning and
brute-forcing produce elevated failed-connection counts against service ports.

### 4.2 Unsupervised — Autoencoder + Isolation Forest
An autoencoder was trained on benign traffic only, flagging flows with high
reconstruction error; an Isolation Forest served as a classical baseline. At the
config-specified 95th-percentile threshold, the two behaved very differently:

| Model | Precision | Recall | F1 |
|---|---|---|---|
| Autoencoder | 1.00 | 0.13 | 0.23 |
| Isolation Forest | 0.70 | 0.98 | 0.81 |

Neither is universally "better." The autoencoder's perfect precision suits
production escalation (every alert is real); the Isolation Forest's near-perfect
recall suits threat hunting (catch everything, filter later). The autoencoder is
more useful for genuinely unknown threats, as it learns only normal behaviour.

### 4.3 Sequence — GRU Detector
A genuine per-host PyTorch GRU was built (replacing the shipped placeholder). It
achieved **macro F1 ~0.10**. Investigation of the near-flat training loss showed
the model was not learning — because the synthetic data assigns flow labels
independently with no realistic temporal progression per host. A GRU's value is
exploiting temporal structure; where none exists, it cannot outperform random
guessing. This is a key limitation of the synthetic data, not a model failure
(see Limitations).

## 5. Detection, Fusion, and Response

**Streaming detection** processed 2,000 flows in 4.12 seconds (~2 ms/flow,
~486 flows/second on a single constrained CPU core), producing JSONL alerts with
risk scores and ATT&CK mapping.

**Telemetry fusion** parsed the Zeek and Suricata sample logs and joined them on
the (source, destination) IP pair. Both Suricata alerts were corroborated by
Zeek. The C2 beacon (risk 100, external destination, T1071) correctly outranked
the internal port scan (risk 75, T1046), demonstrating that multi-sensor
corroboration produces defensible, prioritized findings.

**Response simulation** ran in dry-run mode only, producing containment
*recommendations* (isolate/escalate/monitor) by risk tier, every action tagged
"dry-run" and "human approval required." No action is ever executed
automatically.

## 6. Safety and Responsible Automation

Automated response without human validation is dangerous: detection models
produce false positives, and an automated block acts on them irreversibly. A
misclassified benign flow could trigger isolation of a critical server, causing
an outage worse than the threat. Attackers can also deliberately craft traffic to
trigger false positives, weaponizing an automated response system. SentinelNet
therefore defaults to dry-run: the AI recommends, a human decides, and execution
is restricted to approved lab networks. The response layer provides decision
support, not autonomous action.

## 7. Limitations

- **Synthetic data is unrealistically clean.** Cleanly separated class signatures
  inflate supervised performance; real traffic overlaps far more. The 0.9994
  macro-F1 reflects data simplicity, not production readiness.
- **No temporal structure.** The data lacks realistic per-host attack progression,
  which is why the GRU could not learn. Sequence modelling should be validated on
  data with authentic temporal behaviour (e.g. CIC-IDS2017/2018).
- **Volume-biased alert ranking.** The streaming heuristic ranks DDoS highest by
  packet rate, which could bury quieter but higher-impact threats (stealthy C2,
  exfiltration). Class-specific thresholds would mitigate this.
- **Streaming uses a heuristic, not the trained model.** A fast rule-based filter
  at the streaming layer is a reasonable design choice, but integrating trained
  model confidence into streaming is a clear next step.
- **Not production-validated.** No claim of production readiness is made without
  testing on real, authorized telemetry.

## 8. Improvements Made Over the Shipped Pipeline

Three documented improvements were made (full detail in `CHANGES.md`):
1. Config-driven anomaly threshold (fixed an 85th vs 95th percentile mismatch).
2. A genuine per-host PyTorch GRU (replacing an MLP placeholder).
3. A real Zeek/Suricata telemetry-fusion step (the shipped sample logs were
   otherwise unused).

## 9. Conclusion

SentinelNet demonstrates an end-to-end defensive AI pipeline: three model
families, multi-sensor fusion, ATT&CK-mapped prioritization, and safe response
governance. Its most valuable outcomes are not the high supervised scores but the
honest findings — that the synthetic data supports single-flow classification yet
not temporal detection, and that responsible SOC automation requires a human in
the loop. Future work will enhance the dataset with realistic temporal attack
behaviour and validate the pipeline on authorized real-world telemetry.
