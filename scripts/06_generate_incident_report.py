#!/usr/bin/env python3
from pathlib import Path
import json, datetime

def load_json(path, default):
    p=Path(path)
    return json.loads(p.read_text()) if p.exists() else default

def main():
    Path('outputs').mkdir(exist_ok=True)
    sup=load_json('outputs/supervised_metrics.json',{})
    anom=load_json('outputs/anomaly_metrics.json',{})
    seq=load_json('outputs/sequence_metrics.json',{})
    fusion=load_json('outputs/fusion_summary.json',{'alerts':0,'top_alerts':[]})
    md=[]
    md.append('# SentinelNet AI Defense Fabric - Incident and Model Report\n')
    md.append(f"Generated: {datetime.datetime.utcnow().isoformat()}Z\n")
    md.append('## Model Summary')
    md.append(f"- Supervised weighted F1: {sup.get('weighted_f1','not trained')}")
    md.append(f"- Supervised macro F1: {sup.get('macro_f1','not trained')}")
    md.append(f"- Sequence macro F1: {seq.get('macro_f1','not trained')}")
    md.append(f"- Autoencoder threshold: {anom.get('autoencoder_threshold','not trained')}\n")
    md.append('## Alert Summary')
    md.append(f"- Total streaming alerts: {fusion.get('alerts',0)}")
    md.append('\n## Top Alerts')
    for a in fusion.get('top_alerts',[])[:10]:
        md.append(f"- {a['timestamp']} {a['src_ip']} -> {a['dst_ip']} | {a['predicted_threat']} | risk={a['risk_score']} | {a['mitre_technique']}")
    md.append('\n## Analyst Notes')
    md.append('- Validate high-risk alerts with raw telemetry before containment.')
    md.append('- Compare model prediction with Suricata/Zeek context and asset criticality.')
    md.append('- Document false positives and update thresholds responsibly.')
    Path('outputs/incident_report.md').write_text('\n'.join(md))
    print('[+] wrote outputs/incident_report.md')
if __name__=='__main__': main()
