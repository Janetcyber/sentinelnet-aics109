#!/usr/bin/env python3
import argparse, json, time, math
from pathlib import Path
import pandas as pd, numpy as np, joblib, torch
from torch import nn
from sentinel_utils import FEATURES

CLASSES=['Benign','PortScan','DDoS','BruteForce','Exfiltration','C2Beacon']
ATTACK_MAP={
 'PortScan':['Discovery','T1046 Network Service Discovery'],
 'DDoS':['Impact','T1498 Network Denial of Service'],
 'BruteForce':['Credential Access','T1110 Brute Force'],
 'Exfiltration':['Exfiltration','T1041 Exfiltration Over C2 Channel'],
 'C2Beacon':['Command and Control','T1071 Application Layer Protocol'],
 'Benign':['None','None']}
class IDSNet(nn.Module):
    def __init__(self, in_dim, classes, hidden=96, dropout=0.15):
        super().__init__(); self.net=nn.Sequential(nn.Linear(in_dim,hidden), nn.BatchNorm1d(hidden), nn.ReLU(), nn.Linear(hidden,hidden), nn.ReLU(), nn.Linear(hidden,classes))
    def forward(self,x): return self.net(x)

def heuristic(row):
    scores={c:0.02 for c in CLASSES}; scores['Benign']=0.4
    if row['unique_dst_ports_5m']>30 or row['failed_conn_5m']>20: scores['PortScan']+=0.7
    if row['packets_per_sec']>400 or row['burst_score']>0.75: scores['DDoS']+=0.7
    if row['failed_conn_5m']>50 and row['dst_port'] in [22,21,3389,445,25]: scores['BruteForce']+=0.75
    if row['bytes_out']>2_000_000 and row['outbound_ratio']>0.85: scores['Exfiltration']+=0.8
    if row['beacon_score']>0.7: scores['C2Beacon']+=0.8
    total=sum(scores.values()); return {k:v/total for k,v in scores.items()}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--input',default='data/synthetic_flows.csv'); ap.add_argument('--limit',type=int,default=300); args=ap.parse_args()
    Path('outputs').mkdir(exist_ok=True)
    df=pd.read_csv(args.input).head(args.limit)
    out=open('outputs/stream_alerts.jsonl','w')
    alerts=[]
    for _,row in df.iterrows():
        probs=heuristic(row); label=max(probs,key=probs.get); conf=probs[label]
        if label!='Benign' and conf>0.45:
            tactic,tech=ATTACK_MAP[label]
            risk=min(100, int(conf*60 + row.get('asset_criticality',1)*8 + row.get('suricata_alert_count',0)*4))
            alert={'timestamp':row['timestamp'],'src_ip':row['src_ip'],'dst_ip':row['dst_ip'],'predicted_threat':label,'confidence':round(conf,4),'risk_score':risk,'mitre_tactic':tactic,'mitre_technique':tech,'evidence':{'dst_port':int(row['dst_port']),'bytes_out':int(row['bytes_out']),'packets_per_sec':float(row['packets_per_sec']),'unique_dst_ports_5m':int(row['unique_dst_ports_5m']),'failed_conn_5m':int(row['failed_conn_5m']),'beacon_score':float(row['beacon_score'])}}
            out.write(json.dumps(alert)+'\n'); alerts.append(alert)
    out.close(); Path('outputs/fusion_summary.json').write_text(json.dumps({'processed':len(df),'alerts':len(alerts),'top_alerts':sorted(alerts,key=lambda x:x['risk_score'],reverse=True)[:10]},indent=2))
    print(f'[+] processed={len(df)} alerts={len(alerts)} output=outputs/stream_alerts.jsonl')
if __name__=='__main__': main()
