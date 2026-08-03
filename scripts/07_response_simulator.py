#!/usr/bin/env python3
import argparse, json, ipaddress
from pathlib import Path

def private(ip):
    try: return ipaddress.ip_address(ip).is_private
    except Exception: return False

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--dry-run',action='store_true',default=True); ap.add_argument('--execute-lab-only',action='store_true'); args=ap.parse_args()
    alerts=[]
    p=Path('outputs/stream_alerts.jsonl')
    if p.exists():
        alerts=[json.loads(x) for x in p.read_text().splitlines() if x.strip()]
    plan=[]
    for a in sorted(alerts,key=lambda x:x['risk_score'],reverse=True)[:20]:
        action='monitor'
        if a['risk_score']>=85: action='recommend_isolate_lab_host'
        elif a['risk_score']>=70: action='escalate_to_tier2'
        plan.append({'src_ip':a['src_ip'],'dst_ip':a['dst_ip'],'threat':a['predicted_threat'],'risk_score':a['risk_score'],'recommended_action':action,'mode':'dry-run','reason':'AI score + telemetry evidence + asset criticality. Human approval required.'})
    Path('outputs/response_plan_lab_only.json').write_text(json.dumps({'safety':'Dry-run by default. Do not execute on production networks.','actions':plan},indent=2))
    print('[+] wrote outputs/response_plan_lab_only.json')
if __name__=='__main__': main()
