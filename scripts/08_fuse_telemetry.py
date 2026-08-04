#!/usr/bin/env python3
"""Zeek + Suricata telemetry fusion for SentinelNet (AICS-109) Lab 7.

Parses the shipped Suricata EVE and Zeek conn sample logs, joins them on the
(src_ip, dest_ip) pair, computes a fused risk score enriched by both sensors,
and maps each fused finding to MITRE ATT&CK.
Writes outputs/telemetry_fusion.json.
"""
import json
from pathlib import Path

ATTACK_MAP = {
    'scan': ('Discovery', 'T1046 Network Service Discovery'),
    'beacon': ('Command and Control', 'T1071 Application Layer Protocol'),
    'bruteforce': ('Credential Access', 'T1110 Brute Force'),
    'exfil': ('Exfiltration', 'T1041 Exfiltration Over C2 Channel'),
    'unknown': ('Uncategorized', 'None'),
}

def classify(signature):
    s = signature.lower()
    if 'scan' in s or 'nmap' in s:
        return 'scan'
    if 'beacon' in s or 'c2' in s or 'command' in s:
        return 'beacon'
    if 'brute' in s or 'login' in s:
        return 'bruteforce'
    if 'exfil' in s or 'data' in s:
        return 'exfil'
    return 'unknown'

def load_jsonl(path):
    rows = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows

def is_external(ip):
    return not (ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'))

def main():
    Path('outputs').mkdir(exist_ok=True)
    suricata = load_jsonl('sample_logs/suricata_eve_sample.jsonl')
    zeek = load_jsonl('sample_logs/zeek_conn_sample.jsonl')

    # index Zeek by (src, dst) for joining
    zeek_index = {}
    for z in zeek:
        key = (z.get('id.orig_h'), z.get('id.resp_h'))
        zeek_index[key] = z

    findings = []
    for a in suricata:
        if a.get('event_type') != 'alert':
            continue
        src, dst = a.get('src_ip'), a.get('dest_ip')
        sig = a.get('alert', {}).get('signature', '')
        sev = a.get('alert', {}).get('severity', 3)
        category = classify(sig)
        tactic, technique = ATTACK_MAP[category]

        # JOIN with Zeek on (src, dst)
        z = zeek_index.get((src, dst))
        corroborated = z is not None

        # fused risk: base from Suricata severity (lower sev num = higher risk in EVE),
        # boosted when Zeek corroborates and when destination is external
        base = {1: 70, 2: 55, 3: 40}.get(sev, 40)
        risk = base
        evidence = {'suricata_signature': sig, 'suricata_severity': sev}
        if corroborated:
            risk += 20
            evidence['zeek_dst_port'] = z.get('id.resp_p')
            evidence['zeek_duration'] = z.get('duration')
            evidence['zeek_orig_bytes'] = z.get('orig_bytes')
            evidence['zeek_resp_bytes'] = z.get('resp_bytes')
            evidence['zeek_conn_state'] = z.get('conn_state')
        if is_external(dst):
            risk += 10
            evidence['external_destination'] = True
        risk = min(risk, 100)

        findings.append({
            'src_ip': src, 'dst_ip': dst, 'category': category,
            'fused_risk_score': risk,
            'corroborated_by_zeek': corroborated,
            'mitre_tactic': tactic, 'mitre_technique': technique,
            'evidence': evidence,
        })

    findings.sort(key=lambda x: x['fused_risk_score'], reverse=True)
    summary = {
        'suricata_alerts': len(suricata),
        'zeek_connections': len(zeek),
        'fused_findings': len(findings),
        'corroborated_findings': sum(1 for f in findings if f['corroborated_by_zeek']),
        'findings': findings,
    }
    Path('outputs/telemetry_fusion.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps({
        'suricata_alerts': summary['suricata_alerts'],
        'zeek_connections': summary['zeek_connections'],
        'fused_findings': summary['fused_findings'],
        'corroborated': summary['corroborated_findings'],
    }, indent=2))
    print('[+] wrote outputs/telemetry_fusion.json')

if __name__ == '__main__':
    main()
