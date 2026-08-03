#!/usr/bin/env python3
import argparse, random, math, csv, ipaddress
from pathlib import Path
from datetime import datetime, timedelta

LABELS = ['Benign','PortScan','DDoS','BruteForce','Exfiltration','C2Beacon']

def ip(private=True):
    if private:
        return f"10.10.{random.randint(1,8)}.{random.randint(2,250)}"
    return f"203.0.113.{random.randint(2,250)}"

def row_for(label, ts):
    proto = random.choice(['TCP','UDP'])
    if label == 'Benign':
        duration=random.expovariate(1/7)+0.2; sp=random.randint(1024,65000); dp=random.choice([53,80,123,443,993,22])
        packets=random.randint(3,90); bytes_out=random.randint(200,90000); bytes_in=random.randint(200,140000); flags='SF'; alert_count=0; unique_ports=random.randint(1,4); failed=0
    elif label == 'PortScan':
        duration=random.uniform(0.01,1.5); sp=random.randint(1024,65000); dp=random.randint(1,65535)
        packets=random.randint(1,5); bytes_out=random.randint(40,400); bytes_in=random.randint(0,200); flags=random.choice(['S0','REJ']); alert_count=random.randint(1,3); unique_ports=random.randint(20,300); failed=random.randint(5,80)
    elif label == 'DDoS':
        duration=random.uniform(0.1,5); sp=random.randint(1024,65000); dp=random.choice([80,443,53])
        packets=random.randint(500,8000); bytes_out=random.randint(20000,2000000); bytes_in=random.randint(0,5000); flags=random.choice(['S0','SF']); alert_count=random.randint(2,8); unique_ports=random.randint(1,5); failed=random.randint(0,3)
    elif label == 'BruteForce':
        duration=random.uniform(2,80); sp=random.randint(1024,65000); dp=random.choice([22,3389,445,21,25])
        packets=random.randint(30,500); bytes_out=random.randint(5000,150000); bytes_in=random.randint(1000,40000); flags=random.choice(['REJ','S0','SF']); alert_count=random.randint(1,5); unique_ports=random.randint(1,3); failed=random.randint(30,400)
    elif label == 'Exfiltration':
        duration=random.uniform(20,600); sp=random.randint(1024,65000); dp=random.choice([443,22,8080,8443])
        packets=random.randint(200,4000); bytes_out=random.randint(2000000,40000000); bytes_in=random.randint(5000,500000); flags='SF'; alert_count=random.randint(0,3); unique_ports=random.randint(1,6); failed=random.randint(0,2)
    else: # C2Beacon
        duration=random.uniform(0.05,3); sp=random.randint(1024,65000); dp=random.choice([443,80,53,8080])
        packets=random.randint(3,30); bytes_out=random.randint(100,3000); bytes_in=random.randint(100,8000); flags='SF'; alert_count=random.randint(0,2); unique_ports=random.randint(1,3); failed=random.randint(0,2)
    bps=(bytes_in+bytes_out)/max(duration,0.01)
    pps=packets/max(duration,0.01)
    out_ratio=bytes_out/max(bytes_in+bytes_out,1)
    entropy=random.uniform(2.0,4.5) if label=='Benign' else random.uniform(3.5,7.8)
    beacon_score=random.uniform(0,0.2) if label!='C2Beacon' else random.uniform(0.75,0.99)
    burst_score=min(1.0, math.log1p(pps)/8)
    return {
        'timestamp':ts.isoformat(), 'src_ip': ip(True), 'dst_ip': ip(False if label in ['Exfiltration','C2Beacon'] else True),
        'src_port':sp, 'dst_port':dp, 'proto':proto, 'duration':round(duration,4), 'packets':packets,
        'bytes_out':bytes_out, 'bytes_in':bytes_in, 'bytes_per_sec':round(bps,4), 'packets_per_sec':round(pps,4),
        'outbound_ratio':round(out_ratio,4), 'unique_dst_ports_5m':unique_ports, 'failed_conn_5m':failed,
        'dns_entropy':round(entropy,4), 'beacon_score':round(beacon_score,4), 'burst_score':round(burst_score,4),
        'suricata_alert_count':alert_count, 'tcp_state':flags, 'asset_criticality': random.choice([1,2,2,3,4,5]), 'label':label
    }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--rows',type=int,default=12000); ap.add_argument('--out',default='data/synthetic_flows.csv'); args=ap.parse_args()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    weights=[0.62,0.10,0.08,0.08,0.06,0.06]
    ts=datetime.utcnow()-timedelta(hours=8)
    with open(args.out,'w',newline='') as f:
        writer=None
        for i in range(args.rows):
            label=random.choices(LABELS,weights=weights)[0]
            ts += timedelta(seconds=random.randint(1,7))
            row=row_for(label,ts)
            if writer is None:
                writer=csv.DictWriter(f,fieldnames=list(row.keys())); writer.writeheader()
            writer.writerow(row)
    print(f'[+] wrote {args.rows} rows to {args.out}')
if __name__=='__main__': main()
