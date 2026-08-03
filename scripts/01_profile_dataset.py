#!/usr/bin/env python3
from pathlib import Path
import pandas as pd, json

def main():
    path=Path('data/synthetic_flows.csv')
    if not path.exists():
        raise SystemExit('Run 00_generate_synthetic_network_data.py first')
    df=pd.read_csv(path)
    Path('outputs').mkdir(exist_ok=True)
    report={
        'rows': int(len(df)),
        'columns': list(df.columns),
        'label_counts': df['label'].value_counts().to_dict(),
        'missing_values': df.isna().sum().to_dict(),
        'numeric_summary': df.select_dtypes('number').describe().round(3).to_dict()
    }
    Path('outputs/data_profile.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({'rows': report['rows'], 'label_counts': report['label_counts']}, indent=2))
if __name__=='__main__': main()
