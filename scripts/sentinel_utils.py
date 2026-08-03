from pathlib import Path
import pandas as pd, numpy as np, json
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib

FEATURES=['duration','packets','bytes_out','bytes_in','bytes_per_sec','packets_per_sec','outbound_ratio','unique_dst_ports_5m','failed_conn_5m','dns_entropy','beacon_score','burst_score','suricata_alert_count','asset_criticality']

def load_xy(path='data/synthetic_flows.csv'):
    df=pd.read_csv(path)
    X=df[FEATURES].replace([np.inf,-np.inf],np.nan).fillna(0).astype('float32')
    y=df['label'].astype(str)
    le=LabelEncoder(); y_enc=le.fit_transform(y)
    return df, X, y_enc, le

def split_scaled(path='data/synthetic_flows.csv'):
    df,X,y,le=load_xy(path)
    X_train,X_test,y_train,y_test=train_test_split(X.values,y,test_size=0.25,random_state=42,stratify=y)
    scaler=StandardScaler().fit(X_train)
    return df, scaler.transform(X_train).astype('float32'), scaler.transform(X_test).astype('float32'), y_train, y_test, scaler, le

def save_json(obj,path):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(json.dumps(obj,indent=2))
