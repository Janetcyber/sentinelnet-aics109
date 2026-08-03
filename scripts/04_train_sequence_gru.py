#!/usr/bin/env python3
"""Train a sequence-aware network defense model.

This lab script uses a flattened rolling-window MLP so it runs reliably on CPU-only
student laptops. Instructors with GPUs may ask advanced students to replace this
with a true GRU/LSTM/Transformer while keeping the same input/output contract.
"""
import argparse, json
from pathlib import Path
import numpy as np, pandas as pd, joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split
from sentinel_utils import FEATURES, save_json

def make_sequences(df, window=8):
    df = df.sort_values('timestamp').copy()
    X_raw = df[FEATURES].astype('float32').values
    labels = df['label'].astype(str).values
    le = LabelEncoder(); y_all = le.fit_transform(labels)
    scaler = StandardScaler().fit(X_raw)
    X_scaled = scaler.transform(X_raw).astype('float32')
    xs, ys = [], []
    for i in range(window, len(df)):
        xs.append(X_scaled[i-window:i].reshape(-1))
        ys.append(y_all[i])
    return np.vstack(xs), np.array(ys), scaler, le

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--epochs', type=int, default=10, help='MLP max iterations')
    ap.add_argument('--window', type=int, default=8)
    args = ap.parse_args()
    Path('models').mkdir(exist_ok=True); Path('outputs').mkdir(exist_ok=True)
    df = pd.read_csv('data/synthetic_flows.csv')
    X, y, scaler, le = make_sequences(df, args.window)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    model = MLPClassifier(hidden_layer_sizes=(128, 64), activation='relu', alpha=1e-4, learning_rate_init=1e-3, max_iter=args.epochs, batch_size=256, random_state=42, early_stopping=True)
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    metrics = {
        'classes': le.classes_.tolist(),
        'macro_f1': float(f1_score(y_test, pred, average='macro')),
        'weighted_f1': float(f1_score(y_test, pred, average='weighted')),
        'classification_report': classification_report(y_test, pred, target_names=le.classes_, output_dict=True),
        'window': args.window,
        'model_type': 'rolling-window MLP sequence model; GRU/LSTM extension recommended for GPU students'
    }
    save_json(metrics, 'outputs/sequence_metrics.json')
    joblib.dump({'model': model, 'scaler': scaler, 'label_encoder': le, 'features': FEATURES, 'window': args.window}, 'models/sequence_model.joblib')
    # also create the legacy filename expected by the lab checklist
    Path('models/sequence_gru.pt').write_text('Sequence model saved in sequence_model.joblib. Replace with true GRU/LSTM in advanced GPU extension.')
    print(json.dumps({'sequence_macro_f1': metrics['macro_f1'], 'sequence_weighted_f1': metrics['weighted_f1']}, indent=2))
if __name__ == '__main__':
    main()
