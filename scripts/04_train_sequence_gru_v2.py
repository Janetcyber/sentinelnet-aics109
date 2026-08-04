#!/usr/bin/env python3
"""Genuine GRU sequence detector for SentinelNet (AICS-109).

Replaces the shipped rolling-window MLP with a true PyTorch GRU.
Sequences are built PER SOURCE HOST so each window represents one
host's behaviour over time. Scaler is fit on training data only.
Keeps the same output contract: outputs/sequence_metrics.json + models/sequence_gru.pt
"""
import argparse, json
from pathlib import Path
import numpy as np, pandas as pd, torch, joblib
from torch import nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score
import sys
sys.path.insert(0, str(Path(__file__).parent))
from sentinel_utils import FEATURES, save_json

torch.manual_seed(42)
np.random.seed(42)

def build_host_sequences(df, window):
    """Build sequences per source host, ordered by time."""
    df = df.sort_values(['src_ip', 'timestamp']).copy()
    xs, ys = [], []
    for _, g in df.groupby('src_ip'):
        feats = g[FEATURES].astype('float32').values
        labels = g['label'].astype(str).values
        for i in range(window, len(g)):
            xs.append(feats[i-window:i])
            ys.append(labels[i])
    return np.array(xs, dtype='float32'), np.array(ys)

class GRUDetector(nn.Module):
    def __init__(self, n_features, n_classes, hidden=64):
        super().__init__()
        self.gru = nn.GRU(input_size=n_features, hidden_size=hidden, batch_first=True)
        self.head = nn.Sequential(nn.ReLU(), nn.Linear(hidden, n_classes))
    def forward(self, x):
        out, h = self.gru(x)
        return self.head(h[-1])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--epochs', type=int, default=10)
    ap.add_argument('--window', type=int, default=8)
    ap.add_argument('--batch', type=int, default=128)
    args = ap.parse_args()
    Path('models').mkdir(exist_ok=True); Path('outputs').mkdir(exist_ok=True)

    df = pd.read_csv('data/synthetic_flows.csv')
    X, y_str = build_host_sequences(df, args.window)
    le = LabelEncoder(); y = le.fit_transform(y_str)

    idx = np.arange(len(X))
    tr, te = train_test_split(idx, test_size=0.25, random_state=42, stratify=y)
    Xtr, Xte, ytr, yte = X[tr], X[te], y[tr], y[te]

    # scaler fit on TRAIN only (reshape to 2D for fitting, then back)
    n_feat = Xtr.shape[2]
    scaler = StandardScaler().fit(Xtr.reshape(-1, n_feat))
    Xtr = scaler.transform(Xtr.reshape(-1, n_feat)).reshape(Xtr.shape).astype('float32')
    Xte = scaler.transform(Xte.reshape(-1, n_feat)).reshape(Xte.shape).astype('float32')

    device = 'cpu'
    model = GRUDetector(n_feat, len(le.classes_)).to(device)
    counts = np.bincount(ytr, minlength=len(le.classes_))
    weights = (counts.max() / np.maximum(counts, 1)).astype('float32')
    loss_fn = nn.CrossEntropyLoss(weight=torch.tensor(weights, device=device))
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    dl = DataLoader(TensorDataset(torch.tensor(Xtr), torch.tensor(ytr).long()),
                    batch_size=args.batch, shuffle=True)

    for epoch in range(args.epochs):
        model.train(); total = 0.0
        for xb, yb in dl:
            opt.zero_grad(); loss = loss_fn(model(xb), yb)
            loss.backward(); opt.step(); total += loss.item() * len(xb)
        print(f'epoch={epoch+1} loss={total/len(Xtr):.4f}')

    model.eval()
    with torch.no_grad():
        pred = model(torch.tensor(Xte)).argmax(1).cpu().numpy()

    metrics = {
        'classes': le.classes_.tolist(),
        'macro_f1': float(f1_score(yte, pred, average='macro')),
        'weighted_f1': float(f1_score(yte, pred, average='weighted')),
        'classification_report': classification_report(yte, pred, target_names=le.classes_, output_dict=True),
        'window': args.window,
        'model_type': 'true GRU (per-host sequences, PyTorch)',
        'n_sequences': int(len(X))
    }
    save_json(metrics, 'outputs/sequence_metrics.json')
    torch.save(model.state_dict(), 'models/sequence_gru.pt')
    joblib.dump({'scaler': scaler, 'label_encoder': le, 'features': FEATURES, 'window': args.window},
                'models/sequence_preprocess.joblib')
    print(json.dumps({'sequence_macro_f1': metrics['macro_f1'],
                      'sequence_weighted_f1': metrics['weighted_f1'],
                      'n_sequences': metrics['n_sequences']}, indent=2))

if __name__ == '__main__':
    main()
