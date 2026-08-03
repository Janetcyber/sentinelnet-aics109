#!/usr/bin/env python3
import argparse, json
from pathlib import Path
import numpy as np, torch, joblib
from torch import nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
from sentinel_utils import split_scaled, save_json, FEATURES

class AutoEncoder(nn.Module):
    def __init__(self, d):
        super().__init__(); self.enc=nn.Sequential(nn.Linear(d,64),nn.ReLU(),nn.Linear(64,24),nn.ReLU(),nn.Linear(24,8)); self.dec=nn.Sequential(nn.Linear(8,24),nn.ReLU(),nn.Linear(24,64),nn.ReLU(),nn.Linear(64,d))
    def forward(self,x): return self.dec(self.enc(x))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--epochs',type=int,default=8); args=ap.parse_args()
    Path('models').mkdir(exist_ok=True); Path('outputs').mkdir(exist_ok=True)
    df,Xtr,Xte,ytr,yte,scaler,le=split_scaled()
    benign_train=Xtr[ytr==le.transform(['Benign'])[0]]
    device='cpu'; model=AutoEncoder(Xtr.shape[1]).to(device)
    opt=torch.optim.AdamW(model.parameters(),lr=1e-3); loss_fn=nn.MSELoss(); dl=DataLoader(TensorDataset(torch.tensor(benign_train)),batch_size=256,shuffle=True)
    for e in range(args.epochs):
        total=0; model.train()
        for (xb,) in dl:
            xb=xb.to(device); opt.zero_grad(); loss=loss_fn(model(xb),xb); loss.backward(); opt.step(); total+=loss.item()*len(xb)
        print(f'epoch={e+1} ae_loss={total/len(benign_train):.5f}')
    model.eval()
    with torch.no_grad():
        recon=model(torch.tensor(Xte).to(device)).cpu().numpy()
    err=((Xte-recon)**2).mean(axis=1); threshold=float(np.percentile(err, 85))
    pred_anom=(err>threshold).astype(int); true_anom=(yte!=le.transform(['Benign'])[0]).astype(int)
    iso=IsolationForest(n_estimators=200, contamination=0.25, random_state=42).fit(benign_train)
    iso_pred=(iso.predict(Xte)==-1).astype(int)
    metrics={'autoencoder_threshold':threshold,'autoencoder_report':classification_report(true_anom,pred_anom,output_dict=True),'isolation_forest_report':classification_report(true_anom,iso_pred,output_dict=True)}
    save_json(metrics,'outputs/anomaly_metrics.json')
    torch.save(model.state_dict(),'models/autoencoder.pt'); joblib.dump(iso,'models/isolation_forest.joblib')
    print(json.dumps({'ae_threshold':threshold},indent=2))
if __name__=='__main__': main()
