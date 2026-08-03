#!/usr/bin/env python3
import argparse, json
from pathlib import Path
import numpy as np, torch
torch.set_num_threads(1)
from torch import nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.metrics import classification_report, confusion_matrix, f1_score
import joblib
from sentinel_utils import split_scaled, save_json, FEATURES

class ResidualBlock(nn.Module):
    def __init__(self, dim, dropout):
        super().__init__(); self.net=nn.Sequential(nn.Linear(dim,dim), nn.BatchNorm1d(dim), nn.ReLU(), nn.Dropout(dropout), nn.Linear(dim,dim), nn.BatchNorm1d(dim)); self.act=nn.ReLU()
    def forward(self,x): return self.act(x+self.net(x))
class IDSNet(nn.Module):
    def __init__(self, in_dim, classes, hidden=96, dropout=0.15):
        super().__init__(); self.net=nn.Sequential(nn.Linear(in_dim,hidden), nn.BatchNorm1d(hidden), nn.ReLU(), ResidualBlock(hidden,dropout), ResidualBlock(hidden,dropout), nn.Linear(hidden,classes))
    def forward(self,x): return self.net(x)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--epochs',type=int,default=8); ap.add_argument('--batch',type=int,default=256); args=ap.parse_args()
    Path('models').mkdir(exist_ok=True); Path('outputs').mkdir(exist_ok=True)
    df,Xtr,Xte,ytr,yte,scaler,le=split_scaled()
    device='cpu'
    model=IDSNet(Xtr.shape[1], len(le.classes_)).to(device)
    counts=np.bincount(ytr); weights=(counts.max()/np.maximum(counts,1)).astype('float32')
    loss_fn=nn.CrossEntropyLoss(weight=torch.tensor(weights,device=device))
    opt=torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    dl=DataLoader(TensorDataset(torch.tensor(Xtr), torch.tensor(ytr).long()), batch_size=args.batch, shuffle=True)
    for epoch in range(args.epochs):
        model.train(); total=0
        for xb,yb in dl:
            xb,yb=xb.to(device),yb.to(device); opt.zero_grad(); loss=loss_fn(model(xb),yb); loss.backward(); opt.step(); total+=loss.item()*len(xb)
        print(f'epoch={epoch+1} loss={total/len(Xtr):.4f}')
    model.eval()
    with torch.no_grad():
        logits=model(torch.tensor(Xte).to(device)); prob=torch.softmax(logits,dim=1).cpu().numpy(); pred=prob.argmax(1)
    metrics={'classes': le.classes_.tolist(), 'macro_f1': float(f1_score(yte,pred,average='macro')), 'weighted_f1': float(f1_score(yte,pred,average='weighted')), 'classification_report': classification_report(yte,pred,target_names=le.classes_,output_dict=True), 'confusion_matrix': confusion_matrix(yte,pred).tolist(), 'features': FEATURES}
    save_json(metrics,'outputs/supervised_metrics.json')
    torch.save(model.state_dict(),'models/supervised_ids.pt'); joblib.dump({'scaler':scaler,'label_encoder':le,'features':FEATURES},'models/preprocess.joblib')
    print(json.dumps({'macro_f1':metrics['macro_f1'],'weighted_f1':metrics['weighted_f1']},indent=2))
if __name__=='__main__': main()
