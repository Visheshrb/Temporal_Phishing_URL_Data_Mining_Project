import argparse, hashlib, json, re, warnings
from pathlib import Path
from urllib.parse import urlsplit, unquote
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import tldextract
from scipy.stats import ks_2samp
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import precision_score, recall_score, f1_score, average_precision_score, confusion_matrix, roc_auc_score
from .config import RAW, PROCESSED, FIGURES, METRICS, COLUMN_ALIASES, SEED

extractor = tldextract.TLDExtract(suffix_list_urls=[])
NUM = ["url_length","hostname_length","path_length","query_length","subdomain_count","path_depth","digit_ratio","alpha_ratio","special_char_count","at_count","hyphen_count","dot_count","question_count","equals_count","https_flag","ip_host_flag"]

def colname(cols, aliases):
    m = {str(c).strip().lower(): c for c in cols}
    return next((m[a] for a in aliases if a in m), None)

def source_name(p):
    n=p.stem.lower()
    return next((s for s in ["phishtank","urlhaus","piracema","tranco"] if s in n), n)

def load():
    paths=sorted(list(RAW.glob("*.csv"))+list(RAW.glob("*.txt")))
    if not paths: raise FileNotFoundError(f"Put downloaded CSV/TXT files in {RAW}. See README.")
    frames=[]; manifest=[]
    for p in paths:
        src=source_name(p)
        x=pd.read_csv(p, header=None, names=["domain"], dtype=str) if p.suffix.lower()==".txt" else pd.read_csv(p,dtype=str,low_memory=False)
        uc=colname(x.columns,COLUMN_ALIASES["url"])
        if uc is None: raise ValueError(f"No URL column in {p.name}: {list(x.columns)}. Edit src/config.py.")
        dc=colname(x.columns,COLUMN_ALIASES["date"]); lc=colname(x.columns,COLUMN_ALIASES["label"])
        y=pd.DataFrame({"url":x[uc].astype(str).str.strip()})
        y["date"]=pd.to_datetime(x[dc],errors="coerce",utc=True) if dc else pd.NaT
        y["source"]=src
        if src=="tranco":
            y["label"]=0; y["label_type"]="weak_lower_risk_reference"
            y["url"]=y.url.apply(lambda z:z if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://",z) else "http://"+z)
        elif lc:
            vals=x[lc].astype(str).str.lower().str.strip()
            mp={"1":1,"true":1,"yes":1,"verified":1,"valid":1,"phishing":1,"malicious":1,
                "0":0,"false":0,"no":0,"invalid":0,"benign":0,"clean":0}
            y["label"]=vals.map(mp); y["label_type"]="source_label"
        else:
            y["label"]=1; y["label_type"]="threat_feed_positive"
        y["source_file"]=p.name
        frames.append(y)
        manifest.append({"file":p.name,"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"rows":len(y)})
    (PROCESSED/"source_manifest.json").write_text(json.dumps(manifest,indent=2))
    return pd.concat(frames,ignore_index=True)

def norm(u):
    if pd.isna(u): return None
    u=str(u).strip()
    if not u or u.lower() in {"nan","none","null"}: return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://",u): u="http://"+u
    try:
        p=urlsplit(u); h=(p.hostname or "").lower().rstrip(".")
        if not h: return None
        netloc=h+(f":{p.port}" if p.port else "")
        return f"{p.scheme.lower()}://{netloc}{p.path or '/'}"+(f"?{p.query}" if p.query else "")
    except Exception: return None

def feats(u):
    p=urlsplit(u); h=p.hostname or ""; e=extractor(h); path=unquote(p.path or ""); q=p.query or ""; z=u.lower()
    specials="@-_. /?=%&#".replace(" ","")
    return {"url_length":len(u),"hostname_length":len(h),"path_length":len(path),"query_length":len(q),
      "subdomain_count":len(e.subdomain.split(".")) if e.subdomain else 0,
      "path_depth":len([v for v in path.split("/") if v]),
      "digit_ratio":sum(c.isdigit() for c in z)/max(len(z),1),
      "alpha_ratio":sum(c.isalpha() for c in z)/max(len(z),1),
      "special_char_count":sum(z.count(c) for c in specials),"at_count":z.count("@"),
      "hyphen_count":z.count("-"),"dot_count":z.count("."),"question_count":z.count("?"),
      "equals_count":z.count("="),"https_flag":int(p.scheme=="https"),
      "ip_host_flag":int(bool(re.fullmatch(r"\\d{1,3}(?:\\.\\d{1,3}){3}",h))),
      "tld":e.suffix or "unknown","registered_domain":e.top_domain_under_public_suffix or h}

def metrics(y,pred,prob,model,year,strategy,train_end):
    tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
    try: auc=roc_auc_score(y,prob)
    except ValueError: auc=np.nan
    return {"model":model,"strategy":strategy,"train_end_year":int(train_end),"test_year":int(year),"n_test":len(y),
      "precision":precision_score(y,pred,zero_division=0),"recall":recall_score(y,pred,zero_division=0),
      "f1":f1_score(y,pred,zero_division=0),"pr_auc":average_precision_score(y,prob),"roc_auc":auc,
      "false_positive_rate":fp/max(fp+tn,1),"tp":int(tp),"fp":int(fp),"tn":int(tn),"fn":int(fn)}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--min-year-count",type=int,default=20)
    ap.add_argument("--cluster-sample",type=int,default=10000)
    a=ap.parse_args()
    print("1/6 Loading sources")
    d=load(); print("Rows loaded:",len(d))
    print("2/6 Cleaning")
    d["url"]=d.url.apply(norm); d=d.dropna(subset=["url","label"]).copy()
    d["date"]=pd.to_datetime(d.date,errors="coerce",utc=True); d["label"]=d.label.astype(int)
    d=d.drop_duplicates("url",keep="first")
    d.to_csv(PROCESSED/"clean_urls.csv",index=False)
    print("Clean rows:",len(d),"dated:",d.date.notna().sum())
    print("3/6 Feature extraction")
    f=pd.DataFrame([feats(u) for u in d.url],index=d.index)
    d=pd.concat([d.reset_index(drop=True),f.reset_index(drop=True)],axis=1)
    d.to_csv(PROCESSED/"featured_urls.csv",index=False)
    # EDA
    dated=d.dropna(subset=["date"]).copy(); dated["year"]=dated.date.dt.year
    if len(dated):
        s=dated.groupby(["year","source"]).size().rename("records").reset_index()
        s.to_csv(METRICS/"dataset_summary.csv",index=False)
        s.pivot(index="year",columns="source",values="records").fillna(0).plot(figsize=(10,5),marker="o")
        plt.title("Records by year and source"); plt.tight_layout(); plt.savefig(FIGURES/"records_by_year_source.png",dpi=160); plt.close()
        for c in ["url_length","hostname_length","path_depth","digit_ratio"]:
            sns.lineplot(data=dated,x="year",y=c,hue="source",estimator="median")
            plt.title(f"Median {c} by year and source"); plt.tight_layout(); plt.savefig(FIGURES/f"{c}_over_time.png",dpi=160); plt.close()
    print("4/6 Clustering")
    sample=d.dropna(subset=NUM).sample(min(a.cluster_sample,len(d)),random_state=SEED) if len(d)>=20 else d.iloc[0:0]
    if len(sample)>=20:
        X=sample[NUM].replace([np.inf,-np.inf],np.nan).fillna(0); Xs=StandardScaler().fit_transform(X)
        k=min(5,max(2,len(sample)//10)); sample["cluster"]=KMeans(n_clusters=k,n_init=10,random_state=SEED).fit_predict(Xs)
        sample.groupby("cluster")[NUM].median().to_csv(METRICS/"cluster_summary.csv")
        xy=PCA(n_components=2,random_state=SEED).fit_transform(Xs)
        plt.figure(figsize=(8,6)); plt.scatter(xy[:,0],xy[:,1],c=sample.cluster,s=7,alpha=.5)
        plt.title("K-means URL feature clusters (PCA)"); plt.tight_layout(); plt.savefig(FIGURES/"url_clusters_pca.png",dpi=160); plt.close()
    else: print("Skipping clustering: fewer than 20 usable rows.")
    print("5/6 Feature drift")
    rows=[]
    for y0,y1 in zip(sorted(dated.year.unique())[:-1],sorted(dated.year.unique())[1:]):
        x0=dated[dated.year==y0]; x1=dated[dated.year==y1]
        for c in NUM:
            if len(x0[c].dropna())>=10 and len(x1[c].dropna())>=10:
                st,p=ks_2samp(x0[c].dropna(),x1[c].dropna())
                rows.append({"earlier_year":y0,"later_year":y1,"feature":c,"ks_statistic":st,"p_value":p})
    pd.DataFrame(rows).to_csv(METRICS/"feature_drift.csv",index=False)
    print("6/6 Chronological classification")
    data=dated[dated.label.isin([0,1])].copy(); years=sorted(data.year.unique()); results=[]
    for test_year in years[1:]:
        tr=data[data.year<test_year]; te=data[data.year==test_year]
        if min(len(tr),len(te))<a.min_year_count or tr.label.nunique()<2 or te.label.nunique()<2: continue
        for name,est in [("logistic_regression",LogisticRegression(max_iter=1000,class_weight="balanced",random_state=SEED)),
                         ("random_forest",RandomForestClassifier(n_estimators=200,class_weight="balanced_subsample",random_state=SEED,n_jobs=-1))]:
            pipe=Pipeline([("impute",SimpleImputer(strategy="median")),("scale",StandardScaler()),("model",est)])
            pipe.fit(tr[NUM],tr.label); prob=pipe.predict_proba(te[NUM])[:,1]; pred=(prob>=.5).astype(int)
            results.append(metrics(te.label,pred,prob,name,test_year,"expanding_window",test_year-1))
        # Character n-gram experiment, capped to bound RAM.
        tr2=tr.sample(min(120000,len(tr)),random_state=SEED); te2=te.sample(min(120000,len(te)),random_state=SEED)
        if tr2.label.nunique()==2 and te2.label.nunique()==2:
            pipe=Pipeline([("tfidf",TfidfVectorizer(analyzer="char",ngram_range=(3,5),min_df=2,max_features=30000,sublinear_tf=True)),
              ("model",LogisticRegression(max_iter=400,class_weight="balanced",random_state=SEED))])
            pipe.fit(tr2.url,tr2.label); prob=pipe.predict_proba(te2.url)[:,1]; pred=(prob>=.5).astype(int)
            results.append(metrics(te2.label,pred,prob,"char_ngram_logistic_regression",test_year,"expanding_window",test_year-1))
        recent=tr[tr.year.isin(sorted(tr.year.unique())[-2:])]
        if len(recent)>=a.min_year_count and recent.label.nunique()==2:
            pipe=Pipeline([("impute",SimpleImputer(strategy="median")),("scale",StandardScaler()),
              ("model",LogisticRegression(max_iter=1000,class_weight="balanced",random_state=SEED))])
            pipe.fit(recent[NUM],recent.label); prob=pipe.predict_proba(te[NUM])[:,1]; pred=(prob>=.5).astype(int)
            results.append(metrics(te.label,pred,prob,"logistic_regression",test_year,"rolling_recent_2_years",max(recent.year)))
    res=pd.DataFrame(results); res.to_csv(METRICS/"classification_metrics.csv",index=False)
    if len(res):
        res["series"]=res.model+" / "+res.strategy
        res.pivot_table(index="test_year",columns="series",values="f1").plot(figsize=(11,6),marker="o")
        plt.title("Chronological test F1 by model and strategy"); plt.ylabel("F1"); plt.ylim(0,1)
        plt.tight_layout(); plt.savefig(FIGURES/"temporal_model_f1.png",dpi=160); plt.close()
        print(res[["model","strategy","test_year","precision","recall","f1","pr_auc"]].to_string(index=False))
    else: print("No temporal model results: verify timestamp coverage, class labels, and year sample sizes.")
    print("Pipeline finished. Review all outputs and limitations before drawing conclusions.")

if __name__=="__main__": main()
