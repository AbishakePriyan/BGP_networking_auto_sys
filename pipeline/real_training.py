"""Historical-only supervised experiment with strict data and split guards.

Input consists of feature export JSONL records. Each supervised record needs
an independently reviewed label and source, a group ID and explicit group
window; the source must attest complete prior history. This does not verify the
quality of those attestations. No public router or lab router is controlled.
"""
import argparse, hashlib, json, math, platform
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import joblib, numpy as np, sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
from backend.training_audit import chronological_group_split
from pipeline.temporal_features import CONTRACT

FEATURES=['prefix_length','as_path_length','repeated_as_count','origin_seen_before','new_path_edges',
          'prior_announcements_1h','prior_withdrawals_1h','prior_distinct_peers']

def validate_model_metadata(metadata,collector):
    if collector!='historical-updates' or metadata.get('collector_compatibility')!='historical-updates only':
        raise ValueError('Model and collector are incompatible')
    if metadata.get('feature_contract')!=CONTRACT or metadata.get('features')!=FEATURES or metadata.get('feature_encoding')!='values+missingness-v1':
        raise ValueError('Model feature contract differs')
    threshold=metadata.get('threshold')
    if type(threshold) not in (int,float) or not math.isfinite(threshold) or not 0<=threshold<=1:
        raise ValueError('Invalid model threshold')

def parse_time(value):
    time=datetime.fromisoformat(value.replace('Z','+00:00'))
    if time.tzinfo is None: raise ValueError('Timezone is required')
    return time

def prepare_data(records):
    supervised=[]; by_group={}
    for item in records:
        observation=item.get('observation',{}); label=observation.get('label','unknown')
        if label=='unknown': continue
        if label not in ('incident_match','reviewed_benign'): raise ValueError('Unsupported supervised label')
        if item.get('feature_contract')!=CONTRACT: raise ValueError('Feature contract mismatch')
        if item.get('history_complete') is not True: raise ValueError('Complete preceding history must be attested for every supervised record')
        features=item.get('features')
        if not isinstance(features,dict) or set(features)!=set(FEATURES): raise ValueError('Unexpected feature schema')
        origin_seen=features['origin_seen_before']
        if origin_seen is not None and type(origin_seen) is not bool: raise ValueError('origin_seen_before must be boolean or null')
        for value in features.values():
            if value is not None and (type(value) not in (int,float,bool) or not math.isfinite(value)):
                raise ValueError('Features must be numeric, boolean or missing')
        group=observation.get('incident_id')
        if not isinstance(group,str) or not group or not observation.get('label_source'): raise ValueError('Reviewed group and label source required')
        try:
            start=parse_time(observation['group_window_start']); end=parse_time(observation['group_window_end']); observed=parse_time(observation['timestamp_utc'])
        except (KeyError,TypeError,ValueError) as exc: raise ValueError('Each record needs a timezone-aware reviewed group window') from exc
        if not start<=observed<=end: raise ValueError('Observation outside group window')
        if group in by_group and by_group[group]!=(start,end): raise ValueError('Inconsistent group windows')
        by_group[group]=(start,end)
        supervised.append({**observation,'_features':features})
    windows=sorted(by_group.items(),key=lambda entry:entry[1][0])
    if any(left[1][1]>=right[1][0] for left,right in zip(windows,windows[1:])):
        raise ValueError('Group windows overlap; merge correlated groups before splitting')
    return chronological_group_split(supervised)

def matrix(rows):
    return np.array([[np.nan if r['_features'][key] is None else float(r['_features'][key]) for key in FEATURES] +
                     [float(r['_features'][key] is None) for key in FEATURES] for r in rows],dtype=float)
def labels(rows): return np.array([int(row['label']=='incident_match') for row in rows])
def scores(y,pred,score):
    return {'precision':float(precision_score(y,pred,zero_division=0)),
        'recall':float(recall_score(y,pred,zero_division=0)), 'f1':float(f1_score(y,pred,zero_division=0)),
        'confusion_matrix':confusion_matrix(y,pred,labels=[0,1]).tolist(),
        'pr_auc_average_precision':float(average_precision_score(y,score)) if len(set(y))==2 else None,
        'false_positives':int(((pred==1)&(y==0)).sum()),'false_positive_unit':'collector observation'}
def summary(rows):
    y=labels(rows)
    return {'rows':len(rows),'groups':len({r['incident_id'] for r in rows}),
            'positive':int(y.sum()),'negative':int(len(y)-y.sum()),'positive_prevalence':float(y.mean())}

def train_and_evaluate(records):
    train,validation,test=prepare_data(records)
    model=Pipeline([('impute',SimpleImputer(strategy='median',add_indicator=False,keep_empty_features=True)),
                    ('forest',RandomForestClassifier(n_estimators=150,max_depth=8,class_weight='balanced',random_state=42,n_jobs=1))])
    model.fit(matrix(train),labels(train))
    validation_scores=model.predict_proba(matrix(validation))[:,1]
    candidates=sorted(set([0.,1.,*validation_scores.tolist()]))
    threshold=max(candidates,key=lambda t:(f1_score(labels(validation),validation_scores>=t,zero_division=0),t))
    y=labels(test); probability=model.predict_proba(matrix(test))[:,1]
    rule=np.array([int(r['_features']['origin_seen_before'] is False) for r in test])
    rule_available=np.array([r['_features']['origin_seen_before'] is not None for r in test])
    rule_result={'coverage':float(rule_available.mean()),'abstained':int((~rule_available).sum()),
                 'metrics':scores(y[rule_available],rule[rule_available],rule[rule_available]) if rule_available.any() else None}
    groups=defaultdict(list)
    for i,row in enumerate(test): groups[row['incident_id']].append(i)
    per_group={}
    for group,idx in groups.items():
        per_group[group]={'rows':len(idx),'positive':int(y[idx].sum()),
                          'random_forest':scores(y[idx],(probability[idx]>=threshold).astype(int),probability[idx])}
    report={'dataset_rows':len(records),'unknown_excluded':sum(r.get('observation',{}).get('label','unknown')=='unknown' for r in records),
        'incident_groups':len({r['incident_id'] for r in train+validation+test if r['label']=='incident_match'}),
        'feature_contract':CONTRACT,'features':FEATURES,'feature_encoding':'values+missingness-v1','collector_compatibility':'historical-updates only',
        'environment':{'python':platform.python_version(),'scikit_learn':sklearn.__version__},
        'label_sources':dict(Counter(r.get('label_source') for r in train+validation+test)),
        'algorithm':'RandomForestClassifier, 150 trees, max_depth=8, balanced class weights, seed=42',
        'train':summary(train),'validation':summary(validation),'test':summary(test),
        'threshold':float(threshold),'threshold_selection':'validation F1; ties prefer higher threshold',
        'score_note':'Random Forest scores are uncalibrated; they are not probabilities of hijacking.',
        'validation_result':scores(labels(validation),(validation_scores>=threshold).astype(int),validation_scores),
        'test_results':{'random_forest':scores(y,(probability>=threshold).astype(int),probability),
                        'prior_origin_rule':rule_result},'test_by_group':per_group,
        'limitations':['Operator-reviewed labels and complete history are attested, not independently verified by this command.',
                       'Collector copies are correlated; false positives are counted per observation.',
                       'Historical UPDATE models are incompatible with FRR RIB polling; no live deployment is implied.']}
    return report,model

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--input',required=True); p.add_argument('--output-dir',required=True); args=p.parse_args()
    source=Path(args.input); raw=source.read_bytes(); records=[json.loads(line) for line in raw.decode().splitlines() if line.strip()]
    report,model=train_and_evaluate(records); report['input_sha256']=hashlib.sha256(raw).hexdigest()
    out=Path(args.output_dir); out.mkdir(parents=True,exist_ok=False)
    (out/'evaluation.json').write_text(json.dumps(report,indent=2)+'\n')
    joblib.dump({'model':model,'feature_contract':CONTRACT,'features':FEATURES,'feature_encoding':'values+missingness-v1','threshold':report['threshold'],'collector_compatibility':'historical-updates only'},out/'model.joblib')
    print(json.dumps(report,indent=2))
if __name__=='__main__': main()
