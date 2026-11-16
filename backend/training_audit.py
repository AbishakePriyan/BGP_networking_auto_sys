"""Inspectable evidence report; no model is promoted by this module."""
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def audit_current_data():
    path = ROOT / 'data' / 'youtube_2008.jsonl'
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []
    labels = Counter(r.get('label', 'unknown') for r in rows)
    incidents = {r['incident_id'] for r in rows if r.get('label') == 'incident_match' and r.get('incident_id')}
    metrics_path = ROOT / 'artifacts' / 'metrics.json'
    metrics = json.loads(metrics_path.read_text()) if metrics_path.exists() else None
    return {
        'active_detector': 'Lab authorization rule; no ML model is active',
        'synthetic_experiment': {
            'algorithm':'RandomForestClassifier', 'rows':2400, 'class_counts':{'0':1200,'1':1200},
            'split':'75% train, 25% random test, stratified', 'seed':42,
            'target_leakage':'Synthetic label is identical to origin_mismatch input',
            'metrics':metrics, 'generalization_claim':'None; synthetic test only',
            'reproduce_command':'.venv/bin/python train.py',
            'warning':'Reproduction overwrites artifacts/model.joblib and artifacts/metrics.json',
        },
        'historical_data': 'RIPE RIS rrc00, 2008 YouTube incident; see docs/DATASET_CARD.md',
        'historical_feature_contract': 'historical-update-v1; partial history, not compatible with lab RIB polling; not used for a trained model',
        'rows':len(rows), 'labels':dict(labels), 'incident_count':len(incidents),
        'ready_for_training':False,
        'blockers':['One documented incident is not an independent incident-level evaluation',
                    'No reviewed benign training examples', 'Baseline UPDATE interval is incomplete',
                    'No independently validated real-data training or evaluation has been performed'],
    }

def chronological_group_split(rows):
    """Separate time-ordered incident/benign groups; fail closed on ambiguity."""
    groups = defaultdict(list)
    for row in rows:
        if row.get('label') == 'unknown':
            continue
        if row.get('label') not in ('incident_match', 'reviewed_benign') or not row.get('incident_id'):
            raise ValueError('Every supervised record requires an explicit label and group')
        stamp = datetime.fromisoformat(row['timestamp_utc'].replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError('Timestamps must include a timezone')
        groups[row['incident_id']].append((stamp, row))
    if len(groups) < 6:
        raise ValueError('Need at least six independent groups with reviewed labels')
    ordered = sorted(groups, key=lambda k: min(t for t, _ in groups[k]))
    for left, right in zip(ordered, ordered[1:]):
        if max(t for t, _ in groups[left]) >= min(t for t, _ in groups[right]):
            raise ValueError('Incident windows overlap; combine correlated groups before splitting')
    n=len(ordered); cuts=(max(1,int(n*.6)), max(2,int(n*.8)))
    partitions = [ordered[:cuts[0]], ordered[cuts[0]:cuts[1]], ordered[cuts[1]:]]
    out = [[row for group in part for _, row in groups[group]] for part in partitions]
    for part in out:
        if {r['label'] for r in part} != {'incident_match','reviewed_benign'}:
            raise ValueError('Every partition needs both classes; collect more independent groups')
    return tuple(out)
