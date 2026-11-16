"""Export causal features for a bounded historical observation JSONL file."""
import argparse, collections, hashlib, json
from pathlib import Path
from pipeline.temporal_features import CONTRACT, extract_temporal

def build_dataset(source,output):
    source=Path(source); output=Path(output)
    if source.resolve()==output.resolve(): raise ValueError('Source and output must differ')
    manifest=output.with_suffix(output.suffix+'.manifest.json')
    if output.exists() or manifest.exists(): raise FileExistsError('Output or its manifest already exists')
    data=source.read_bytes(); rows=[json.loads(line) for line in data.decode('utf-8').splitlines() if line.strip()]
    if not rows: raise ValueError('Input contains no observations')
    transformed=extract_temporal(rows)
    encoded=''.join(json.dumps(row,sort_keys=True)+'\n' for row in transformed).encode()
    summary={'source_file':str(source),'source_sha256':hashlib.sha256(data).hexdigest(),
        'output_file':str(output),'output_sha256':hashlib.sha256(encoded).hexdigest(),
        'feature_contract':CONTRACT,'collector_compatibility':'historical-updates only',
        'history_complete':False,'count':len(rows),
        'label_counts':dict(collections.Counter(row.get('label','unknown') for row in rows)),
        'warning':'Features use only supplied prior data; gaps and unknown labels remain unresolved.'}
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('xb') as f: f.write(encoded)
    with manifest.open('x') as f: json.dump(summary,f,indent=2); f.write('\n')
    return summary

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True); parser.add_argument('--output',required=True)
    args=parser.parse_args(); print(json.dumps(build_dataset(args.input,args.output),indent=2))
if __name__=='__main__': main()
