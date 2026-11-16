"""Bounded MRT cache and conservative, unlabeled observation export."""
import argparse, hashlib, ipaddress, json, os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import requests
import bgpkit

ROOT=Path(__file__).resolve().parent.parent

def download(url, max_bytes):
    parsed=urlparse(url)
    if parsed.scheme!='https' or parsed.hostname not in {'data.ris.ripe.net','archive.routeviews.org'}:
        raise ValueError('Only HTTPS RIPE RIS and RouteViews archive URLs are accepted')
    filename=Path(parsed.path).name
    if not filename.endswith(('.gz','.bz2')): raise ValueError('Expected a compressed MRT file')
    folder=ROOT/'data'/'cache'; folder.mkdir(parents=True,exist_ok=True)
    target=folder/filename; partial=folder/(filename+'.part')
    h=requests.head(url,timeout=30,allow_redirects=False); h.raise_for_status()
    size=int(h.headers.get('Content-Length','0'))
    if size<=0 or size>max_bytes: raise ValueError(f'Unknown or excessive size: {size} bytes (limit {max_bytes})')
    if not target.exists():
        offset=partial.stat().st_size if partial.exists() else 0
        if offset>size: raise ValueError('Partial cache is larger than remote file')
        headers={'Range':f'bytes={offset}-'} if offset else {}
        with requests.get(url,headers=headers,stream=True,timeout=60,allow_redirects=False) as response:
            response.raise_for_status()
            if offset and response.status_code!=206: raise ValueError('Server did not honor resume request')
            with partial.open('ab' if offset else 'wb') as f:
                for chunk in response.iter_content(65536):
                    f.write(chunk)
                    if f.tell()>size or f.tell()>max_bytes: raise ValueError('Download exceeded declared bound')
        if partial.stat().st_size!=size: raise ValueError('Incomplete download; rerun to resume')
        os.replace(partial,target)
    if target.stat().st_size!=size: raise ValueError('Cached file size differs from server')
    checksum=hashlib.sha256(target.read_bytes()).hexdigest()
    manifest={'url':url,'file':str(target.relative_to(ROOT)),'bytes':size,'sha256':checksum,'downloaded_at_utc':datetime.now(timezone.utc).isoformat(),'etag':h.headers.get('ETag')}
    target.with_suffix(target.suffix+'.manifest.json').write_text(json.dumps(manifest,indent=2))
    return target,manifest

def main():
    p=argparse.ArgumentParser(); p.add_argument('--url',required=True); p.add_argument('--collector',required=True); p.add_argument('--prefix',required=True); p.add_argument('--max-mb',type=int,default=50); args=p.parse_args()
    wanted=ipaddress.ip_network(args.prefix,strict=True)
    path,manifest=download(args.url,args.max_mb*1024*1024)
    output=ROOT/'data'/'observations.jsonl'; count=0; seen=set()
    with output.open('w') as out:
        for elem in bgpkit.Parser(url=str(path)):
            d=elem.to_dict(); net=ipaddress.ip_network(d['prefix'])
            if net.version!=wanted.version or not (net.subnet_of(wanted) or wanted.subnet_of(net)): continue
            row={'source_url':args.url,'collector':args.collector,'timestamp_utc':datetime.fromtimestamp(d['timestamp'],timezone.utc).isoformat(),'peer_asn':d['peer_asn'],'peer_ip':d['peer_ip'],'prefix':d['prefix'],'type':d['elem_type'],'as_path':d['as_path'],'origin_asns':d['origin_asns'],'incident_id':None,'label':'unknown','label_source':None,'label_confidence':None,'processing_version':'0.1','exclusion_reason':'No reviewed incident evidence'}
            key=json.dumps(row,sort_keys=True)
            if key not in seen: out.write(key+'\n'); seen.add(key); count+=1
    print(json.dumps({'manifest':manifest,'observations':count,'output':str(output),'label':'unknown'},indent=2))
if __name__=='__main__': main()
