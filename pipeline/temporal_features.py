"""Historical UPDATE features v1; strictly prior timestamps, never labels.

Counts are collector observations, not independent Internet events. The caller
must supply an appropriate prior RIB and complete UPDATE stream to claim a
complete history. RIB rows seed state but are not counted as UPDATE messages.
This contract is not compatible with the polling-only FRR lab collector.
"""
from collections import defaultdict, deque
from datetime import datetime, timedelta
import ipaddress, re

CONTRACT='historical-update-v1'

def require_collector_compatibility(collector):
    if collector != 'historical-updates':
        raise ValueError('historical-update-v1 requires historical UPDATE observations and is incompatible with RIB polling')

def _timestamp(row):
    value=datetime.fromisoformat(row['timestamp_utc'].replace('Z','+00:00'))
    if value.tzinfo is None: raise ValueError('UTC-aware observation timestamp required')
    return value

def _path(value):
    if isinstance(value,str) and re.fullmatch(r'\d+(?:\s+\d+)*',value.strip()):
        values=[int(part) for part in value.split()]
        return values if all(0<n<=4294967295 for n in values) else None
    if isinstance(value,list) and value and all(type(n) is int and 0<n<=4294967295 for n in value):
        return value
    return None

def _origin(row):
    origins=row.get('origin_asns')
    return origins[0] if isinstance(origins,list) and len(origins)==1 and type(origins[0]) is int and 0<origins[0]<=4294967295 else None

def extract_temporal(rows):
    """Return source rows with features. Equal timestamps observe the same prior state."""
    ordered=sorted(enumerate(rows),key=lambda item:(_timestamp(item[1]),item[0]))
    history=defaultdict(deque); origins=defaultdict(set); edges=defaultdict(set); peers=defaultdict(set)
    result=[]; index=0
    while index<len(ordered):
        now=_timestamp(ordered[index][1]); end=index
        while end<len(ordered) and _timestamp(ordered[end][1])==now: end+=1
        batch=ordered[index:end]
        pending=[]
        for _,row in batch:
            prefix=str(ipaddress.ip_network(row['prefix'],strict=True))
            bucket=history[prefix]
            while bucket and bucket[0][0] < now-timedelta(hours=1): bucket.popleft()
            path=_path(row.get('as_path')) if row.get('type')=='A' else None
            origin=_origin(row) if row.get('type')=='A' else None
            path_edges=set(zip(path,path[1:])) if path is not None else None
            source=str(row.get('source_url') or '')
            is_rib='/bview.' in source or '/rib.' in source.lower()
            features={'prefix_length':ipaddress.ip_network(prefix).prefixlen,
                'as_path_length':len(path) if path is not None else None,
                'repeated_as_count':len(path)-len(set(path)) if path is not None else None,
                'origin_seen_before':origin in origins[prefix] if origin is not None else None,
                'new_path_edges':len(path_edges-edges[prefix]) if path_edges is not None else None,
                'prior_announcements_1h':sum(kind=='A' for _,kind in bucket),
                'prior_withdrawals_1h':sum(kind=='W' for _,kind in bucket),
                'prior_distinct_peers':len(peers[prefix])}
            result.append({'observation':row,'feature_contract':CONTRACT,'history_complete':False,'features':features})
            pending.append((prefix,row,path_edges,origin,is_rib))
        for prefix,row,path_edges,origin,is_rib in pending:
            if origin is not None: origins[prefix].add(origin)
            if path_edges is not None: edges[prefix].update(path_edges)
            if row.get('peer_ip'): peers[prefix].add((row.get('collector'),row['peer_ip']))
            if row.get('type') in ('A','W') and not is_rib: history[prefix].append((now,row['type']))
        index=end
    return result
