"""Collect a small, explicitly bounded RIPE RIS slice of the 2008 YouTube event."""
import ipaddress, json
from datetime import datetime, timezone
from pathlib import Path
import bgpkit
from collect import ROOT, download

BASE='https://data.ris.ripe.net/rrc00/2008.02/'
FILES=['bview.20080224.1559.gz','updates.20080224.1840.gz','updates.20080224.1845.gz','updates.20080224.1850.gz','updates.20080224.1855.gz','updates.20080224.1900.gz']
COVER=ipaddress.ip_network('208.65.152.0/22')
INCIDENT='https://www.ripe.net/about-us/news/youtube-hijacking-a-ripe-ncc-ris-case-study/'
START=datetime.fromisoformat('2008-02-24T18:47:00+00:00').timestamp()
END=datetime.fromisoformat('2008-02-24T21:01:22+00:00').timestamp()

def main():
 rows=[]; seen=set()
 for name in FILES:
  path,manifest=download(BASE+name,30*1024*1024)
  print(name,manifest['bytes'],manifest['sha256'],flush=True)
  for elem in bgpkit.Parser(url=str(path)):
   d=elem.to_dict(); net=ipaddress.ip_network(d['prefix'])
   if net.version!=4 or not net.subnet_of(COVER): continue
   origins=d['origin_asns'] or []
   match=d['elem_type']=='A' and str(net)=='208.65.153.0/24' and origins == [17557] and START<=d['timestamp']<=END
   entry_time=datetime.fromtimestamp(d['timestamp'],timezone.utc).isoformat()
   observation_time='2008-02-24T15:59:00+00:00' if name.startswith('bview.') else entry_time
   row={'source_url':BASE+name,'collector':'rrc00','timestamp_utc':observation_time,'mrt_entry_timestamp_utc':entry_time if name.startswith('bview.') else None,'peer_asn':d['peer_asn'],'peer_ip':d['peer_ip'],'prefix':str(net),'type':d['elem_type'],'as_path':d['as_path'],'origin_asns':origins or None,'incident_id':'youtube-2008' if match else None,'label':'incident_match' if match else 'unknown','label_source':INCIDENT if match else None,'label_confidence':'documented_match' if match else None,'processing_version':'0.2','exclusion_reason':None if match else 'Not a matching announcement; supervised label unknown'}
   key=json.dumps(row,sort_keys=True)
   if key not in seen: seen.add(key); rows.append(row)
 rows.sort(key=lambda x:x['timestamp_utc'])
 out=ROOT/'data'/'youtube_2008.jsonl'; out.write_text(''.join(json.dumps(r,sort_keys=True)+'\n' for r in rows))
 print(json.dumps({'records':len(rows),'incident_matches':sum(r['label']=='incident_match' for r in rows),'path':str(out)},indent=2))
if __name__=='__main__': main()
