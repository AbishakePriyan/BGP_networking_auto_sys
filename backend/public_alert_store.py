"""Durable operator-baseline mismatch candidates, not confirmed hijacks."""
import hashlib, json, sqlite3
from datetime import datetime, timezone
from pathlib import Path

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

class PublicAlertStore:
    def __init__(self, path):
        self.path=Path(path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('''CREATE TABLE IF NOT EXISTS public_alerts (
              id INTEGER PRIMARY KEY, group_key TEXT NOT NULL UNIQUE, watch_prefix TEXT NOT NULL,
              prefix TEXT NOT NULL, origin_asn INTEGER NOT NULL, allowed_origins TEXT NOT NULL,
              authorization_source TEXT NOT NULL, first_recorded_utc TEXT NOT NULL,
              last_recorded_utc TEXT NOT NULL, last_observed_utc TEXT NOT NULL,
              observation_count INTEGER NOT NULL, status TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS public_alert_observations (
              observation_key TEXT PRIMARY KEY, alert_id INTEGER NOT NULL,
              FOREIGN KEY(alert_id) REFERENCES public_alerts(id))''')
            columns={row[1] for row in db.execute('PRAGMA table_info(public_alert_observations)')}
            for column in ('timestamp_utc','collector','peer_ip','peer_asn','message_id','as_path'):
                if column not in columns: db.execute(f'ALTER TABLE public_alert_observations ADD COLUMN {column} TEXT')
    def record_many(self, events):
        now=datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.path,timeout=10) as db:
            for event in events:
                if event.get('assessment')!='origin_mismatch': continue
                baseline=sorted(set(event['allowed_origins']))
                group=digest([event['watch_prefix'],event['prefix'],event['origin_asn'],baseline,event['authorization_source']])
                obs=digest([group,event.get('message_id'),event.get('peer_ip'),event.get('collector'),event.get('timestamp_utc'),event['prefix']])
                if db.execute('SELECT 1 FROM public_alert_observations WHERE observation_key=?',(obs,)).fetchone(): continue
                db.execute('''INSERT INTO public_alerts(group_key,watch_prefix,prefix,origin_asn,allowed_origins,authorization_source,first_recorded_utc,last_recorded_utc,last_observed_utc,observation_count,status)
                 VALUES(?,?,?,?,?,?,?,?,?,0,'open') ON CONFLICT(group_key) DO NOTHING''',
                 (group,event['watch_prefix'],event['prefix'],event['origin_asn'],json.dumps(baseline),event['authorization_source'],now,now,event['timestamp_utc']))
                ident=db.execute('SELECT id FROM public_alerts WHERE group_key=?',(group,)).fetchone()[0]
                db.execute('''INSERT INTO public_alert_observations
                    (observation_key,alert_id,timestamp_utc,collector,peer_ip,peer_asn,message_id,as_path)
                    VALUES (?,?,?,?,?,?,?,?)''',(obs,ident,event.get('timestamp_utc'),event.get('collector'),
                    event.get('peer_ip'),str(event.get('peer_asn')) if event.get('peer_asn') is not None else None,
                    str(event.get('message_id')) if event.get('message_id') is not None else None,
                    json.dumps(event.get('as_path'))))
                db.execute('''UPDATE public_alerts SET observation_count=observation_count+1,
                  last_recorded_utc=?, last_observed_utc=MAX(last_observed_utc,?), status='open' WHERE id=?''',
                  (now,event['timestamp_utc'],ident))
    def list_alerts(self,limit=100):
        with sqlite3.connect(self.path,timeout=10) as db:
            db.row_factory=sqlite3.Row
            result=[]
            for row in db.execute('SELECT * FROM public_alerts ORDER BY last_recorded_utc DESC,id DESC LIMIT ?', (min(max(limit,1),500),)):
                item=dict(row); item.pop('group_key'); item['allowed_origins']=json.loads(item['allowed_origins']); result.append(item)
            return result
    def get_alert(self,alert_id):
        with sqlite3.connect(self.path,timeout=10) as db:
            db.row_factory=sqlite3.Row
            row=db.execute('SELECT * FROM public_alerts WHERE id=?',(alert_id,)).fetchone()
            if not row: return None
            item=dict(row); item.pop('group_key'); item['allowed_origins']=json.loads(item['allowed_origins']); return item
    def list_observations(self,alert_id,limit=100):
        with sqlite3.connect(self.path,timeout=10) as db:
            db.row_factory=sqlite3.Row
            rows=db.execute('''SELECT timestamp_utc,collector,peer_ip,peer_asn,message_id,as_path
                FROM public_alert_observations WHERE alert_id=? ORDER BY timestamp_utc DESC LIMIT ?''',
                (alert_id,min(max(limit,1),500)))
            result=[]
            for row in rows:
                item=dict(row); item['as_path']=json.loads(item['as_path']) if item['as_path'] else None; result.append(item)
            return result
    def resolve(self,alert_id):
        with sqlite3.connect(self.path,timeout=10) as db:
            return db.execute("UPDATE public_alerts SET status='resolved' WHERE id=? AND status='open'",(alert_id,)).rowcount==1
