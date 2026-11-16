"""Bounded read-only RIPE RIS Live UPDATE observation; never changes routing."""
import asyncio, ipaddress, json
from collections import deque
from datetime import datetime, timezone
import websockets

URL='wss://ris-live.ripe.net/v1/ws/'

def subscription(prefix):
    network=ipaddress.ip_network(prefix,strict=True)
    if (network.version==4 and network.prefixlen<8) or (network.version==6 and network.prefixlen<16):
        raise ValueError('Prefix must be at least /8 for IPv4 or /16 for IPv6')
    return {'type':'ris_subscribe','data':{'type':'UPDATE','prefix':str(network),'moreSpecific':True}}

def normalize(message, watch_prefix, allowed_origins=None, baseline_source=None):
    wanted=ipaddress.ip_network(watch_prefix,strict=True)
    d=message.get('data',{})
    if message.get('type')!='ris_message' or d.get('type')!='UPDATE': return []
    try: stamp=datetime.fromtimestamp(float(d['timestamp']),timezone.utc).isoformat()
    except (KeyError,ValueError,TypeError,OverflowError,OSError): return []
    path=d.get('path') or []
    origin=path[-1] if isinstance(path,list) and path and type(path[-1]) is int else None
    entries=[]
    for group in d.get('announcements') or []:
        if isinstance(group,dict): entries.extend((p,'announcement') for p in group.get('prefixes',[]))
    entries.extend((p,'withdrawal') for p in d.get('withdrawals') or [] if isinstance(p,str))
    result=[]
    for p,kind in entries:
        try: net=ipaddress.ip_network(p,strict=True)
        except (ValueError,TypeError): continue
        if net.version!=wanted.version or not net.subnet_of(wanted): continue
        assessment='unknown'; explanation='No independent authorization baseline; this observation is not a hijack verdict.'
        if kind=='announcement' and origin is not None and allowed_origins and baseline_source:
            assessment='origin_consistent' if origin in allowed_origins else 'origin_mismatch'
            explanation='Origin compared to the operator-supplied baseline; mismatch is not proof of hijacking.'
        result.append({'source':'RIPE RIS Live','timestamp_utc':stamp,'collector':d.get('host'),
          'peer_ip':d.get('peer'),'peer_asn':d.get('peer_asn'),'prefix':str(net),'kind':kind,
          'as_path':path if kind=='announcement' else None,'origin_asn':origin if kind=='announcement' else None,
          'assessment':assessment,'explanation':explanation,'authorization_source':baseline_source if allowed_origins else None,
          'watch_prefix':str(wanted),'allowed_origins':sorted(allowed_origins or []),'message_id':d.get('id')})
    return result

class PublicFeed:
    def __init__(self, alert_sink=None):
        self.alert_sink=alert_sink
        self.task=None; self.running=False; self.status='stopped'; self.prefix=None; self.error=None
        self.events=deque(maxlen=100); self.last_message=None; self.gaps=0; self.allowed_origins=[]; self.baseline_source=None
    def snapshot(self):
        return {'running':self.running,'status':self.status,'prefix':self.prefix,'error':self.error,'last_message_utc':self.last_message,'reconnect_gaps':self.gaps,'allowed_origins':self.allowed_origins,'authorization_source':self.baseline_source,'events':list(self.events), 'notice':'Read-only collector observations, not a full routing table or proof of hijacking. Reconnects may miss updates.'}
    def start(self,prefix,allowed_origins=None,baseline_source=None):
        subscription(prefix)
        allowed_origins=allowed_origins or []
        if any(type(asn) is not int or not 1<=asn<=4294967295 for asn in allowed_origins): raise ValueError('ASNs must be integers between 1 and 4294967295')
        if allowed_origins and not (baseline_source and baseline_source.strip()): raise ValueError('Authorization source is required for expected origins')
        if baseline_source and not allowed_origins: raise ValueError('Expected origins are required with an authorization source')
        if baseline_source and len(baseline_source)>200: raise ValueError('Authorization source is too long')
        if self.running: raise ValueError('Stop the existing public subscription first')
        self.prefix=str(ipaddress.ip_network(prefix,strict=True)); self.events.clear(); self.error=None
        self.last_message=None; self.gaps=0; self.allowed_origins=list(set(allowed_origins)); self.baseline_source=baseline_source.strip() if baseline_source else None; self.running=True; self.status='connecting'
        self.task=asyncio.create_task(self._run())
    def stop(self):
        self.running=False; self.status='stopped'
        if self.task: self.task.cancel(); self.task=None
    async def _run(self):
        delay=1
        while self.running:
            try:
                async with websockets.connect(URL,open_timeout=10,ping_interval=20,max_size=2**20) as ws:
                    await ws.send(json.dumps(subscription(self.prefix)))
                    self.status='connected'; self.error=None; delay=1
                    async for raw in ws:
                        if not self.running: break
                        msg=json.loads(raw)
                        if msg.get('type')=='ris_error': raise RuntimeError(str(msg.get('data','subscription rejected')))
                        if msg.get('type')=='ris_message':
                            self.last_message=datetime.now(timezone.utc).isoformat()
                            observations=normalize(msg,self.prefix,self.allowed_origins,self.baseline_source)
                            candidates=[event for event in observations if event['assessment']=='origin_mismatch']
                            if candidates and self.alert_sink: await asyncio.to_thread(self.alert_sink,candidates)
                            self.events.extendleft(observations)
                    if self.running: raise ConnectionError('Feed disconnected; observations may have been missed')
            except asyncio.CancelledError: raise
            except Exception as exc:
                self.gaps+=1; self.status='reconnecting'; self.error=str(exc)
                await asyncio.sleep(delay); delay=min(delay*2,30)
