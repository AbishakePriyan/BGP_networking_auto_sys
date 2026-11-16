import asyncio, json, sqlite3, subprocess, time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from core import routes, vty, filter_commands, reset_commands
from backend.contract import classify
from backend.replay import Replay
from backend.public_feed import PublicFeed
from backend.public_alert_store import PublicAlertStore
from backend.training_audit import audit_current_data
from backend.rpki import validate_rpki

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = json.loads((ROOT / 'authorized_prefixes.json').read_text())
DB = ROOT / 'logs' / 'events.sqlite3'
DB.parent.mkdir(exist_ok=True)
def record(kind, **details):
    event = {'timestamp':datetime.now(timezone.utc).isoformat(), 'kind':kind, **details}
    with sqlite3.connect(DB) as c:
        c.execute('create table if not exists events (id integer primary key, data text not null)')
        c.execute('insert into events(data) values (?)', (json.dumps(event),))
    return event

def events():
    with sqlite3.connect(DB) as c:
        c.execute('create table if not exists events (id integer primary key, data text not null)')
        return [json.loads(x[0]) for x in c.execute('select data from events order by id desc limit 100')]

state = {'monitoring':False, 'mode':'alert', 'routes':[], 'status':'unavailable', 'connectivity':'unavailable', 'last_poll':None, 'error':None, 'filter':'not requested'}
lock = asyncio.Lock()
worker = None
seen = set()
replay = Replay()
replay.load()
view = {'source':'live'}
@lru_cache(maxsize=8)
def get_public_alert_store(path):
    return PublicAlertStore(path)

def store_public_alerts(rows):
    get_public_alert_store(str(DB)).record_many(rows)

public_feed = PublicFeed(alert_sink=store_public_alerts)

def command_attack(on):
    configured = '  network 10.199.113.0/25' in vty('r3', ['show running-config'])
    if configured == on:
        return
    vty('r3', ['configure terminal','router bgp 65003','address-family ipv4 unicast', ('network' if on else 'no network') + ' 10.199.113.0/25','end'])

def ping():
    p = subprocess.run(['docker','exec','bgpguard-v2-r2','ping','-c','2','-W','1','10.199.113.10'], capture_output=True, text=True, timeout=10)
    return p.returncode == 0

def collect():
    return routes()

def apply_filter(route):
    if route['peer'] != '10.199.0.4' or route['prefix'] != '10.199.113.0/25':
        raise ValueError('Only the documented attacker peer and prefix are allowed')
    vty('r2', filter_commands(route['peer'],route['prefix']))
    for _ in range(20):
        time.sleep(.25)
        if not any(r['peer']==route['peer'] and r['prefix']==route['prefix'] for r in collect()):
            return True
    return False

async def poll():
    global seen
    while state['monitoring']:
        try:
            async with lock:
                if not state['monitoring'] or view['source']!='live': continue
                current = await asyncio.to_thread(collect)
                state.update(routes=current, last_poll=datetime.now(timezone.utc).isoformat(), error=None, status='normal')
                keys=set()
                for r in current:
                    key=(r['prefix'],r['peer'],tuple(r['as_path']))
                    keys.add(key)
                    if classify(r['prefix'],r['origin_as'],REGISTRY)=='suspicious':
                        state['status']='alert'
                        if key not in seen:
                            record('alert', route=r, explanation='Origin differs from the configured lab authorization baseline; this is a rule, not proof of malicious intent.')
                            if state['mode']=='automatic':
                                state['filter']='pending'; state['connectivity']='stale'; record('filter_requested',route=r)
                                try:
                                    ok=await asyncio.to_thread(apply_filter,r)
                                    state['filter']='verified' if ok else 'failed'
                                    record('filter_'+state['filter'], route=r)
                                except Exception as e:
                                    state['filter']='failed'; record('filter_failed',error=str(e))
                seen=keys
        except Exception as e:
            state.update(status='unavailable',error=str(e))
        await asyncio.sleep(1)

@asynccontextmanager
async def lifespan(app):
    yield
    state['monitoring']=False
    if worker: worker.cancel()
    replay.pause()
    public_feed.stop()
app=FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=['http://localhost:5173','http://127.0.0.1:5173'],allow_methods=['GET','POST'],allow_headers=['Content-Type'])
@app.middleware('http')
async def check_origin(request: Request, call_next):
    origin=request.headers.get('origin')
    if origin and origin not in ('http://localhost:5173','http://127.0.0.1:5173'):
        return JSONResponse({'detail':'Origin not allowed'},status_code=403)
    return await call_next(request)

class ReplayControl(BaseModel):
    action: Literal['play','pause','reset','speed']
    speed: float = 60

class Scenario(BaseModel):
    scenario: Literal['sample','youtube-2008']

class PublicRequest(BaseModel):
    prefix: str
    allowed_origins: list[int] = []
    baseline_source: str | None = None

class Source(BaseModel):
    source: Literal['live','historical','public']

class Mode(BaseModel):
    mode: Literal['alert','automatic']

@app.get('/api/state')
async def get_state(): return {**state,'events':events(), 'source':view['source'], 'replay':replay.snapshot(), 'public':public_feed.snapshot(), 'model':'Authorization baseline rule; synthetic model not used'}
@app.get('/api/public/alerts')
async def public_alerts():
    return {'alerts':await asyncio.to_thread(get_public_alert_store(str(DB)).list_alerts), 'note':'Candidate history, not confirmed incidents or current routing state.'}
@app.get('/api/public/alerts/{alert_id}/rpki')
async def public_alert_rpki(alert_id:int):
    if alert_id < 1: raise HTTPException(422,'Invalid alert ID')
    alert=await asyncio.to_thread(get_public_alert_store(str(DB)).get_alert,alert_id)
    if not alert: raise HTTPException(404,'Candidate not found')
    try: return await validate_rpki(alert['prefix'],alert['origin_asn'])
    except Exception as exc: raise HTTPException(503,'RPKI evidence unavailable: '+str(exc))
@app.get('/api/public/alerts/{alert_id}/observations')
async def public_alert_observations(alert_id:int):
    if alert_id < 1: raise HTTPException(422,'Invalid alert ID')
    return {'observations':await asyncio.to_thread(get_public_alert_store(str(DB)).list_observations,alert_id)}
@app.post('/api/public/alerts/{alert_id}/resolve')
async def resolve_public_alert(alert_id:int):
    if alert_id < 1: raise HTTPException(422,'Invalid alert ID')
    if not await asyncio.to_thread(get_public_alert_store(str(DB)).resolve,alert_id): raise HTTPException(404,'Open candidate not found')
    return {'status':'resolved', 'note':'Manually resolved; this does not verify Internet routing recovery.'}
@app.get('/api/model/audit')
async def model_audit(): return audit_current_data()
@app.get('/api/health')
async def health():
    try:
        p=await asyncio.to_thread(subprocess.run,['docker','info','--format','{{.ServerVersion}}'],capture_output=True,text=True,timeout=8)
        return {'docker':p.returncode==0,'detail':(p.stdout or p.stderr).strip()}
    except Exception as e: return {'docker':False,'detail':str(e)}
@app.get('/api/replay/scenarios')
async def scenarios(): return {'scenarios':[{'id':'sample','description':'Unlabeled RIPE RIS sample'},{'id':'youtube-2008','description':'2008 YouTube incident, bounded RIPE RIS evidence'}]}
@app.post('/api/source')
async def set_source(body:Source):
    async with lock:
        if body.source!='live':
            state['monitoring']=False; state['status']='stale'
            if worker: worker.cancel()
        if body.source!='historical': replay.pause()
        if body.source!='public': public_feed.stop()
        view['source']=body.source
        return {'source':view['source']}
@app.post('/api/public/start')
async def public_start(body:PublicRequest):
    async with lock:
        if view['source']!='public': raise HTTPException(409,'Select public feed first')
        try: public_feed.start(body.prefix,body.allowed_origins,body.baseline_source)
        except ValueError as e: raise HTTPException(422,str(e))
        return public_feed.snapshot()
@app.post('/api/public/stop')
async def public_stop():
    async with lock:
        public_feed.stop()
        return public_feed.snapshot()
@app.post('/api/replay/scenario')
async def select_scenario(body:Scenario):
    if view['source']!='historical': raise HTTPException(409,'Select historical replay first')
    replay.pause(); replay.load(body.scenario)
    if not replay.records: raise HTTPException(404,'Scenario data not collected')
    return replay.snapshot()
@app.post('/api/replay/control')
async def playback(body:ReplayControl):
    if view['source']!='historical': raise HTTPException(409,'Select historical replay first')
    if not 1 <= body.speed <= 3600: raise HTTPException(422,'Speed must be between 1 and 3600')
    replay.speed=body.speed
    if body.action=='pause': replay.pause()
    elif body.action=='reset': replay.pause(); replay.load()
    elif body.action=='play':
        try: replay.play()
        except ValueError as e: raise HTTPException(409,str(e))
    return replay.snapshot()
@app.post('/api/mode')
async def set_mode(body:Mode):
    if view['source']!='live': raise HTTPException(409,'Live controls unavailable in historical replay')
    state['mode']=body.mode; record('mode_changed',mode=body.mode); return state
@app.post('/api/monitor/{action}')
async def monitor(action:Literal['start','stop']):
    global worker,seen
    if view['source']!='live': raise HTTPException(409,'Live controls unavailable in historical replay')
    if action=='start' and not state['monitoring']:
        seen=set(); state['monitoring']=True; worker=asyncio.create_task(poll()); record('monitor_started')
    elif action=='stop':
        state['monitoring']=False; state['status']='stale'
        if worker: worker.cancel()
        record('monitor_stopped')
    return {'monitoring':state['monitoring']}
@app.post('/api/action/{action}')
async def action(action:Literal['check','announce','withdraw','filter','ping','reset']):
    global seen
    if view['source']!='live': raise HTTPException(409,'Live controls unavailable in historical replay')
    async with lock:
        if view['source']!='live': raise HTTPException(409,'Live controls unavailable in historical replay')
        try:
            if action=='check':
                state['routes']=await asyncio.to_thread(collect); state['last_poll']=datetime.now(timezone.utc).isoformat(); state['status']='normal'; state['error']=None
            elif action in ('announce','withdraw'):
                state['connectivity']='stale'; state['status']='pending'
                await asyncio.to_thread(command_attack,action=='announce'); record('announcement_requested' if action=='announce' else 'withdrawal_requested')
            elif action=='filter':
                current=await asyncio.to_thread(collect)
                suspect=next((r for r in current if r['peer']=='10.199.0.4' and r['prefix']=='10.199.113.0/25'),None)
                if not suspect: raise ValueError('No accepted attacker route is present')
                state['filter']='pending'; state['connectivity']='stale'; record('filter_requested',route=suspect)
                try: ok=await asyncio.to_thread(apply_filter,suspect)
                except Exception:
                    state['filter']='failed'; record('filter_failed'); raise
                state['filter']='verified' if ok else 'failed'; record('filter_'+state['filter'],route=suspect)
            elif action=='ping':
                ok=await asyncio.to_thread(ping); state['connectivity']='reachable' if ok else 'unreachable'; record('connectivity_checked',result=state['connectivity'])
            elif action=='reset':
                await asyncio.to_thread(command_attack,False); await asyncio.to_thread(vty,'r2',reset_commands()); seen=set(); state.update(filter='not requested',connectivity='unavailable',status='pending'); record('reset_requested',note='Events retained; route convergence must be observed separately')
            return state
        except Exception as e:
            state['error']=str(e); record('action_failed',action=action,error=str(e)); raise HTTPException(503,str(e))
@app.websocket('/ws')
async def ws(socket:WebSocket):
    if socket.headers.get('origin') not in ('http://localhost:5173','http://127.0.0.1:5173'):
        await socket.close(code=1008); return
    await socket.accept()
    try:
        while True:
            await socket.send_json({**state,'events':events(),'source':view['source'],'replay':replay.snapshot(),'public':public_feed.snapshot()}); await asyncio.sleep(1)
    except (WebSocketDisconnect,RuntimeError): pass
