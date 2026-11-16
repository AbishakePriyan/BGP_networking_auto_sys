import time, requests
base='http://127.0.0.1:8000/api'
def post(path,body=None):
 r=requests.post(base+path,json=body,timeout=40); r.raise_for_status(); return r.json()
def state(): return requests.get(base+'/state',timeout=5).json()
def wait_for(f, name):
 for _ in range(40):
  s=state()
  if f(s): print(name, 'OK', flush=True); return s
  time.sleep(.5)
 raise RuntimeError(name+' timed out: '+str(state()))
post('/action/reset'); time.sleep(3)
post('/action/check'); post('/action/ping'); assert state()['connectivity']=='reachable'; print('baseline ping reachable',flush=True)
post('/mode',{'mode':'alert'}); post('/monitor/start'); post('/action/announce')
wait_for(lambda s:any(r['prefix']=='10.199.113.0/25' for r in s['routes']) and s['status']=='alert','alert-only route and alert')
post('/action/ping'); assert state()['connectivity']=='unreachable'; print('attack ping unreachable',flush=True)
post('/action/reset'); wait_for(lambda s:not any(r['prefix']=='10.199.113.0/25' for r in s['routes']),'reset route withdrawn')
post('/mode',{'mode':'automatic'}); post('/action/announce')
wait_for(lambda s:s['filter']=='verified','automatic filter verified')
post('/action/ping'); assert state()['connectivity']=='reachable'; print('recovery ping reachable',flush=True)
post('/action/reset'); post('/monitor/stop'); print('scenario complete; reset requested',flush=True)
