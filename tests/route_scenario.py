import time, requests
base='http://127.0.0.1:8000/api'
def post(path, body=None):
 r=requests.post(base+path,json=body,timeout=40); r.raise_for_status(); return r.json()
def state(): return requests.get(base+'/state').json()
def wait(f):
 for _ in range(30):
  s=state()
  if f(s): return s
  time.sleep(.5)
 raise RuntimeError(str(state()))
try:
 post('/action/reset'); post('/monitor/start'); post('/mode',{'mode':'alert'}); post('/action/announce')
 s=wait(lambda s:any(r['prefix']=='10.199.113.0/25' for r in s['routes']) and s['status']=='alert'); print('alert-only: /25 accepted and alert observed',flush=True)
 post('/action/ping'); print('attack connectivity:',state()['connectivity'],flush=True)
 post('/action/reset'); wait(lambda s:not any(r['prefix']=='10.199.113.0/25' for r in s['routes']))
 post('/mode',{'mode':'automatic'}); post('/action/announce'); s=wait(lambda s:s['filter']=='verified'); print('automatic: peer/prefix absence verified',flush=True)
 post('/action/ping'); print('post-filter connectivity:',state()['connectivity'],flush=True)
finally:
 post('/action/reset'); post('/monitor/stop')
