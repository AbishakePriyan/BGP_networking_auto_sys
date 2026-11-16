from backend.public_alert_store import PublicAlertStore

def candidate(message_id, peer='192.0.2.1'):
    return {'assessment':'origin_mismatch','prefix':'1.1.1.0/24','origin_asn':64500,
            'authorization_source':'operator registry','watch_prefix':'1.1.1.0/24',
            'allowed_origins':[13335], 'message_id':message_id, 'peer_ip':peer,
            'timestamp_utc':'2026-01-01T00:00:00+00:00', 'collector':'rrc00'}

def test_persists_and_deduplicates_repeated_messages(tmp_path):
    db=tmp_path/'alerts.sqlite3'
    store=PublicAlertStore(db)
    store.record_many([candidate('msg-1'),candidate('msg-1')])
    store.record_many([candidate('msg-2', '192.0.2.2')])
    rows=PublicAlertStore(db).list_alerts()
    assert len(rows)==1 and rows[0]['observation_count']==2
    assert rows[0]['status']=='open' and rows[0]['origin_asn']==64500

def test_resolved_candidate_reopens_only_on_new_observation(tmp_path):
    store=PublicAlertStore(tmp_path/'alerts.sqlite3')
    store.record_many([candidate('msg-1')]); alert=store.list_alerts()[0]
    assert store.resolve(alert['id'])
    store.record_many([candidate('msg-1')]); assert store.list_alerts()[0]['status']=='resolved'
    store.record_many([candidate('msg-2')]); assert store.list_alerts()[0]['status']=='open'

def test_unknown_and_consistent_events_never_create_alerts(tmp_path):
    store=PublicAlertStore(tmp_path/'alerts.sqlite3')
    store.record_many([{**candidate('msg-1'),'assessment':'unknown'}, {**candidate('msg-2'),'assessment':'origin_consistent'}])
    assert store.list_alerts()==[]

def test_feed_persists_mismatches_without_storing_other_observations(tmp_path, monkeypatch):
    import asyncio, json
    import backend.public_feed as service
    msg={'type':'ris_message','data':{'id':'event-42','type':'UPDATE','timestamp':1700000000,
        'peer':'192.0.2.1','host':'rrc00','path':[65000,64500],
        'announcements':[{'prefixes':['1.1.1.0/24']}],'withdrawals':[]}}
    class FakeSocket:
        async def __aenter__(self): return self
        async def __aexit__(self,*args): pass
        async def send(self,data): pass
        def __aiter__(self): return self
        async def __anext__(self):
            if not hasattr(self,'sent'):
                self.sent=True; return json.dumps(msg)
            await asyncio.Future()
    monkeypatch.setattr(service.websockets,'connect',lambda *a,**kw:FakeSocket())
    store=PublicAlertStore(tmp_path/'alerts.sqlite3')
    async def check():
        feed=service.PublicFeed(alert_sink=store.record_many)
        feed.start('1.1.1.0/24',[13335],'operator registry')
        for _ in range(100):
            if store.list_alerts(): break
            await asyncio.sleep(.01)
        feed.stop(); await asyncio.sleep(0)
    asyncio.run(check())
    assert store.list_alerts()[0]['observation_count']==1

def test_api_lists_and_resolves_candidate_history(tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    import backend.main as app_module
    monkeypatch.setattr(app_module, 'DB', tmp_path/'api.sqlite3')
    PublicAlertStore(app_module.DB).record_many([candidate('api-event')])
    with TestClient(app_module.app) as client:
        listed=client.get('/api/public/alerts').json()['alerts']
        assert len(listed)==1 and listed[0]['status']=='open'
        evidence=client.get('/api/public/alerts/%s/observations' % listed[0]['id']).json()['observations']
        assert evidence[0]['collector']=='rrc00' and evidence[0]['peer_ip']=='192.0.2.1'
        assert client.post('/api/public/alerts/%s/resolve' % listed[0]['id']).status_code==200
        assert client.get('/api/public/alerts').json()['alerts'][0]['status']=='resolved'
        assert client.post('/api/public/alerts/%s/resolve' % listed[0]['id']).status_code==404

def test_candidate_retains_observation_provenance(tmp_path):
    store=PublicAlertStore(tmp_path/'alerts.sqlite3')
    event={**candidate('msg-1'), 'as_path':[65000,64500]}
    store.record_many([event])
    alert=store.list_alerts()[0]
    observations=store.list_observations(alert['id'])
    assert len(observations)==1
    assert observations[0]['collector']=='rrc00'
    assert observations[0]['peer_ip']=='192.0.2.1'
    assert observations[0]['as_path']==[65000,64500]
    assert observations[0]['timestamp_utc']==event['timestamp_utc']

def test_existing_schema_upgrades_without_losing_candidates(tmp_path):
    import sqlite3
    db=tmp_path/'old.sqlite3'
    with sqlite3.connect(db) as c:
        c.execute('CREATE TABLE public_alert_observations (observation_key TEXT PRIMARY KEY, alert_id INTEGER NOT NULL)')
    store=PublicAlertStore(db); store.record_many([candidate('new')])
    assert store.list_observations(store.list_alerts()[0]['id'])[0]['collector']=='rrc00'

def test_concurrent_recording_deduplicates_observations(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    db=tmp_path/'concurrent.sqlite3'
    def save(_): PublicAlertStore(db).record_many([candidate('same-event')])
    with ThreadPoolExecutor(max_workers=5) as pool: list(pool.map(save,range(10)))
    assert PublicAlertStore(db).list_alerts()[0]['observation_count']==1
