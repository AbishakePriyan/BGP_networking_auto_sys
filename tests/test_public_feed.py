import pytest
from backend.public_feed import normalize, subscription

def test_subscriptions_require_bounded_specific_prefix():
    with pytest.raises(ValueError): subscription('0.0.0.0/0')
    assert subscription('1.1.1.0/24')['data']['prefix']=='1.1.1.0/24'

def test_normalize_announcements_with_origin_and_withdrawals():
    message={'type':'ris_message','data':{'type':'UPDATE','timestamp':1700000000,'host':'rrc00.ripe.net','peer':'192.0.2.1','peer_asn':'65000','path':[65000,13335], 'announcements':[{'prefixes':['1.1.1.0/24']}], 'withdrawals':['1.0.0.0/24']}}
    rows=normalize(message,'1.1.1.0/24')
    assert len(rows)==1 and rows[0]['origin_asn']==13335 and rows[0]['kind']=='announcement'
    assert rows[0]['assessment']=='unknown' and rows[0]['source']=='RIPE RIS Live'

def test_ambiguous_as_path_is_not_assigned_an_origin():
    message={'type':'ris_message','data':{'type':'UPDATE','timestamp':1700000000,'host':'rrc00','path':[1,[2,3]],'announcements':[{'prefixes':['1.1.1.0/24']}], 'withdrawals':[]}}
    assert normalize(message,'1.1.1.0/24')[0]['origin_asn'] is None

def test_public_mode_blocks_lab_controls_and_rejects_global_subscription():
    from fastapi.testclient import TestClient
    from backend.main import app
    with TestClient(app) as client:
        assert client.post('/api/source',json={'source':'public'}).status_code == 200
        assert client.post('/api/action/announce').status_code == 409
        assert client.post('/api/public/start',json={'prefix':'0.0.0.0/0'}).status_code == 422
        assert client.post('/api/source',json={'source':'live'}).status_code == 200

def test_origin_mismatch_is_a_candidate_not_a_hijack_verdict():
    msg={'type':'ris_message','data':{'type':'UPDATE','timestamp':1700000000,'path':[65000,64501], 'announcements':[{'prefixes':['1.1.1.0/24']}], 'withdrawals':[]}}
    row=normalize(msg,'1.1.1.0/24', allowed_origins=[13335], baseline_source='operator entry')[0]
    assert row['assessment']=='origin_mismatch'
    assert 'not proof' in row['explanation']
    assert row['authorization_source']=='operator entry'

def test_without_baseline_or_origin_assessment_stays_unknown():
    msg={'type':'ris_message','data':{'type':'UPDATE','timestamp':1700000000,'path':[65000,[1,2]], 'announcements':[{'prefixes':['1.1.1.0/24']}], 'withdrawals':[]}}
    assert normalize(msg,'1.1.1.0/24', allowed_origins=[13335], baseline_source='operator entry')[0]['assessment']=='unknown'

def test_baseline_requires_attribution():
    from backend.public_feed import PublicFeed
    with pytest.raises(ValueError, match='source'):
        PublicFeed().start('1.1.1.0/24', [13335], '')

def test_clean_disconnect_records_a_gap(monkeypatch):
    import asyncio
    import backend.public_feed as service
    class ClosedSocket:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def send(self, data): pass
        def __aiter__(self): return self
        async def __anext__(self): raise StopAsyncIteration
    monkeypatch.setattr(service.websockets, 'connect', lambda *a,**kw: ClosedSocket())
    async def check():
        feed=service.PublicFeed(); feed.start('1.1.1.0/24')
        for _ in range(50):
            if feed.gaps: break
            await asyncio.sleep(.01)
        assert feed.gaps == 1 and feed.status == 'reconnecting'
        feed.stop()
        await asyncio.sleep(0)
    asyncio.run(check())
