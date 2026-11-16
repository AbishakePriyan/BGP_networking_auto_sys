import pytest
from core import parse_routes, extract, filter_commands
from fastapi.testclient import TestClient
from backend.main import app

def test_parse_valid_frr_path():
    table={'routes':{'10.199.113.0/25':[{'peerId':'10.199.0.4','path':'65003'}]}}
    assert parse_routes(table)[0]['origin_as']==65003

def test_unmanaged_route_has_no_ownership_inference():
    assert extract({'prefix':'198.51.100.0/24','origin_as':3,'as_path':[3]}, {'10.199.113.0/24':[65001]}) is None

def test_filter_refuses_outside_lab():
    with pytest.raises(ValueError): filter_commands('10.199.0.4','198.51.100.0/24')

def test_api_rejects_unknown_action_and_mode():
    with TestClient(app) as c:
        assert c.post('/api/action/execute').status_code==422
        assert c.post('/api/mode',json={'mode':'shell'}).status_code==422
        assert c.post('/api/action/reset',headers={'Origin':'https://example.com'}).status_code==403

def test_replay_disables_live_actions():
    with TestClient(app) as c:
        assert c.post('/api/source',json={'source':'historical'}).status_code==200
        assert c.post('/api/action/announce').status_code==409
        assert c.post('/api/replay/control',json={'action':'play','speed':600}).status_code==200
        assert c.get('/api/state').json()['replay']['total']==13
        assert c.post('/api/replay/control',json={'action':'pause','speed':600}).status_code==200
        assert c.post('/api/source',json={'source':'live'}).status_code==200

def test_failed_filter_is_reported(tmp_path):
    from unittest.mock import patch
    import backend.main as service
    route={'peer':'10.199.0.4','prefix':'10.199.113.0/25','origin_as':65003,'as_path':[65003]}
    with patch.object(service,'DB',tmp_path/'events.sqlite3'), TestClient(app) as c, patch.object(service,'collect',return_value=[route]), patch.object(service,'apply_filter',side_effect=RuntimeError('router unavailable')):
        c.post('/api/source',json={'source':'live'})
        response=c.post('/api/action/filter')
        assert response.status_code==503
        assert c.get('/api/state').json()['filter']=='failed'

def test_youtube_labels_only_documented_announcement():
    import json
    from pathlib import Path
    records=[json.loads(line) for line in (Path(__file__).resolve().parents[1]/'data/youtube_2008.jsonl').read_text().splitlines()]
    positive=[r for r in records if r['label']=='incident_match']
    assert positive
    assert all(r['type']=='A' and r['prefix']=='208.65.153.0/24' and r['origin_asns']==[17557] and '2008-02-24T18:47:00' <= r['timestamp_utc'] <= '2008-02-24T21:01:22+00:00' for r in positive)
    assert all(r['label'] in ('incident_match','unknown') for r in records)

def test_documented_incident_replay_is_selectable():
    with TestClient(app) as c:
        c.post('/api/source',json={'source':'historical'})
        r=c.post('/api/replay/scenario',json={'scenario':'youtube-2008'})
        assert r.status_code==200 and r.json()['total']>0
        c.post('/api/replay/scenario',json={'scenario':'sample'})
        c.post('/api/source',json={'source':'live'})
