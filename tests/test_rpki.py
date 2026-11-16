import pytest
from backend.rpki import interpret_response

def test_validation_result_keeps_source_and_is_not_hijack_verdict():
    data={'status':'ok','time':'2026-01-01T00:00:00','data':{'resource':'13335','prefix':'1.1.1.0/24','status':'invalid_asn','validator':'routinator'}}
    result=interpret_response(data,'1.1.1.0/24',13335)
    assert result['status']=='invalid_asn'
    assert result['source']=='RIPEstat RPKI validation'
    assert 'not proof' in result['note']

def test_mismatched_or_unknown_upstream_data_fails_closed():
    data={'status':'ok','data':{'resource':'1234','prefix':'1.1.1.0/24','status':'valid'}}
    with pytest.raises(ValueError): interpret_response(data,'1.1.1.0/24',13335)
    data['data']['resource']='13335'; data['data']['status']='invented'
    with pytest.raises(ValueError): interpret_response(data,'1.1.1.0/24',13335)

def test_rpki_api_uses_candidate_and_handles_upstream_failure(tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    import backend.main as service
    from backend.public_alert_store import PublicAlertStore
    monkeypatch.setattr(service,'DB',tmp_path/'rpki.sqlite3')
    store=PublicAlertStore(service.DB)
    store.record_many([{'assessment':'origin_mismatch','watch_prefix':'1.1.1.0/24',
      'prefix':'1.1.1.0/24','origin_asn':13335,'allowed_origins':[1234],
      'authorization_source':'test registry','timestamp_utc':'2026-01-01T00:00:00+00:00'}])
    ident=store.list_alerts()[0]['id']
    async def success(prefix,asn): return {'prefix':prefix,'origin_asn':asn,'status':'valid'}
    monkeypatch.setattr(service,'validate_rpki',success)
    with TestClient(service.app) as c:
        assert c.get(f'/api/public/alerts/{ident}/rpki').json()['status']=='valid'
        assert c.get('/api/public/alerts/9999/rpki').status_code==404
        async def fail(prefix,asn): raise TimeoutError('timeout')
        monkeypatch.setattr(service,'validate_rpki',fail)
        assert c.get(f'/api/public/alerts/{ident}/rpki').status_code==503
