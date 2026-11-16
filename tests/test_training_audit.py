import pytest
from backend.training_audit import audit_current_data, chronological_group_split

def test_real_data_audit_does_not_count_collector_copies_as_incidents():
    audit = audit_current_data()
    assert audit['incident_count'] == 1
    assert audit['labels']['incident_match'] == 26
    assert audit['labels']['unknown'] == 12
    assert audit['ready_for_training'] is False

def test_group_split_rejects_one_incident_and_missing_negatives():
    with pytest.raises(ValueError):
        chronological_group_split([{'incident_id':'event-1','timestamp_utc':'2020-01-01T00:00:00Z','label':'incident_match'}])

def test_group_split_rejects_interleaved_groups():
    rows=[{'incident_id':'a','timestamp_utc':'2020-01-01T00:00:00Z','label':'incident_match'},
          {'incident_id':'b','timestamp_utc':'2020-01-02T00:00:00Z','label':'reviewed_benign'},
          {'incident_id':'a','timestamp_utc':'2020-01-03T00:00:00Z','label':'incident_match'},
          {'incident_id':'c','timestamp_utc':'2020-01-04T00:00:00Z','label':'incident_match'},
          {'incident_id':'d','timestamp_utc':'2020-01-05T00:00:00Z','label':'reviewed_benign'},
          {'incident_id':'e','timestamp_utc':'2020-01-06T00:00:00Z','label':'incident_match'},
          {'incident_id':'f','timestamp_utc':'2020-01-07T00:00:00Z','label':'reviewed_benign'}]
    with pytest.raises(ValueError, match='overlap'): chronological_group_split(rows)

def test_group_split_keeps_chronological_groups_together():
    rows=[]
    for i in range(10):
        label = 'incident_match' if i % 2 == 0 else 'reviewed_benign'
        rows.extend({'incident_id':str(i),'timestamp_utc':f'2020-01-{i+1:02}T0{hour}:00:00Z','label':label} for hour in range(2))
    train, validation, test = chronological_group_split(rows)
    assert len(train)==12 and len(validation)==4 and len(test)==4
    assert not ({r['incident_id'] for r in train} & {r['incident_id'] for r in validation})
    assert max(r['timestamp_utc'] for r in validation) < min(r['timestamp_utc'] for r in test)

def test_audit_is_available_through_api():
    from fastapi.testclient import TestClient
    from backend.main import app
    with TestClient(app) as client:
        result = client.get('/api/model/audit')
        assert result.status_code == 200
        assert result.json()['ready_for_training'] is False
