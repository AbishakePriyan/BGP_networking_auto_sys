from pipeline.temporal_features import extract_temporal

def event(t,kind='A',path='1 2',origin=[2],peer='192.0.2.1'):
    return {'timestamp_utc':t,'type':kind,'prefix':'203.0.113.0/24','as_path':path,
            'origin_asns':origin,'peer_ip':peer,'collector':'rrc00'}

def test_features_use_only_prior_timestamps_and_not_future_labels():
    rows=[event('2020-01-01T00:00:00+00:00'),event('2020-01-01T00:01:00+00:00',path='1 3',origin=[3])]
    early=extract_temporal(rows)[0]['features']
    rows[1]['label']='incident_match'; rows[1]['as_path']='1 999'
    assert extract_temporal(rows)[0]['features']==early
    assert early['prior_announcements_1h']==0 and early['origin_seen_before'] is False

def test_simultaneous_events_do_not_see_each_other():
    rows=[event('2020-01-01T00:00:00+00:00'),event('2020-01-01T00:00:00+00:00',peer='192.0.2.2')]
    result=extract_temporal(rows)
    assert [r['features']['prior_announcements_1h'] for r in result]==[0,0]

def test_missing_as_path_and_withdrawals_are_not_fabricated():
    rows=[event('2020-01-01T00:00:00+00:00',kind='W',path=None,origin=None),event('2020-01-01T00:01:00+00:00',path=None,origin=None)]
    result=extract_temporal(rows)
    assert result[1]['features']['as_path_length'] is None
    assert result[1]['features']['origin_seen_before'] is None
    assert result[1]['features']['prior_withdrawals_1h']==1

def test_new_path_edges_are_based_on_past_only():
    rows=[event('2020-01-01T00:00:00+00:00'),event('2020-01-01T00:01:00+00:00',path='1 3',origin=[3])]
    result=extract_temporal(rows)
    assert result[0]['features']['new_path_edges']==1
    assert result[1]['features']['new_path_edges']==1

def test_rib_snapshot_seeds_state_but_is_not_an_update():
    rib=event('2020-01-01T00:00:00+00:00'); rib['source_url']='https://data.ris.ripe.net/rrc00/bview.20200101.gz'
    update=event('2020-01-01T00:01:00+00:00')
    result=extract_temporal([rib,update])
    assert result[1]['features']['origin_seen_before'] is True
    assert result[1]['features']['prior_announcements_1h']==0
    assert result[1]['history_complete'] is False

def test_lab_collector_cannot_use_historical_feature_contract():
    from pipeline.temporal_features import require_collector_compatibility
    import pytest
    with pytest.raises(ValueError): require_collector_compatibility('frr-rib-poll')
    require_collector_compatibility('historical-updates')

def test_feature_export_preserves_unknown_labels_and_refuses_overwrite(tmp_path):
    import json, pytest
    from pipeline.build_features import build_dataset
    source=tmp_path/'input.jsonl'; output=tmp_path/'output.jsonl'
    row={**event('2020-01-01T00:00:00+00:00'),'label':'unknown','incident_id':None}
    source.write_text(json.dumps(row)+'\n')
    summary=build_dataset(source,output)
    record=json.loads(output.read_text())
    assert record['observation']['label']=='unknown'
    assert summary['label_counts']['unknown']==1 and summary['history_complete'] is False
    with pytest.raises(FileExistsError): build_dataset(source,output)

def test_invalid_paths_remain_missing_and_time_requires_timezone():
    import pytest
    row=event('2020-01-01T00:00:00+00:00',path='1 999999999999')
    assert extract_temporal([row])[0]['features']['as_path_length'] is None
    row['timestamp_utc']='2020-01-01T00:00:00'
    with pytest.raises(ValueError,match='timestamp'): extract_temporal([row])
