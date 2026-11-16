import json
import pytest
from pipeline.real_training import prepare_data, train_and_evaluate
from pipeline.temporal_features import CONTRACT

FEATURES={'prefix_length':24,'as_path_length':3,'repeated_as_count':0,'origin_seen_before':True,
          'new_path_edges':1,'prior_announcements_1h':1,'prior_withdrawals_1h':0,'prior_distinct_peers':1}

def sample(group,day,label):
    t=f'2020-01-{day:02}T12:00:00+00:00'
    return {'feature_contract':CONTRACT,'history_complete':True,'features':dict(FEATURES),
            'observation':{'incident_id':group,'timestamp_utc':t,'label':label,'label_source':'reviewed fixture',
            'group_window_start':f'2020-01-{day:02}T00:00:00+00:00',
            'group_window_end':f'2020-01-{day:02}T23:00:00+00:00'}}

def test_real_training_rejects_incomplete_real_sample():
    records=[json.loads(x) for x in open('data/features/youtube_2008.jsonl')]
    with pytest.raises(ValueError,match='[Cc]omplete'): prepare_data(records)

def test_training_refuses_mixed_contracts_and_overlapping_windows():
    rows=[sample(str(i),i+1,'incident_match' if i%2==0 else 'reviewed_benign') for i in range(10)]
    rows[0]['feature_contract']='lab'
    with pytest.raises(ValueError,match='contract'): prepare_data(rows)
    rows[0]['feature_contract']=CONTRACT; rows[0]['observation']['group_window_end']='2020-01-03T00:00:00+00:00'
    with pytest.raises(ValueError,match='overlap'): prepare_data(rows)

def test_separate_time_groups_and_report_both_baselines():
    rows=[sample(str(i),i+1,'incident_match' if i%2==0 else 'reviewed_benign') for i in range(10)]
    report, model=train_and_evaluate(rows)
    assert report['train']['groups']==6 and report['validation']['groups']==2 and report['test']['groups']==2
    assert 'random_forest' in report['test_results'] and 'prior_origin_rule' in report['test_results']
    assert report['feature_contract']==CONTRACT

def test_historical_model_rejects_lab_collector_and_wrong_schema():
    from pipeline.real_training import validate_model_metadata, FEATURES
    metadata={'feature_contract':CONTRACT,'features':FEATURES,'collector_compatibility':'historical-updates only','feature_encoding':'values+missingness-v1','threshold':0.5}
    validate_model_metadata(metadata,'historical-updates')
    with pytest.raises(ValueError): validate_model_metadata(metadata,'frr-rib-poll')
    with pytest.raises(ValueError): validate_model_metadata({**metadata,'features':['origin_mismatch']},'historical-updates')

def test_target_and_unknown_features_cannot_be_smuggled_into_model():
    rows=[sample(str(i),i+1,'incident_match' if i%2==0 else 'reviewed_benign') for i in range(10)]
    rows[0]['features']['label']=1
    with pytest.raises(ValueError,match='schema'): prepare_data(rows)

def test_unknown_label_is_excluded_not_treated_as_negative():
    rows=[sample(str(i),i+1,'incident_match' if i%2==0 else 'reviewed_benign') for i in range(10)]
    unknown=sample('extra',11,'unknown'); unknown['history_complete']=False
    report,_=train_and_evaluate(rows+[unknown])
    assert report['unknown_excluded']==1 and report['test']['negative']==1

def test_rule_reports_missing_origin_history_as_abstention():
    rows=[sample(str(i),i+1,'incident_match' if i%2==0 else 'reviewed_benign') for i in range(10)]
    rows[8]['features']['origin_seen_before']=None
    report,_=train_and_evaluate(rows)
    assert report['test_results']['prior_origin_rule']['abstained']==1
    assert report['test_results']['prior_origin_rule']['coverage']==0.5

def test_boolean_origin_evidence_does_not_accept_numeric_flags():
    rows=[sample(str(i),i+1,'incident_match' if i%2==0 else 'reviewed_benign') for i in range(10)]
    rows[0]['features']['origin_seen_before']=0
    with pytest.raises(ValueError,match='boolean'): prepare_data(rows)

def test_missingness_is_explicit_for_every_feature_even_if_training_had_no_missing():
    from pipeline.real_training import matrix
    rows=[sample('a',1,'incident_match')['observation']]
    rows[0]['_features']=dict(FEATURES)
    rows[0]['_features']['as_path_length']=None
    encoded=matrix(rows)
    assert encoded.shape==(1,16)
    assert encoded[0,8+1]==1 and encoded[0,8]==0
