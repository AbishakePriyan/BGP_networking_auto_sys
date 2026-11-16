from backend.contract import classify, compatible

def test_known_origin_mismatch_requires_cover():
    assert classify('10.199.113.0/25', 65003, {'10.199.113.0/24':[65001]}) == 'suspicious'
    assert classify('198.51.100.0/24', 65003, {'10.199.113.0/24':[65001]}) == 'unknown'

def test_schema_must_match():
    assert not compatible(['other'])
