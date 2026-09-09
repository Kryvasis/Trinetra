import importlib
import json
from pathlib import Path

import pytest

bridge = importlib.import_module('bridge.app')


@pytest.fixture
def evidence_client():
    # This module must run through tests/run_isolated.py, like the legacy suites.
    import uuid
    name = 'accuracy_' + uuid.uuid4().hex[:10]
    client = bridge.app.test_client()
    assert client.post('/api/session', json={'name': name, 'target': 'offline'}).status_code == 201
    return client, name


def upload(client, name, content, device='router', vendor='Cisco'):
    response = client.post(f'/api/session/{name}/upload-config', json={
        'device_id': device, 'vendor': vendor, 'config_content': content,
    })
    assert response.status_code == 200, response.get_json()
    return client.get(f'/api/session/{name}/score').get_json()['score']


def test_runtime_rules_do_not_pass_from_config(evidence_client):
    client, name = evidence_client
    score = upload(client, name, 'hostname test\nip ssh version 1\nip http server\nusername demo password 0 SENSITIVE-DEMO\nsnmp-server community public RO\nline vty 0 4\n transport input telnet ssh\n')
    for fw in score['frameworks'].values():
        assert fw['tests_passed'] == 0
        assert fw['tests_failed'] + fw['tests_manual_review'] == fw['total_tests_mapped']
        assert len(fw['results']) == fw['total_tests_mapped']
        assert all(row['result'] in {'fail', 'manual_review'} for row in fw['results'])
    assert sum(fw['tests_failed'] for fw in score['frameworks'].values()) > 0
    state_path = Path(bridge.TRINETRA_ROOT) / 'sessions' / name / f'brain_state_{name}.json'
    state = json.loads(state_path.read_text())
    verdicts = {row['test_id']: row['normalized_result'] for row in state['normalized_results']}
    assert {code for code, verdict in verdicts.items() if verdict == 'fail'} == {
        'V-003', 'V-006', 'V-013', 'V-057', 'V-071', 'V-107',
    }
    assert verdicts['V-058'] == 'manual_review', "missing logging syntax is insufficient evidence"
    review = score['configuration_reviews'][0]
    assert len([row for row in review['observations'] if row['status'] == 'observed_risk']) == 5
    assert 'SENSITIVE-DEMO' not in json.dumps(score)
    assert score['legacy_config_records'] == 0
    assert client.get(f'/api/session/{name}/status').get_json()['chain']['intact']
    assert score['evidence_chain_intact'] is True
    report = client.get(f'/api/session/{name}/audit-report').get_json()['combined_content']
    assert 'Config observation: CFG-SSH1' in report
    assert 'SENSITIVE-DEMO' not in report
    pdf = client.get(f'/api/session/{name}/audit-report/pdf')
    assert pdf.status_code == 200 and pdf.data.startswith(b'%PDF')


def test_negation_comments_banners_and_absence_are_not_passes(evidence_client):
    client, name = evidence_client
    text = 'hostname test\n! ip ssh version 1\nno ip http server\nip ssh version 2\ntransport input ssh\nbanner motd ^C\nip http server\ntransport input telnet\n^C\n'
    score = upload(client, name, text)
    assert all(row['status'] == 'not_observed' for row in score['configuration_reviews'][0]['observations'])
    # Secure directives now produce PASS via baseline (semantic wiring); banner/comment content must not leak
    assert any(fw['tests_passed'] > 0 for fw in score['frameworks'].values())
    # Missing logging evidence remains unresolved; banner content must not add
    # false failures (V-003/V-071 should be PASS, not FAIL).
    state_path = Path(bridge.TRINETRA_ROOT) / 'sessions' / name / f'brain_state_{name}.json'
    state = json.loads(state_path.read_text())
    verdicts = {row['test_id']: row['normalized_result'] for row in state['normalized_results']}
    assert verdicts['V-003'] == 'pass', "no ip http server + no telnet outside banner should be PASS"
    assert verdicts['V-006'] == 'pass', "ip ssh version 2 should be PASS"
    assert verdicts['V-071'] == 'pass', "transport input ssh + no http should be PASS"
    assert verdicts['V-058'] == 'manual_review'


def test_unsupported_vendor_and_removed_device(evidence_client):
    client, name = evidence_client
    score = upload(client, name, 'set system services telnet\n', vendor='Juniper')
    assert score['configuration_reviews'][0]['parser'] == 'unsupported'
    assert client.delete(f'/api/session/{name}/devices/router').status_code == 200
    assert client.get(f'/api/session/{name}/score').get_json()['score']['configuration_reviews'] == []


def test_corrupt_brain_does_not_look_healthy(evidence_client):
    client, name = evidence_client
    path = Path(bridge.TRINETRA_ROOT) / 'sessions' / name / f'brain_state_{name}.json'
    path.write_text('{broken')
    assert client.get(f'/api/session/{name}/devices').status_code == 500


def test_tampered_observation_is_flagged(evidence_client):
    client, name = evidence_client
    upload(client, name, 'hostname test\nip ssh version 1\n')
    path = Path(bridge.TRINETRA_ROOT) / 'sessions' / name / f'brain_state_{name}.json'
    state = json.loads(path.read_text())
    state['normalized_results'][0]['configuration_review']['parser'] = 'tampered'
    path.write_text(json.dumps(state))
    assert client.get(f'/api/session/{name}/score').get_json()['score']['evidence_chain_intact'] is False
