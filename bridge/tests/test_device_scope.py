"""Isolated regression tests: no real sessions, network calls or AI invocation."""
import importlib
import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

bridge = importlib.import_module('bridge.app')
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    for name in ('out', 'lib', 'config'):
        shutil.copytree(ROOT / name, tmp_path / name)
    for name in ('trinetra', '1_classification.csv', '2_static_map.json', '3_decision_engine.csv'):
        shutil.copy2(ROOT / name, tmp_path / name)
    monkeypatch.setenv('TRINETRA_ROOT', str(tmp_path))
    monkeypatch.setattr(bridge, 'TRINETRA_ROOT', str(tmp_path))
    monkeypatch.setattr(bridge, 'TRINETRA_BIN', str(tmp_path / 'trinetra'))
    return bridge.app.test_client(), tmp_path


def test_remove_restore_preserves_chain_and_filters_score(isolated):
    client, root = isolated
    assert client.post('/api/session', json={'name': 'scope-test', 'target': 'offline'}).status_code == 201
    for device in ('router-a', 'router-b'):
        assert client.post('/api/session/scope-test/upload-config', json={
            'device_id': device, 'vendor': 'Cisco', 'config_content': 'hostname demo\nip ssh version 2\n',
        }).status_code == 200
    brain_path = root / 'sessions/scope-test/brain_state_scope-test.json'
    before = json.loads(brain_path.read_text())['normalized_results']
    score_before = client.get('/api/session/scope-test/score').get_json()['score']['total_tests_executed']
    assert client.delete('/api/session/scope-test/devices/router-a').status_code == 200
    assert client.delete('/api/session/scope-test/devices/router-a').status_code == 200
    devices = client.get('/api/session/scope-test/devices').get_json()
    assert [d['device_id'] for d in devices['devices']] == ['router-b']
    assert devices['removed_devices'] == ['router-a']
    assert client.get('/api/session/scope-test/score').get_json()['score']['total_tests_executed'] == score_before // 2
    assert json.loads(brain_path.read_text())['normalized_results'] == before
    assert client.get('/api/session/scope-test/status').get_json()['chain']['intact']
    report = client.get('/api/session/scope-test/audit-report')
    assert report.status_code == 200, report.get_json()
    assert 'router-a' not in report.get_json()['combined_content']
    assert client.post('/api/session/scope-test/devices/router-a/restore').status_code == 200
    assert client.get('/api/session/scope-test/devices').get_json()['device_count'] == 2
    assert client.get('/api/session/scope-test/score').get_json()['score']['total_tests_executed'] == score_before
    assert client.delete('/api/session/scope-test/devices/absent').status_code == 404
    for device in ('router-a', 'router-b'):
        assert client.delete(f'/api/session/scope-test/devices/{device}').status_code == 200
    assert client.get('/api/session/scope-test/devices').get_json()['device_count'] == 0
    assert client.get('/api/session/scope-test/score').get_json()['score']['total_tests_executed'] == 0
    assert client.get('/api/session/scope-test/audit-report').status_code == 200


def test_missing_session_read_does_not_create_directory(isolated):
    client, root = isolated
    with patch.object(bridge, 'run_trinetra') as command:
        for endpoint in ('score', 'report'):
            assert client.get('/api/session/this_session_does_not_exist_999/' + endpoint).status_code == 404
        command.assert_not_called()
    assert not (root / 'sessions/this_session_does_not_exist_999').exists()


def test_doctor_inventory_is_not_errors(isolated):
    client, root = isolated
    assert client.post('/api/session', json={'name': 'healthy', 'target': 'offline'}).status_code == 201
    with patch.object(bridge, 'run_trinetra', return_value=(0, '[4] Session Validation\n  broken: 1 errors\n    - Session file not found\n[5] AI Integration\n', '')):
        result = client.get('/api/doctor').get_json()
    assert result['sessions'] == ['healthy']
    assert result['session_validation']['session_errors']['broken'] == ['- Session file not found']


def test_foreign_origin_cannot_remove(isolated):
    client, _ = isolated
    with patch.object(bridge, 'run_java_helper') as command:
        assert client.delete('/api/session/demo/devices/router', headers={'Origin': 'https://evil.example'}).status_code == 403
        command.assert_not_called()
