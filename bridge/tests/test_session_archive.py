"""Session list removal is reversible and never mutates assessment evidence."""
import importlib
import json
from unittest.mock import patch

import pytest

bridge = importlib.import_module('bridge.app')


@pytest.fixture
def archive_client(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge, 'TRINETRA_ROOT', str(tmp_path))
    folder = tmp_path / 'sessions' / 'saved'
    folder.mkdir(parents=True)
    (folder / 'saved.json').write_text(json.dumps({'name': 'saved'}))
    (folder / 'evidence.txt').write_text('original evidence')
    return bridge.app.test_client(), folder


def inventory(client):
    with patch.object(bridge, 'run_trinetra', return_value=(0, '[4] Session Validation\nAll sessions valid\n', '')):
        return client.get('/api/doctor').get_json()


def test_remove_and_restore_preserve_all_files(archive_client):
    client, folder = archive_client
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    assert inventory(client)['sessions'] == ['saved']
    for _ in range(2):
        assert client.post('/api/session/saved/archive').status_code == 200
    assert inventory(client)['sessions'] == []
    assert inventory(client)['archived_sessions'] == ['saved']
    assert {name: (folder / name).read_bytes() for name in before} == before
    for _ in range(2):
        assert client.delete('/api/session/saved/archive').status_code == 200
    assert inventory(client)['sessions'] == ['saved']
    assert inventory(client)['archived_sessions'] == []
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before


def test_invalid_missing_and_foreign_origin(archive_client):
    client, folder = archive_client
    assert client.post('/api/session/missing/archive').status_code == 404
    assert client.post('/api/session/bad.name/archive').status_code == 400
    for method in (client.post, client.delete):
        assert method('/api/session/saved/archive', headers={'Origin': 'https://evil.example'}).status_code == 403
    assert not (folder / '.cortex-archived').exists()
    assert not (folder.parent / 'missing').exists()


def test_symlink_session_rejected(archive_client):
    client, folder = archive_client
    (folder.parent / 'linked').symlink_to(folder, target_is_directory=True)
    assert client.post('/api/session/linked/archive').status_code == 400
    assert inventory(client)['sessions'] == ['saved']


def test_write_error_is_recoverable(archive_client):
    client, folder = archive_client
    with patch.object(bridge.os, 'open', side_effect=PermissionError):
        assert client.post('/api/session/saved/archive').status_code == 500
    assert inventory(client)['sessions'] == ['saved']
    assert not (folder / '.cortex-archived').exists()
