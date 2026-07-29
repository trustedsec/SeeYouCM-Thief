import sqlite3

import pytest

import thief


def _db(tmp_path):
    db_file = str(tmp_path / 'thief.db')
    thief.init_database(db_file)
    return db_file


def test_uds_device_macs_scoped_to_host(tmp_path):
    db_file = _db(tmp_path)
    thief.log_uds_device('cucm1', 'alice', 'SEPAABBCCDDEEFF', 'userenum', db_file)
    thief.log_uds_device('cucm2', 'bob', 'SEP112233445566', 'userenum', db_file)

    assert thief.get_uds_device_macs_from_db('cucm1', db_file) == [
        ('AABBCCDDEEFF', 'cucm1')
    ]
    assert thief.get_uds_device_macs_from_db('cucm3', db_file) == []


def test_uds_device_macs_ignores_non_sep_names(tmp_path):
    db_file = _db(tmp_path)
    thief.log_uds_device('cucm1', 'alice', 'CSFALICE', 'userenum', db_file)
    assert thief.get_uds_device_macs_from_db('cucm1', db_file) == []


def test_uds_device_macs_missing_table(tmp_path):
    db_file = str(tmp_path / 'empty.db')
    sqlite3.connect(db_file).close()
    assert thief.get_uds_device_macs_from_db('cucm1', db_file) == []


def test_brute_mac_accepts_host_without_phone(tmp_path):
    import os
    import subprocess

    db_file = str(tmp_path / 'thief.db')
    thief.init_database(db_file)
    thief.log_uds_device('cucm1', 'alice', 'SEPAABBCCDDEEFF', 'userenum', db_file)

    env = os.environ.copy()
    env['PYTEST_CURRENT_TEST'] = '1'
    result = subprocess.run(
        ['python3', 'thief.py', '-b', '1', '-H', 'cucm1', '--db', db_file],
        capture_output=True, text=True, env=env, timeout=300,
    )
    assert 'You must specify at least one phone' not in result.stdout
    assert 'MAC brute force mode enabled using 1 MAC prefix' in result.stdout


def test_brute_mac_does_not_probe_uds_version(monkeypatch, tmp_path, capsys):
    """--brute-mac must not run the UDS version probe: it never touches UDS, so
    a firewalled 8443 would otherwise cost a full read timeout and a misleading
    'could not retrieve version' error."""
    calls = []
    monkeypatch.setattr(thief, 'get_version', lambda *a, **kw: calls.append(kw) or None)
    db_file = str(tmp_path / 'thief.db')
    thief.init_database(db_file)
    monkeypatch.setattr('sys.argv',
                        ['thief', '-b', '1', '-H', 'cucm1', '--db', db_file])
    with pytest.raises(SystemExit):
        thief.main()
    out = capsys.readouterr().out
    assert calls == []
    assert 'Could not retrieve CUCM version' not in out


def test_brute_mac_empty_db_message_names_host(monkeypatch, tmp_path, capsys):
    """With -H but no seeded prefixes, the error should point at seeding steps,
    not claim -H was missing."""
    monkeypatch.setattr(thief, 'get_version', lambda *a, **kw: None)
    db_file = str(tmp_path / 'thief.db')
    thief.init_database(db_file)
    monkeypatch.setattr('sys.argv',
                        ['thief', '-b', '1', '-H', 'cucm-empty', '--db', db_file])
    with pytest.raises(SystemExit):
        thief.main()
    out = capsys.readouterr().out
    assert 'no MAC prefixes for cucm-empty' in out
    assert 'You must specify at least one phone' not in out


def test_servers_feature_still_probes_uds_version(monkeypatch, tmp_path):
    """UDS features must keep running the version probe."""
    calls = []
    monkeypatch.setattr(thief, 'get_version',
                        lambda *a, **kw: calls.append(kw) or {'version': '14.0', 'prefix': None})
    monkeypatch.setattr(thief, 'get_servers_api', lambda *a, **kw: [])
    db_file = str(tmp_path / 'thief.db')
    thief.init_database(db_file)
    monkeypatch.setattr('sys.argv',
                        ['thief', '--servers', '-H', 'cucm1', '--db', db_file])
    with pytest.raises(SystemExit):
        thief.main()
    assert len(calls) == 1
