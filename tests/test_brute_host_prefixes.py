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


def test_mac_from_phone_arg_plain_sep():
    assert thief.mac_from_phone_arg('SEPC064E4D83AAF') == 'C064E4D83AAF'


def test_mac_from_phone_arg_with_dns_suffix():
    assert thief.mac_from_phone_arg('SEPC064E4D83AAF.mason.ad') == 'C064E4D83AAF'


def test_mac_from_phone_arg_lowercase_normalised():
    assert thief.mac_from_phone_arg('sepc064e4d83aaf') == 'C064E4D83AAF'


def test_mac_from_phone_arg_ip_returns_none():
    assert thief.mac_from_phone_arg('10.45.200.50') is None


def test_mac_from_phone_arg_plain_hostname_returns_none():
    assert thief.mac_from_phone_arg('phone-lobby.example.com') is None


def test_mac_from_phone_arg_empty():
    assert thief.mac_from_phone_arg('') is None


def test_brute_mac_sep_name_skips_http_detection(monkeypatch, tmp_path, capsys):
    """A SEP<MAC> passed to -p must not trigger an HTTP phone lookup and must
    still yield its MAC when the phone is unreachable."""
    def _boom(*a, **kw):
        raise AssertionError('get_hostname_from_phone should not be called for a SEP name')
    monkeypatch.setattr(thief, 'get_hostname_from_phone', _boom)
    monkeypatch.setattr(thief, 'get_version', lambda *a, **kw: None)
    db_file = str(tmp_path / 'thief.db')
    thief.init_database(db_file)
    monkeypatch.setattr('sys.argv',
                        ['thief', '-b', '3', '-p', 'SEPC064E4D83AAF.mason.ad',
                         '-H', 'cucm1', '--db', db_file])
    with pytest.raises(SystemExit):
        thief.main()
    out = capsys.readouterr().out
    assert 'Using MAC from device name' in out
    assert 'Detected: SEPC064E4D83AAF' in out
    assert 'Could not detect hostname' not in out


def test_get_cucm_for_mac_from_db_mac_prefixes(tmp_path):
    db_file = _db(tmp_path)
    thief.log_mac_prefix_to_db('cucm-a', '10.0.0.5', 'C064E4D83AAF', 'C064E4D83', db_file)
    assert thief.get_cucm_for_mac_from_db('c064e4d83aaf', db_file) == 'cucm-a'
    assert thief.get_cucm_for_mac_from_db('AABBCCDDEEFF', db_file) is None


def test_get_cucm_for_mac_from_db_uds_devices(tmp_path):
    db_file = _db(tmp_path)
    thief.log_uds_device('cucm-b', 'alice', 'SEPC064E4D83AAF', 'userenum', db_file)
    assert thief.get_cucm_for_mac_from_db('C064E4D83AAF', db_file) == 'cucm-b'


def test_get_cucm_for_mac_from_db_missing_tables(tmp_path):
    import sqlite3 as _sq
    db_file = str(tmp_path / 'empty.db')
    _sq.connect(db_file).close()
    assert thief.get_cucm_for_mac_from_db('C064E4D83AAF', db_file) is None


def test_brute_mac_sep_name_resolves_cucm_from_db(monkeypatch, tmp_path, capsys):
    """-p SEP<MAC> with no -H and an unreachable phone should still find its
    CUCM from a prior scan in the database."""
    monkeypatch.setattr(thief, 'get_hostname_from_phone',
                        lambda *a, **kw: (_ for _ in ()).throw(AssertionError('no http')))
    monkeypatch.setattr(thief, 'get_cucm_name_from_phone', lambda *a, **kw: None)
    monkeypatch.setattr(thief, 'get_version', lambda *a, **kw: None)
    db_file = str(tmp_path / 'thief.db')
    thief.init_database(db_file)
    thief.log_uds_device('cucm-b', 'alice', 'SEPC064E4D83AAF', 'userenum', db_file)
    monkeypatch.setattr('sys.argv',
                        ['thief', '-b', '3', '-p', 'SEPC064E4D83AAF.mason.ad', '--db', db_file])
    with pytest.raises(SystemExit):
        thief.main()
    out = capsys.readouterr().out
    assert 'resolved from database' in out
    assert 'cucm-b' in out


def test_brute_mac_no_cucm_does_not_crash_worker(monkeypatch, tmp_path, capsys):
    """Regression: the no-CUCM path double-called queue.task_done(), crashing
    the detect worker with 'task_done() called too many times'."""
    import threading
    monkeypatch.setattr(thief, 'get_hostname_from_phone', lambda *a, **kw: None)
    monkeypatch.setattr(thief, 'get_cucm_name_from_phone', lambda *a, **kw: None)
    monkeypatch.setattr(thief, 'get_version', lambda *a, **kw: None)
    db_file = str(tmp_path / 'thief.db')
    thief.init_database(db_file)

    errors = []
    orig = threading.excepthook
    monkeypatch.setattr(threading, 'excepthook', lambda args: errors.append(args.exc_value))
    monkeypatch.setattr('sys.argv',
                        ['thief', '-b', '3', '-p', 'SEPC064E4D83AAF', '--db', db_file])
    try:
        with pytest.raises(SystemExit):
            thief.main()
    finally:
        threading.excepthook = orig
    assert errors == [], f'worker thread raised: {errors}'


def test_brute_mac_sep_name_uses_sole_known_cucm(monkeypatch, tmp_path, capsys):
    """With no -H and the device not recorded, fall back to the only CUCM host
    known in the database."""
    monkeypatch.setattr(thief, 'get_hostname_from_phone', lambda *a, **kw: None)
    monkeypatch.setattr(thief, 'get_cucm_name_from_phone', lambda *a, **kw: None)
    monkeypatch.setattr(thief, 'get_version', lambda *a, **kw: None)
    db_file = str(tmp_path / 'thief.db')
    thief.init_database(db_file)
    # A different device seeds a single known CUCM host.
    thief.log_mac_prefix_to_db('cucm-only', '10.0.0.9', 'AABBCCDDEEFF', 'AABBCCDDE', db_file)
    monkeypatch.setattr('sys.argv',
                        ['thief', '-b', '3', '-p', 'SEPC064E4D83AAF', '--db', db_file])
    with pytest.raises(SystemExit):
        thief.main()
    out = capsys.readouterr().out
    assert 'only CUCM host known in the database: cucm-only' in out
