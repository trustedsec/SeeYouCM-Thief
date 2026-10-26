"""Every config download -- not just the -b brute-force worker -- must land in
download_attempts, otherwise the --show-db summary reports 0 downloads after a
-p/-H/-e run that clearly fetched and parsed configs."""
import sqlite3

import pytest

from seeyoucm_thief import thief

CONFIG = "<device>\n<userId>jsmith</userId>\n</device>"


@pytest.fixture
def db(db_path, monkeypatch):
    monkeypatch.setattr(thief, 'db_file', db_path)
    monkeypatch.setattr(thief, 'no_db', False)
    return db_path


def _attempts(db_path):
    with sqlite3.connect(db_path) as conn:
        return conn.execute(
            'SELECT cucm_host, filename, success, method, content FROM download_attempts'
        ).fetchall()


def test_search_for_secrets_logs_successful_tftp_download(db, monkeypatch):
    monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: CONFIG)
    thief.search_for_secrets('cucm1', 'SEP001122334455.cnf.xml')
    assert _attempts(db) == [('cucm1', 'SEP001122334455.cnf.xml', 1, 'TFTP', CONFIG)]


def test_search_for_secrets_logs_successful_http_download(db, monkeypatch):
    monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: CONFIG)
    thief.search_for_secrets('cucm1', 'SEP001122334455.cnf.xml', use_tftp=False)
    assert _attempts(db) == [('cucm1', 'SEP001122334455.cnf.xml', 1, 'HTTP', CONFIG)]


def test_search_for_secrets_logs_failed_download(db, monkeypatch):
    monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: None)
    thief.search_for_secrets('cucm1', 'SEP001122334455.cnf.xml')
    assert _attempts(db) == [('cucm1', 'SEP001122334455.cnf.xml', 0, 'TFTP', None)]


def test_search_for_secrets_respects_no_db(db, monkeypatch):
    monkeypatch.setattr(thief, 'no_db', True)
    monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: CONFIG)
    thief.search_for_secrets('cucm1', 'SEP001122334455.cnf.xml')
    assert _attempts(db) == []


def test_get_cache_list_logs_fallback_download(db, monkeypatch):
    monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: None)
    monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: 'SEPA.cnf.xml\n')
    assert thief.get_cache_list('cucm1') == ['SEPA.cnf.xml']
    assert _attempts(db) == [('cucm1', 'ConfigFileCacheList.txt', 1, 'HTTP', 'SEPA.cnf.xml\n')]


def test_get_cache_list_logs_failed_download(db, monkeypatch):
    monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: None)
    monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: None)
    assert thief.get_cache_list('cucm1') == []
    assert _attempts(db) == [('cucm1', 'ConfigFileCacheList.txt', 0, 'TFTP+HTTP', None)]


def test_process_phone_run_reports_downloads_in_db(tmp_path, monkeypatch):
    """End-to-end through main(): a -p run must leave download rows behind."""
    db_path = str(tmp_path / 'thief.db')
    monkeypatch.setattr(thief, 'get_cucm_name_from_phone', lambda ip: 'cucm1')
    monkeypatch.setattr(thief, 'get_hostname_from_phone', lambda ip: 'SEP001122334455')
    monkeypatch.setattr(thief, 'get_phones_hostnames_from_reverse', lambda ip: [])
    monkeypatch.setattr(thief, 'get_config_names', lambda *a, **kw: ['SEP001122334455.cnf.xml'])
    monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: CONFIG)
    monkeypatch.setattr('sys.argv', ['thief', '-p', '10.0.0.5', '--db', db_path, '-T', '1'])
    with pytest.raises(SystemExit):
        thief.main()
    assert _attempts(db_path) == [('cucm1', 'SEP001122334455.cnf.xml', 1, 'TFTP', CONFIG)]
