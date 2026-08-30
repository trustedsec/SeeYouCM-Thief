"""Smoke tests: does each thief.main() CLI mode dispatch to the right
function and exit with the right code? Previously this layer did not exist
at all -- coverage was either pure-unit (mocked single functions) or full
subprocess e2e. These run thief.main() in-process with sys.argv patched.

_TEST_MODE is forced True in each test (regardless of the conftest autouse
default) since most of these dispatch paths call functions that have fast,
deterministic _TEST_MODE branches, and we don't want to hand-mock every leaf.
"""
import os
import sqlite3

import pytest

from seeyoucm_thief import thief

pytestmark = pytest.mark.smoke


def _set_test_mode(monkeypatch):
    monkeypatch.setattr(thief, '_TEST_MODE', True)


def _argv(monkeypatch, *args):
    monkeypatch.setattr('sys.argv', ['thief', *args])


# ---------------------------------------------------------------------------
# --servers
# ---------------------------------------------------------------------------

class TestServersDispatch:
    def test_requires_host(self, monkeypatch, capsys):
        _set_test_mode(monkeypatch)
        _argv(monkeypatch, '--servers')
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1
        assert '--servers requires' in capsys.readouterr().out

    def test_dispatches_and_logs_to_db(self, monkeypatch, tmp_path, capsys):
        _set_test_mode(monkeypatch)
        db = tmp_path / 'thief.db'
        _argv(monkeypatch, '-H', 'mock-cucm', '--servers', '--db', str(db))
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert 'Discovered 1 cluster member' in out
        assert 'cucm-pub.test' in out

        conn = sqlite3.connect(db)
        count = conn.execute("SELECT COUNT(*) FROM cluster_servers").fetchone()[0]
        conn.close()
        assert count == 1


# ---------------------------------------------------------------------------
# --gowitness
# ---------------------------------------------------------------------------

class TestGowitnessDispatch:
    def test_missing_phones_and_missing_db_exits_nonzero(self, monkeypatch, tmp_path, capsys):
        _set_test_mode(monkeypatch)
        missing = tmp_path / 'nope.sqlite3'
        _argv(monkeypatch, '--gowitness', str(missing))
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1
        assert 'No phones available' in capsys.readouterr().out

    def test_loads_phones_and_proceeds(self, monkeypatch, tmp_path, capsys):
        _set_test_mode(monkeypatch)
        gw = tmp_path / 'gowitness.sqlite3'
        conn = sqlite3.connect(str(gw))
        conn.execute("CREATE TABLE results (id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
        conn.execute("INSERT INTO results (url, title) VALUES (?, ?)",
                     ("https://10.0.0.5:443/", "Cisco CP-8845"))
        conn.commit()
        conn.close()

        db = tmp_path / 'thief.db'
        _argv(monkeypatch, '--gowitness', str(gw), '--db', str(db), '--threads', '1')
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 0


# ---------------------------------------------------------------------------
# --enumsubnet (regression: found_credentials/found_usernames must populate)
# ---------------------------------------------------------------------------

class TestEnumsubnetDispatch:
    def test_reports_credentials_found_on_subnet(self, monkeypatch, tmp_path, capsys):
        _set_test_mode(monkeypatch)
        db = tmp_path / 'thief.db'
        monkeypatch.setattr(thief, 'enumerate_phones_subnet', lambda subnet: [
            {'ip': '10.0.0.5', 'hostname': 'SEP001122334455', 'url': 'http://cucm1:6970/SEP001122334455.cnf.xml'}
        ])
        monkeypatch.setattr(thief, 'get_cucm_name_from_phone', lambda ip: None)  # CUCM_host stays as -H
        monkeypatch.setattr(thief.socket, 'gethostbyname', lambda host: '10.0.0.1')  # hostname_resolves() -> True
        _argv(monkeypatch, '-H', 'cucm1', '-e', '10.0.0.0/30', '--db', str(db))
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 0
        out = capsys.readouterr().out
        # Regression for the found_credentials/found_usernames-never-populated bug:
        # _TEST_MODE's search_for_secrets fake data must actually surface here.
        assert 'Credentials Found in Configurations!' in out
        assert 'admin' in out and 'pass123' in out


# ---------------------------------------------------------------------------
# --phone (single-threaded path)
# ---------------------------------------------------------------------------

class TestPhoneDispatch:
    def test_single_phone_writes_credentials_to_db(self, monkeypatch, tmp_path, capsys):
        _set_test_mode(monkeypatch)
        db = tmp_path / 'thief.db'
        _argv(monkeypatch, '-H', 'mock-cucm', '-p', '1.2.3.4', '--db', str(db), '--threads', '1')
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 0

        conn = sqlite3.connect(db)
        rows = conn.execute("SELECT username, password FROM credentials").fetchall()
        conn.close()
        usernames = [r[0] for r in rows]
        assert 'admin' in usernames


# ---------------------------------------------------------------------------
# No target / validation errors
# ---------------------------------------------------------------------------

class TestNoTargetAndValidation:
    def test_no_target_exits_nonzero(self, monkeypatch, tmp_path, capsys):
        _set_test_mode(monkeypatch)
        db = tmp_path / 'thief.db'
        _argv(monkeypatch, '--db', str(db))
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1

    def test_directory_requires_host_in_process(self, monkeypatch, capsys):
        _set_test_mode(monkeypatch)
        _argv(monkeypatch, '--directory')
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1
        assert '--directory requires' in capsys.readouterr().out

    def test_userenum_requires_host_in_process(self, monkeypatch, capsys):
        _set_test_mode(monkeypatch)
        _argv(monkeypatch, '--userenum')
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1
        assert '--userenum requires' in capsys.readouterr().out

    def test_verify_requires_db(self, monkeypatch, capsys):
        _set_test_mode(monkeypatch)
        _argv(monkeypatch, '-H', 'cucm1', '--verify', '--no-db')
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1
        assert 'cannot be used with --no-db' in capsys.readouterr().out

    def test_phone_negative_threads_rejected(self, monkeypatch, capsys):
        # threads=0 is falsy, so `num_workers = ... if threads else 1` masks
        # it back to 1 -- only a negative thread count actually reaches the
        # num_workers < 1 validation branch.
        _set_test_mode(monkeypatch)
        _argv(monkeypatch, '-p', '1.2.3.4', '--threads', '-1')
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1
        assert 'Threads must be at least 1' in capsys.readouterr().out


# ---------------------------------------------------------------------------
# --http transport selection
# ---------------------------------------------------------------------------

class TestHttpTransportSelection:
    # Note: under _TEST_MODE, main() seeds the DB via a preamble call to
    # search_for_secrets('mock-cucm', ..., use_tftp=True) hardcoded True
    # regardless of --http, before ever reaching the phone-processing loop.
    # That shows up as calls[0]; only calls[1:] reflect the --http flag.

    def test_default_uses_tftp_first(self, monkeypatch, tmp_path):
        _set_test_mode(monkeypatch)
        db = tmp_path / 'thief.db'
        calls = []
        monkeypatch.setattr(thief, 'search_for_secrets',
                             lambda host, fname, use_tftp=True: (calls.append(use_tftp), ([], []))[1])
        _argv(monkeypatch, '-H', 'mock-cucm', '-p', '1.2.3.4', '--db', str(db), '--threads', '1')
        with pytest.raises(SystemExit):
            thief.main()
        assert calls[1:] and all(c is True for c in calls[1:])

    def test_http_flag_flips_to_http_first(self, monkeypatch, tmp_path):
        _set_test_mode(monkeypatch)
        db = tmp_path / 'thief.db'
        calls = []
        monkeypatch.setattr(thief, 'search_for_secrets',
                             lambda host, fname, use_tftp=True: (calls.append(use_tftp), ([], []))[1])
        _argv(monkeypatch, '-H', 'mock-cucm', '-p', '1.2.3.4', '--http', '--db', str(db), '--threads', '1')
        with pytest.raises(SystemExit):
            thief.main()
        assert calls[1:] and all(c is False for c in calls[1:])
