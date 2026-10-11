"""Smoke tests: does each thief.main() CLI mode dispatch to the right
function and exit with the right code? Previously this layer did not exist
at all -- coverage was either pure-unit (mocked single functions) or full
subprocess e2e. These run thief.main() in-process with sys.argv patched.

_TEST_MODE is forced True only in tests that call _set_test_mode(), for
dispatch paths that have fast, deterministic _TEST_MODE branches. Most other
tests keep _TEST_MODE=False (conftest default) and mock leaf functions instead.
"""
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
    def test_requires_host(self, monkeypatch, tmp_path, capsys):
        _set_test_mode(monkeypatch)
        _argv(monkeypatch, '--servers', '--db', str(tmp_path / 'thief.db'))
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
        assert 'Discovered 2 cluster member' in out
        assert 'cucm-pub.test' in out
        assert 'cucm-sub1.test' in out

        conn = sqlite3.connect(db)
        count = conn.execute("SELECT COUNT(*) FROM cluster_servers").fetchone()[0]
        conn.close()
        assert count == 2


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
        # Prove the seeded phone was loaded and processed
        out = capsys.readouterr().out
        assert '10.0.0.5' in out


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
    def test_single_phone_writes_credentials_to_db(self, monkeypatch, tmp_path):
        # Do NOT force _TEST_MODE. Test the actual phone download path.
        db = tmp_path / 'thief.db'
        # Mock phone discovery and config retrieval functions
        monkeypatch.setattr(thief, 'get_cucm_name_from_phone', lambda *a, **kw: 'cucm.test')
        monkeypatch.setattr(thief, 'get_hostname_from_phone', lambda *a, **kw: 'SEP001122334455')
        monkeypatch.setattr(thief, 'get_phones_hostnames_from_reverse', lambda *a, **kw: [])
        monkeypatch.setattr(thief, 'get_config_names', lambda *a, **kw: ['SEP001122334455.cnf.xml'])
        # Mock search_for_secrets to return phone-specific credentials
        # Return format: (credentials_list, usernames_list) where each cred is (user, pass, filename)
        monkeypatch.setattr(thief, 'search_for_secrets',
                             lambda *a, **kw: ([('phoneuser', 'phonepw', 'SEP001122334455.cnf.xml')], []))
        _argv(monkeypatch, '-H', 'mock-cucm', '-p', '10.0.0.5', '--db', str(db), '-T', '1')
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 0

        # Verify that phoneuser was written (proves the phone path ran)
        conn = sqlite3.connect(db)
        cred_rows = conn.execute("SELECT username, password FROM credentials").fetchall()
        phone_cucm_rows = conn.execute("SELECT * FROM phone_cucm WHERE phone_ip = ?", ('10.0.0.5',)).fetchall()
        conn.close()
        usernames = [r[0] for r in cred_rows]
        assert 'phoneuser' in usernames
        assert len(phone_cucm_rows) > 0  # phone_cucm row must exist for 10.0.0.5


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
        out = capsys.readouterr().out
        assert 'You must enter either a phone IP address or the IP address of the CUCM server' in out

    def test_directory_requires_host_in_process(self, monkeypatch, tmp_path, capsys):
        _set_test_mode(monkeypatch)
        _argv(monkeypatch, '--directory', '--db', str(tmp_path / 'thief.db'))
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1
        assert '--directory requires' in capsys.readouterr().out

    def test_verify_requires_db(self, monkeypatch, tmp_path, capsys):
        _set_test_mode(monkeypatch)
        _argv(monkeypatch, '-H', 'cucm1', '--verify', '--db', str(tmp_path / 'thief.db'), '--no-db')
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1
        assert 'cannot be used with --no-db' in capsys.readouterr().out

    def test_phone_negative_threads_rejected(self, monkeypatch, tmp_path, capsys):
        # threads=0 is falsy, so `num_workers = ... if threads else 1` masks
        # it back to 1 -- only a negative thread count actually reaches the
        # num_workers < 1 validation branch.
        _set_test_mode(monkeypatch)
        _argv(monkeypatch, '-p', '1.2.3.4', '--threads', '-1', '--db', str(tmp_path / 'thief.db'))
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


# ---------------------------------------------------------------------------
# --show-db --csv export
# ---------------------------------------------------------------------------

class TestShowDbCsv:
    def _seed(self, db):
        thief.init_database(db)
        thief.log_credentials_to_db(
            'cucm-a',
            [('admin', 'pw1', 'SEP001122334455.cnf.xml')],
            [('bob', 'SEP001122334455.cnf.xml')],
            db,
        )

    def test_missing_db_exits_1(self, monkeypatch, tmp_path, capsys):
        _argv(monkeypatch, '--show-db', '--csv', str(tmp_path / 'o.csv'),
              '--db', str(tmp_path / 'nope.db'))
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1
        assert 'Database not found' in capsys.readouterr().out

    def test_exports_only_rows_with_passwords(self, monkeypatch, tmp_path, capsys):
        db = str(tmp_path / 'thief.db')
        self._seed(db)
        out_csv = tmp_path / 'o.csv'
        _argv(monkeypatch, '--show-db', '--csv', str(out_csv), '--db', db)
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 0
        body = out_csv.read_text()
        assert 'admin' in body and 'pw1' in body
        assert 'bob' not in body  # username-only rows are excluded
        assert 'Exported credentials (with passwords) to CSV' in capsys.readouterr().out

    def test_host_filter_excludes_other_cucm(self, monkeypatch, tmp_path):
        db = str(tmp_path / 'thief.db')
        self._seed(db)
        thief.log_credentials_to_db('cucm-b', [('root', 'pw2', 'SEPAABBCCDDEEFF.cnf.xml')], [], db)
        out_csv = tmp_path / 'o.csv'
        _argv(monkeypatch, '--show-db', '--csv', str(out_csv), '--db', db, '-H', 'cucm-a')
        with pytest.raises(SystemExit):
            thief.main()
        body = out_csv.read_text()
        assert 'pw1' in body and 'pw2' not in body


# ---------------------------------------------------------------------------
# --extract-configs guards
# ---------------------------------------------------------------------------

class TestExtractConfigsDispatch:
    def test_rejects_no_db(self, monkeypatch, tmp_path, capsys):
        _argv(monkeypatch, '--extract-configs', str(tmp_path / 'out'), '--no-db')
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1
        assert 'cannot be combined with --no-db' in capsys.readouterr().out

    def test_missing_db_exits_1(self, monkeypatch, tmp_path, capsys):
        _argv(monkeypatch, '--extract-configs', str(tmp_path / 'out'),
              '--db', str(tmp_path / 'nope.db'))
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1
        assert 'Run a scan first' in capsys.readouterr().out

    def test_write_errors_exit_1(self, monkeypatch, tmp_path):
        monkeypatch.setattr(thief, 'extract_configs_from_db', lambda db, out, debug=False: (3, 0, 1))
        _argv(monkeypatch, '--extract-configs', str(tmp_path / 'out'), '--db', str(tmp_path / 'x.db'))
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1


# ---------------------------------------------------------------------------
# --userenum dispatch
# ---------------------------------------------------------------------------

class TestUserenumDispatch:
    def test_requires_host(self, monkeypatch, tmp_path, capsys):
        _argv(monkeypatch, '--userenum', '--db', str(tmp_path / 'thief.db'))
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 1
        assert '--userenum requires' in capsys.readouterr().out

    def test_writes_users_and_logs_to_db(self, monkeypatch, tmp_path, capsys):
        db = str(tmp_path / 'thief.db')
        outfile = tmp_path / 'users.txt'
        monkeypatch.setattr(thief, 'get_users_api', lambda host, port=None, **kw: ['alice', 'bob', 'alice'])
        monkeypatch.setattr(thief, 'get_user_directory_api', lambda host, port=None, **kw: [])
        monkeypatch.setattr(thief, 'enumerate_devices_unauthenticated', lambda *a, **kw: 0)
        _argv(monkeypatch, '-H', 'cucm.test', '--userenum', '--db', db, '--outfile', str(outfile))
        with pytest.raises(SystemExit) as exc:
            thief.main()
        assert exc.value.code == 0
        assert sorted(outfile.read_text().split()) == ['alice', 'bob']
        out = capsys.readouterr().out
        assert 'Logged 2 UDS API usernames to database' in out
