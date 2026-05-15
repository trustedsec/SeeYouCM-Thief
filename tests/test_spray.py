"""Tests for the UDS password-spray feature."""
import os
import queue as queue_mod
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
import requests

from seeyoucm_thief import thief


@pytest.fixture(autouse=True)
def _disable_test_mode(monkeypatch):
    """Ensure _TEST_MODE is False so the real code paths execute."""
    monkeypatch.setattr(thief, '_TEST_MODE', False)


@pytest.fixture
def db_path(tmp_path):
    """Return a path to a freshly-initialized thief.db in tmp_path."""
    p = tmp_path / "thief.db"
    thief.init_database(str(p))
    return str(p)


def _table_columns(db_path, table):
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    finally:
        conn.close()
    return {row[1] for row in rows}  # column name is index 1


def _index_exists(db_path, index_name):
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
            (index_name,),
        ).fetchone()
    finally:
        conn.close()
    return row is not None


def test_init_database_creates_uds_users_table(db_path):
    cols = _table_columns(db_path, "uds_users")
    assert {"id", "cucm_host", "username", "first_seen", "last_seen"} <= cols


def test_init_database_creates_spray_attempts_table(db_path):
    cols = _table_columns(db_path, "spray_attempts")
    assert {
        "id", "cucm_host", "username", "password",
        "status_code", "error", "attempt_time",
    } <= cols


def test_init_database_creates_spray_attempts_index(db_path):
    assert _index_exists(db_path, "idx_spray_attempts_user_time")


def test_record_uds_users_inserts_new_rows(db_path):
    thief.record_uds_users("cucm-a.example.com", ["alice", "bob"], db_path)
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT cucm_host, username FROM uds_users ORDER BY username"
    ).fetchall()
    conn.close()
    assert rows == [
        ("cucm-a.example.com", "alice"),
        ("cucm-a.example.com", "bob"),
    ]


def test_record_uds_users_updates_last_seen_on_conflict(db_path):
    thief.record_uds_users("cucm-a.example.com", ["alice"], db_path)
    conn = sqlite3.connect(db_path)
    first_seen, last_seen_1 = conn.execute(
        "SELECT first_seen, last_seen FROM uds_users WHERE username='alice'"
    ).fetchone()
    conn.close()

    time.sleep(1)  # ensure timestamp differs at second granularity
    thief.record_uds_users("cucm-a.example.com", ["alice"], db_path)
    conn = sqlite3.connect(db_path)
    first_seen_2, last_seen_2 = conn.execute(
        "SELECT first_seen, last_seen FROM uds_users WHERE username='alice'"
    ).fetchone()
    conn.close()
    assert first_seen == first_seen_2  # first_seen is immutable
    assert last_seen_2 > last_seen_1  # last_seen advanced


def test_record_uds_users_host_scoped(db_path):
    thief.record_uds_users("cucm-a.example.com", ["alice"], db_path)
    thief.record_uds_users("cucm-b.example.com", ["alice"], db_path)
    conn = sqlite3.connect(db_path)
    count = conn.execute(
        "SELECT COUNT(*) FROM uds_users WHERE username='alice'"
    ).fetchone()[0]
    conn.close()
    assert count == 2  # one row per host


def test_log_spray_attempt_writes_row(db_path):
    thief.log_spray_attempt(
        "cucm-a.example.com", "alice", "Summer2025!", 200, None, db_path
    )
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT cucm_host, username, password, status_code, error "
        "FROM spray_attempts WHERE username='alice'"
    ).fetchone()
    conn.close()
    assert row == ("cucm-a.example.com", "alice", "Summer2025!", 200, None)


def test_log_spray_attempt_records_error_with_null_status(db_path):
    thief.log_spray_attempt(
        "cucm-a.example.com", "bob", "Winter2025!", None, "timeout: read timed out", db_path
    )
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT status_code, error FROM spray_attempts WHERE username='bob'"
    ).fetchone()
    conn.close()
    assert row[0] is None
    assert row[1] == "timeout: read timed out"


def test_log_spray_attempt_appends_history(db_path):
    """No UNIQUE constraint — each call adds a new row, preserving history."""
    for status in (401, 401, 200):
        thief.log_spray_attempt(
            "cucm-a.example.com", "alice", "p", status, None, db_path
        )
    conn = sqlite3.connect(db_path)
    count = conn.execute(
        "SELECT COUNT(*) FROM spray_attempts WHERE username='alice'"
    ).fetchone()[0]
    conn.close()
    assert count == 3


def _insert_attempt_at(db_path, username, minutes_ago, status_code=401, cucm_host="cucm-a.example.com"):
    ts = (datetime.now() - timedelta(minutes=minutes_ago)).strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO spray_attempts "
        "(cucm_host, username, password, status_code, error, attempt_time) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (cucm_host, username, "p", status_code, None, ts),
    )
    conn.commit()
    conn.close()


def test_is_user_rate_limited_recent_attempt(db_path):
    _insert_attempt_at(db_path, "alice", minutes_ago=30)
    assert thief.is_user_rate_limited("alice", db_path, hours=1) is True


def test_is_user_rate_limited_expired_window(db_path):
    _insert_attempt_at(db_path, "alice", minutes_ago=120)
    assert thief.is_user_rate_limited("alice", db_path, hours=1) is False


def test_is_user_rate_limited_no_history(db_path):
    assert thief.is_user_rate_limited("never-tried", db_path, hours=1) is False


def test_is_user_rate_limited_is_global_across_hosts(db_path):
    """Per design: rate limit is per-username globally, not per (host, username)."""
    _insert_attempt_at(db_path, "alice", minutes_ago=30, cucm_host="cucm-a.example.com")
    # Even though we're 'asking' about a different host, alice is still limited.
    assert thief.is_user_rate_limited("alice", db_path, hours=1) is True


def test_is_user_rate_limited_respects_custom_window(db_path):
    _insert_attempt_at(db_path, "alice", minutes_ago=90)  # 1.5h ago
    assert thief.is_user_rate_limited("alice", db_path, hours=1) is False
    assert thief.is_user_rate_limited("alice", db_path, hours=2) is True


def test_oracle_check_returns_ok_on_401():
    fake_resp = MagicMock(status_code=401, text="")
    with patch.object(thief.requests, 'get', return_value=fake_resp) as mock_get:
        result = thief._spray_oracle_check("cucm-a.example.com", 8443, "alice")
    assert result == 'ok'
    # The probe should have called the per-user endpoint with Basic Auth
    call_kwargs = mock_get.call_args.kwargs
    assert 'auth' in call_kwargs
    assert call_kwargs['auth'][0] == 'alice'
    assert call_kwargs['auth'][1].startswith('spray-probe-')


def test_oracle_check_returns_bypass_on_200():
    fake_resp = MagicMock(status_code=200, text="<user/>")
    with patch.object(thief.requests, 'get', return_value=fake_resp):
        result = thief._spray_oracle_check("cucm-a.example.com", 8443, "alice")
    assert result == 'bypass'


def test_oracle_check_returns_unknown_on_403():
    fake_resp = MagicMock(status_code=403, text="")
    with patch.object(thief.requests, 'get', return_value=fake_resp):
        result = thief._spray_oracle_check("cucm-a.example.com", 8443, "alice")
    assert result == 'unknown'


def test_oracle_check_returns_unknown_on_network_error():
    with patch.object(thief.requests, 'get', side_effect=requests.exceptions.ConnectTimeout("boom")):
        result = thief._spray_oracle_check("cucm-a.example.com", 8443, "alice")
    assert result == 'unknown'


def test_load_password_list_strips_and_skips_blanks(tmp_path):
    pw_file = tmp_path / "passwords.txt"
    pw_file.write_text("Summer2025!\n  Winter2024\n\n\t\nPassword1\n")
    pws = thief._load_password_list(str(pw_file))
    assert pws == ["Summer2025!", "Winter2024", "Password1"]


def test_load_password_list_preserves_order_and_duplicates(tmp_path):
    pw_file = tmp_path / "passwords.txt"
    pw_file.write_text("a\nb\na\n")
    pws = thief._load_password_list(str(pw_file))
    # Order matters (rounds run in file order); duplicates pass through —
    # if the operator listed it twice, that's their call.
    assert pws == ["a", "b", "a"]


def test_load_password_list_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        thief._load_password_list(str(tmp_path / "does-not-exist.txt"))


def test_spray_worker_logs_hit_on_200(db_path):
    work = queue_mod.Queue()
    work.put("alice")
    results = {"hits": 0, "misses": 0, "errors": 0, "other": 0, "lock": threading.Lock()}
    dead_flag = threading.Event()
    fake_resp = MagicMock(status_code=200, text="<user/>")
    with patch.object(thief.requests, 'get', return_value=fake_resp):
        thief._spray_worker(
            work_queue=work,
            results=results,
            password="Summer2025!",
            cucm_host="cucm-a.example.com",
            port=8443,
            db_file=db_path,
            dead_flag=dead_flag,
        )
    assert results["hits"] == 1
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT status_code, password FROM spray_attempts WHERE username='alice'"
    ).fetchone()
    conn.close()
    assert row == (200, "Summer2025!")


def test_spray_worker_logs_miss_on_401(db_path):
    work = queue_mod.Queue()
    work.put("bob")
    results = {"hits": 0, "misses": 0, "errors": 0, "other": 0, "lock": threading.Lock()}
    fake_resp = MagicMock(status_code=401, text="")
    with patch.object(thief.requests, 'get', return_value=fake_resp):
        thief._spray_worker(
            work_queue=work, results=results, password="bad",
            cucm_host="cucm-a.example.com", port=8443, db_file=db_path,
            dead_flag=threading.Event(),
        )
    assert results["misses"] == 1


def test_spray_worker_logs_error_on_timeout(db_path):
    work = queue_mod.Queue()
    work.put("carol")
    results = {"hits": 0, "misses": 0, "errors": 0, "other": 0, "lock": threading.Lock()}
    with patch.object(thief.requests, 'get', side_effect=requests.exceptions.ConnectTimeout("boom")):
        thief._spray_worker(
            work_queue=work, results=results, password="p",
            cucm_host="cucm-a.example.com", port=8443, db_file=db_path,
            dead_flag=threading.Event(),
        )
    assert results["errors"] == 1
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT status_code, error FROM spray_attempts WHERE username='carol'"
    ).fetchone()
    conn.close()
    assert row[0] is None
    assert row[1].startswith("timeout:")


def test_spray_worker_short_circuits_on_dead_flag(db_path):
    work = queue_mod.Queue()
    work.put("alice")
    work.put("bob")
    results = {"hits": 0, "misses": 0, "errors": 0, "other": 0, "lock": threading.Lock()}
    dead_flag = threading.Event()
    dead_flag.set()
    with patch.object(thief.requests, 'get') as mock_get:
        thief._spray_worker(
            work_queue=work, results=results, password="p",
            cucm_host="cucm-a.example.com", port=8443, db_file=db_path,
            dead_flag=dead_flag,
        )
    assert mock_get.call_count == 0  # never made any HTTP calls


def _patch_get_users(monkeypatch, users):
    """Bypass the real /cucm-uds/users HTTP call by patching get_users_api."""
    monkeypatch.setattr(thief, 'get_users_api', lambda *a, **kw: list(users))


def _patch_oracle(monkeypatch, result='ok'):
    monkeypatch.setattr(thief, '_spray_oracle_check', lambda *a, **kw: result)


def test_run_spray_end_to_end_single_password(monkeypatch, db_path):
    _patch_get_users(monkeypatch, ["alice", "bob", "carol"])
    _patch_oracle(monkeypatch, 'ok')

    def fake_get(url, **kwargs):
        # /cucm-uds/user/<userid>
        userid = url.rsplit('/', 1)[-1]
        status = 200 if userid == 'bob' else 401
        return MagicMock(status_code=status, text="")

    with patch.object(thief.requests, 'get', side_effect=fake_get):
        thief.run_spray(
            cucm_host="cucm-a.example.com", port=8443,
            passwords=["Summer2025!"], threads=2,
            rate_limit_hours=1, probe=True, db_file=db_path,
        )

    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT username, status_code FROM spray_attempts ORDER BY username"
    ).fetchall()
    conn.close()
    assert ("alice", 401) in rows
    assert ("bob", 200) in rows
    assert ("carol", 401) in rows
    assert len(rows) == 3


def test_run_spray_aborts_on_oracle_bypass(monkeypatch, db_path):
    _patch_get_users(monkeypatch, ["alice", "bob"])
    _patch_oracle(monkeypatch, 'bypass')
    with patch.object(thief.requests, 'get') as mock_get:
        thief.run_spray(
            cucm_host="cucm-a.example.com", port=8443,
            passwords=["Summer2025!"], threads=2,
            rate_limit_hours=1, probe=True, db_file=db_path,
        )
    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM spray_attempts").fetchone()[0]
    conn.close()
    assert count == 0
    assert mock_get.call_count == 0  # never made a real spray request


def test_run_spray_aborts_on_oracle_unknown(monkeypatch, db_path):
    _patch_get_users(monkeypatch, ["alice", "bob"])
    _patch_oracle(monkeypatch, 'unknown')
    with patch.object(thief.requests, 'get') as mock_get:
        thief.run_spray(
            cucm_host="cucm-a.example.com", port=8443,
            passwords=["Summer2025!"], threads=2,
            rate_limit_hours=1, probe=True, db_file=db_path,
        )
    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM spray_attempts").fetchone()[0]
    conn.close()
    assert count == 0
    assert mock_get.call_count == 0


def test_run_spray_skips_rate_limited_users(monkeypatch, db_path):
    _patch_get_users(monkeypatch, ["alice", "bob", "carol"])
    _patch_oracle(monkeypatch, 'ok')
    _insert_attempt_at(db_path, "alice", minutes_ago=30)  # alice is already limited

    requested_users = []

    def fake_get(url, **kwargs):
        userid = url.rsplit('/', 1)[-1]
        requested_users.append(userid)
        return MagicMock(status_code=401, text="")

    with patch.object(thief.requests, 'get', side_effect=fake_get):
        thief.run_spray(
            cucm_host="cucm-a.example.com", port=8443,
            passwords=["Summer2025!"], threads=2,
            rate_limit_hours=1, probe=True, db_file=db_path,
        )

    assert "alice" not in requested_users
    assert set(requested_users) == {"bob", "carol"}


def test_run_spray_kill_switch_on_majority_403(monkeypatch, db_path):
    users = [f"u{i}" for i in range(10)]
    _patch_get_users(monkeypatch, users)
    _patch_oracle(monkeypatch, 'ok')

    def fake_get(url, **kwargs):
        userid = url.rsplit('/', 1)[-1]
        idx = int(userid[1:])
        status = 403 if idx < 6 else 401  # 6/10 return 403
        return MagicMock(status_code=status, text="")

    with patch.object(thief.requests, 'get', side_effect=fake_get):
        thief.run_spray(
            cucm_host="cucm-a.example.com", port=8443,
            # two passwords — kill switch should stop us before round 2
            passwords=["p1", "p2"], threads=10,
            rate_limit_hours=1, probe=True, db_file=db_path,
        )

    conn = sqlite3.connect(db_path)
    # Only password 'p1' should appear; round 2 must be aborted before any 'p2' rows are written.
    pw_set = {row[0] for row in conn.execute("SELECT DISTINCT password FROM spray_attempts").fetchall()}
    conn.close()
    assert pw_set == {"p1"}


def test_run_spray_records_users_in_uds_users(monkeypatch, db_path):
    _patch_get_users(monkeypatch, ["alice", "bob"])
    _patch_oracle(monkeypatch, 'ok')
    with patch.object(thief.requests, 'get', return_value=MagicMock(status_code=401, text="")):
        thief.run_spray(
            cucm_host="cucm-a.example.com", port=8443,
            passwords=["p"], threads=1,
            rate_limit_hours=1, probe=True, db_file=db_path,
        )
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT username FROM uds_users ORDER BY username").fetchall()
    conn.close()
    assert rows == [("alice",), ("bob",)]


def test_run_spray_sleeps_between_password_rounds(monkeypatch, db_path):
    _patch_get_users(monkeypatch, ["alice"])
    _patch_oracle(monkeypatch, 'ok')
    sleeps = []
    monkeypatch.setattr(thief.time, 'sleep', lambda s: sleeps.append(s))
    with patch.object(thief.requests, 'get', return_value=MagicMock(status_code=401, text="")):
        thief.run_spray(
            cucm_host="cucm-a.example.com", port=8443,
            passwords=["p1", "p2"], threads=1,
            rate_limit_hours=1, probe=True, db_file=db_path,
        )
    # Exactly one inter-round sleep, within 3600 ± 60 seconds.
    inter_round = [s for s in sleeps if s > 100]  # filter out worker-internal sleeps if any
    assert len(inter_round) == 1
    assert 3540 <= inter_round[0] <= 3660


def test_run_spray_skips_probe_when_disabled(monkeypatch, db_path):
    _patch_get_users(monkeypatch, ["alice"])
    probe_called = {"n": 0}

    def fake_probe(*a, **kw):
        probe_called["n"] += 1
        return 'ok'

    monkeypatch.setattr(thief, '_spray_oracle_check', fake_probe)
    with patch.object(thief.requests, 'get', return_value=MagicMock(status_code=401, text="")):
        thief.run_spray(
            cucm_host="cucm-a.example.com", port=8443,
            passwords=["p"], threads=1,
            rate_limit_hours=1, probe=False, db_file=db_path,
        )
    assert probe_called["n"] == 0


def test_cli_requires_password_when_spray(monkeypatch, capsys):
    monkeypatch.setattr('sys.argv', ['thief', '-H', '1.2.3.4', '--spray'])
    with pytest.raises(SystemExit):
        thief.main()
    captured = capsys.readouterr()
    assert '--spray-password' in captured.err or '--spray-password' in captured.out


def test_cli_rejects_both_password_and_passwords_file(monkeypatch, tmp_path, capsys):
    pw = tmp_path / "p.txt"
    pw.write_text("x\n")
    monkeypatch.setattr('sys.argv', [
        'thief', '-H', '1.2.3.4', '--spray',
        '--spray-password', 'a', '-P', str(pw),
    ])
    with pytest.raises(SystemExit):
        thief.main()


def test_cli_rejects_spray_with_brute_mac(monkeypatch, capsys):
    monkeypatch.setattr('sys.argv', [
        'thief', '-H', '1.2.3.4', '--spray', '--spray-password', 'a', '--brute-mac',
    ])
    with pytest.raises(SystemExit):
        thief.main()


def test_cli_invokes_run_spray_with_correct_args(monkeypatch, tmp_path):
    called = {}

    def fake_run_spray(**kwargs):
        called.update(kwargs)

    monkeypatch.setattr(thief, 'run_spray', fake_run_spray)
    monkeypatch.setattr(thief, 'get_version', lambda *a, **kw: {'version': '15.0', 'prefix': None})
    db = tmp_path / "thief.db"
    monkeypatch.setattr('sys.argv', [
        'thief', '-H', '1.2.3.4', '--spray',
        '--spray-password', 'Summer2025!',
        '--spray-threads', '5',
        '--spray-rate-limit-hours', '2',
        '--db', str(db),
    ])
    with pytest.raises(SystemExit):
        thief.main()
    assert called['cucm_host'] == '1.2.3.4'
    assert called['passwords'] == ['Summer2025!']
    assert called['threads'] == 5
    assert called['rate_limit_hours'] == 2
    assert called['probe'] is True
    assert called['db_file'] == str(db)
    assert called['port'] == 8443  # default --uds-port


def test_cli_password_file_is_loaded(monkeypatch, tmp_path):
    pw_file = tmp_path / "passwords.txt"
    pw_file.write_text("p1\np2\np3\n")
    called = {}

    def fake_run_spray(**kwargs):
        called.update(kwargs)

    monkeypatch.setattr(thief, 'run_spray', fake_run_spray)
    monkeypatch.setattr(thief, 'get_version', lambda *a, **kw: {'version': '15.0', 'prefix': None})
    db = tmp_path / "thief.db"
    monkeypatch.setattr('sys.argv', [
        'thief', '-H', '1.2.3.4', '--spray', '-P', str(pw_file),
        '--db', str(db),
    ])
    with pytest.raises(SystemExit):
        thief.main()
    assert called['passwords'] == ['p1', 'p2', 'p3']


def test_cli_no_spray_probe_passes_probe_false(monkeypatch, tmp_path):
    called = {}
    monkeypatch.setattr(thief, 'run_spray', lambda **kw: called.update(kw))
    monkeypatch.setattr(thief, 'get_version', lambda *a, **kw: None)
    db = tmp_path / "thief.db"
    monkeypatch.setattr('sys.argv', [
        'thief', '-H', '1.2.3.4', '--spray', '--spray-password', 'p',
        '--no-spray-probe', '--db', str(db),
    ])
    with pytest.raises(SystemExit):
        thief.main()
    assert called['probe'] is False


def test_show_db_prints_spray_hits(db_path, capsys):
    # Seed one hit and one miss
    thief.log_spray_attempt("cucm-a.example.com", "alice", "Summer2025!", 200, None, db_path)
    thief.log_spray_attempt("cucm-a.example.com", "bob", "Summer2025!", 401, None, db_path)
    thief.display_database_summary(db_path)
    out = capsys.readouterr().out
    assert "UDS Spray Hits" in out
    assert "alice" in out
    assert "Summer2025!" in out
    assert "bob" not in out  # misses are not shown in the hits section


def test_spray_worker_urlencodes_username(db_path):
    """A username with special chars must not alter the URL path."""
    work = queue_mod.Queue()
    work.put("weird/name?x")
    results = {"hits": 0, "misses": 0, "errors": 0, "other": 0, "lock": threading.Lock()}
    captured_url = {}

    def fake_get(url, **kwargs):
        captured_url['url'] = url
        return MagicMock(status_code=401, text="")

    with patch.object(thief.requests, 'get', side_effect=fake_get):
        thief._spray_worker(
            work_queue=work, results=results, password="p",
            cucm_host="cucm-a.example.com", port=8443, db_file=db_path,
            dead_flag=threading.Event(),
        )
    assert captured_url['url'] == (
        'https://cucm-a.example.com:8443/cucm-uds/user/weird%2Fname%3Fx'
    )


def test_show_db_omits_spray_section_when_no_hits(db_path, capsys):
    # Seed only a miss; no 200s.
    thief.log_spray_attempt("cucm-a.example.com", "bob", "Winter", 401, None, db_path)
    thief.display_database_summary(db_path)
    out = capsys.readouterr().out
    assert "UDS Spray Hits" not in out
