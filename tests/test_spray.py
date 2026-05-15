"""Tests for the UDS password-spray feature."""
import os
import sqlite3
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


import queue as queue_mod
import threading


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
