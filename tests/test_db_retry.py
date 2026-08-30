"""Unit tests for the SQLite 'database is locked' retry/backoff loops shared
by log_spray_attempt, log_verification_attempt, and log_download_attempt.
All three follow the same pattern: up to 5 attempts, sleeping
retry_delay * 2**attempt (retry_delay=0.1) between locked retries, giving up
silently (no raise) after the last attempt or on any non-locking error.
"""
import sqlite3

import pytest

from seeyoucm_thief import thief

# Captured before any test monkeypatches sqlite3.connect (thief.sqlite3 is the
# same module object, so patching one patches both).
_REAL_CONNECT = sqlite3.connect


class _LockThenSucceed:
    """Stand-in for sqlite3.connect: raises 'database is locked' for the
    first `fail_times` calls, then delegates to a real connection."""

    def __init__(self, real_db_file, fail_times):
        self.real_db_file = real_db_file
        self.fail_times = fail_times
        self.calls = 0

    def __call__(self, db_file, timeout=30.0):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise sqlite3.OperationalError("database is locked")
        return _REAL_CONNECT(self.real_db_file)


class _AlwaysLocked:
    def __init__(self):
        self.calls = 0

    def __call__(self, db_file, timeout=30.0):
        self.calls += 1
        raise sqlite3.OperationalError("database is locked")


@pytest.fixture
def sleeps(monkeypatch):
    calls = []
    monkeypatch.setattr(thief.time, 'sleep', lambda s: calls.append(s))
    return calls


# ---------------------------------------------------------------------------
# log_spray_attempt
# ---------------------------------------------------------------------------

def test_log_spray_attempt_retries_then_succeeds(db_path, monkeypatch, sleeps):
    fake = _LockThenSucceed(db_path, fail_times=2)
    monkeypatch.setattr(thief.sqlite3, 'connect', fake)
    thief.log_spray_attempt('cucm1', 'alice', 'pw', 401, None, db_file=db_path)
    assert fake.calls == 3  # 2 failures + 1 success
    assert sleeps == [0.1 * (2 ** 0), 0.1 * (2 ** 1)]

    conn = _REAL_CONNECT(db_path)
    rows = conn.execute("SELECT username FROM spray_attempts").fetchall()
    conn.close()
    assert rows == [('alice',)]


def test_log_spray_attempt_gives_up_silently_after_max_retries(db_path, monkeypatch, sleeps):
    fake = _AlwaysLocked()
    monkeypatch.setattr(thief.sqlite3, 'connect', fake)
    # Must not raise.
    thief.log_spray_attempt('cucm1', 'alice', 'pw', 401, None, db_file=db_path)
    assert fake.calls == 5
    assert len(sleeps) == 4  # slept between each of the first 4 attempts, not after the last


def test_log_spray_attempt_does_not_retry_non_locking_operational_error(db_path, monkeypatch, sleeps):
    def fake_connect(db_file, timeout=30.0):
        raise sqlite3.OperationalError("no such table: spray_attempts")
    monkeypatch.setattr(thief.sqlite3, 'connect', fake_connect)
    thief.log_spray_attempt('cucm1', 'alice', 'pw', 401, None, db_file=db_path)
    assert sleeps == []


# ---------------------------------------------------------------------------
# log_verification_attempt
# ---------------------------------------------------------------------------

def test_log_verification_attempt_retries_then_succeeds(db_path, monkeypatch, sleeps):
    fake = _LockThenSucceed(db_path, fail_times=1)
    monkeypatch.setattr(thief.sqlite3, 'connect', fake)
    thief.log_verification_attempt('cucm1', 'admin', 'pw', 'valid', 200, None, db_file=db_path)
    assert fake.calls == 2
    assert sleeps == [0.1]

    conn = _REAL_CONNECT(db_path)
    rows = conn.execute("SELECT result FROM verification_attempts").fetchall()
    conn.close()
    assert rows == [('valid',)]


def test_log_verification_attempt_gives_up_silently_after_max_retries(db_path, monkeypatch, sleeps):
    fake = _AlwaysLocked()
    monkeypatch.setattr(thief.sqlite3, 'connect', fake)
    thief.log_verification_attempt('cucm1', 'admin', 'pw', 'valid', 200, None, db_file=db_path)
    assert fake.calls == 5


# ---------------------------------------------------------------------------
# log_download_attempt
# ---------------------------------------------------------------------------

def test_log_download_attempt_retries_then_succeeds(db_path, monkeypatch, sleeps):
    fake = _LockThenSucceed(db_path, fail_times=3)
    monkeypatch.setattr(thief.sqlite3, 'connect', fake)
    thief.log_download_attempt('cucm1', 'SEP1.cnf.xml', True, 'TFTP', content='<a/>', db_file=db_path)
    assert fake.calls == 4
    assert sleeps == [0.1, 0.2, 0.4]

    conn = _REAL_CONNECT(db_path)
    rows = conn.execute("SELECT filename, success FROM download_attempts").fetchall()
    conn.close()
    assert rows == [('SEP1.cnf.xml', 1)]


def test_log_download_attempt_gives_up_silently_after_max_retries(db_path, monkeypatch, sleeps):
    fake = _AlwaysLocked()
    monkeypatch.setattr(thief.sqlite3, 'connect', fake)
    thief.log_download_attempt('cucm1', 'SEP1.cnf.xml', True, 'TFTP', db_file=db_path)
    assert fake.calls == 5

    conn = _REAL_CONNECT(db_path)
    rows = conn.execute("SELECT * FROM download_attempts").fetchall()
    conn.close()
    assert rows == []


def test_log_download_attempt_does_not_retry_non_locking_operational_error(db_path, monkeypatch, sleeps):
    def fake_connect(db_file, timeout=30.0):
        raise sqlite3.OperationalError("disk I/O error")
    monkeypatch.setattr(thief.sqlite3, 'connect', fake_connect)
    thief.log_download_attempt('cucm1', 'SEP1.cnf.xml', True, 'TFTP', db_file=db_path)
    assert sleeps == []
