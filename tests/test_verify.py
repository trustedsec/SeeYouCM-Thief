import sqlite3
import sys
import queue as _queue
import threading as _threading

import pytest

import thief


def test_init_database_creates_verification_attempts(tmp_path):
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    conn = sqlite3.connect(db)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(verification_attempts)")]
    conn.close()
    assert cols == [
        "id", "cucm_host", "username", "password",
        "result", "status_code", "error", "attempt_time",
    ]


def test_log_verification_attempt_writes_row(tmp_path):
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    thief.log_verification_attempt("cucm1", "admin", "pw", "valid", 302, None, db)
    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT cucm_host, username, password, result, status_code, error, attempt_time "
        "FROM verification_attempts"
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    host, user, pw, result, code, err, ts = rows[0]
    assert (host, user, pw, result, code, err) == ("cucm1", "admin", "pw", "valid", 302, None)
    assert ts  # non-empty timestamp recorded


def test_is_already_verified_definitive_vs_error(tmp_path):
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    assert thief.is_already_verified("h", "u", "p", db) is False
    thief.log_verification_attempt("h", "u", "p", "error", None, "timeout", db)
    assert thief.is_already_verified("h", "u", "p", db) is False
    thief.log_verification_attempt("h", "u", "p", "invalid", 200, None, db)
    assert thief.is_already_verified("h", "u", "p", db) is True
    thief.log_verification_attempt("h", "u2", "p", "valid", 302, None, db)
    assert thief.is_already_verified("h", "u2", "p", db) is True
    assert thief.is_already_verified("h", "u2", "other", db) is False


def test_get_distinct_credential_pairs_and_hosts(tmp_path):
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO credentials (cucm_host, device, username, password, discovery_time)"
                 " VALUES ('cA','SEP1','admin','pw1','t')")
    conn.execute("INSERT INTO credentials (cucm_host, device, username, password, discovery_time)"
                 " VALUES ('cA','SEP2','admin','pw1','t')")  # duplicate pair
    conn.execute("INSERT INTO credentials (cucm_host, device, username, password, discovery_time)"
                 " VALUES ('cB','SEP3','op','pw2','t')")
    conn.execute("INSERT INTO credentials (cucm_host, device, username, password, discovery_time)"
                 " VALUES ('cB','SEP4','nouser','','t')")  # empty password -> excluded
    conn.execute("INSERT INTO phone_cucm (cucm_host, phone_ip, discovery_time)"
                 " VALUES ('cC','1.2.3.4','t')")
    conn.execute("INSERT INTO cluster_servers (queried_host, hostname, ipv4, discovery_time)"
                 " VALUES ('cA','cD','5.6.7.8','t')")
    conn.commit()
    conn.close()

    pairs = thief.get_distinct_credential_pairs(db)
    assert sorted(pairs) == [("admin", "pw1"), ("op", "pw2")]

    hosts = thief.get_known_cucm_hosts(db)
    assert hosts == sorted({"cA", "cB", "cC", "cD", "5.6.7.8"})
