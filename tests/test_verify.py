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


class _FakeResp:
    def __init__(self, status_code, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


class _FakeSession:
    """Records POSTs; returns a 200 GET then the queued POST response/exc."""
    def __init__(self, post_resp, get_exc=None):
        self._post_resp = post_resp
        self._get_exc = get_exc
        self.posted = None

    def get(self, url, **kw):
        if self._get_exc:
            raise self._get_exc
        return _FakeResp(200)

    def post(self, url, data=None, **kw):
        self.posted = (url, data)
        if isinstance(self._post_resp, Exception):
            raise self._post_resp
        return self._post_resp


def test_verify_login_valid():
    sess = _FakeSession(_FakeResp(302, {"Location": "https://h:8443/ccmadmin/showHome.do"}))
    result, code = thief.verify_ccmadmin_login(sess, "h", 8443, "admin", "pw")
    assert result == "valid" and code == 302
    url, data = sess.posted
    assert url.endswith("/ccmadmin/j_security_check")
    assert data == {"j_username": "admin", "j_password": "pw"}


def test_verify_login_invalid_redirect_to_login():
    sess = _FakeSession(_FakeResp(302, {"Location": "https://h:8443/ccmadmin/showHome.do?login_error=1"}))
    result, code = thief.verify_ccmadmin_login(sess, "h", 8443, "admin", "bad")
    assert result == "invalid" and code == 302


def test_verify_login_invalid_200_form():
    sess = _FakeSession(_FakeResp(200))
    result, code = thief.verify_ccmadmin_login(sess, "h", 8443, "admin", "bad")
    assert result == "invalid" and code == 200


def test_verify_login_error_on_5xx():
    sess = _FakeSession(_FakeResp(503))
    result, code = thief.verify_ccmadmin_login(sess, "h", 8443, "admin", "pw")
    assert result == "error" and code == 503


def test_verify_login_error_on_exception():
    import requests as _rq
    sess = _FakeSession(_rq.exceptions.ConnectionError("boom"))
    result, code = thief.verify_ccmadmin_login(sess, "h", 8443, "admin", "pw")
    assert result == "error" and code is None


def test_verify_worker_logs_and_tallies(tmp_path):
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    work = _queue.Queue()
    for t in [("h1", "admin", "pw"), ("h2", "op", "bad"), ("h3", "x", "y")]:
        work.put(t)

    def fake_login(session, host, port, user, password, timeout=10):
        return {"h1": ("valid", 302), "h2": ("invalid", 200), "h3": ("error", None)}[host]

    results = {"valid": 0, "invalid": 0, "error": 0, "lock": _threading.Lock()}
    thief._verify_worker(work, results, 8443, db, _login_fn=fake_login)

    assert (results["valid"], results["invalid"], results["error"]) == (1, 1, 1)
    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT cucm_host, username, password, result FROM verification_attempts ORDER BY cucm_host"
    ).fetchall()
    conn.close()
    assert rows == [
        ("h1", "admin", "pw", "valid"),
        ("h2", "op", "bad", "invalid"),
        ("h3", "x", "y", "error"),
    ]


def test_run_verify_skips_already_verified(tmp_path, monkeypatch):
    monkeypatch.setattr(thief, "_TEST_MODE", False)
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    thief.log_verification_attempt("h1", "admin", "pw", "invalid", 200, None, db)

    attempted = []

    def fake_login(session, host, port, user, password, timeout=10):
        attempted.append((host, user, password))
        return ("valid", 302)

    monkeypatch.setattr(thief, "verify_ccmadmin_login", fake_login)

    results = thief.run_verify(
        hosts=["h1", "h2"],
        pairs=[("admin", "pw")],
        port=8443,
        threads=4,
        db_file=db,
    )
    assert ("h1", "admin", "pw") not in attempted
    assert ("h2", "admin", "pw") in attempted
    assert results["valid"] == 1
    assert results["skipped"] == 1


def test_run_verify_test_mode_is_noop(tmp_path, monkeypatch):
    # _TEST_MODE is False during tests (module imported at collection time,
    # before PYTEST_CURRENT_TEST is set), so force it True to exercise the
    # early-return branch.
    monkeypatch.setattr(thief, "_TEST_MODE", True)
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    assert thief.run_verify(["h"], [("u", "p")], 8443, 4, db) is None


def test_cli_verify_dispatches(tmp_path, monkeypatch):
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    captured = {}

    def fake_run_verify(hosts, pairs, port, threads, db_file):
        captured["port"] = port
        captured["threads"] = threads
        captured["db_file"] = db_file
        return None

    monkeypatch.setattr(thief, "run_verify", fake_run_verify)
    monkeypatch.setattr(sys, "argv", ["thief", "--verify", "--db", db,
                                      "--verify-port", "443", "--verify-threads", "3"])
    with pytest.raises(SystemExit) as ei:
        thief.main()
    assert ei.value.code == 0
    assert captured == {"port": 443, "threads": 3, "db_file": db}


def test_cli_verify_rejects_no_db(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["thief", "--verify", "--no-db"])
    with pytest.raises(SystemExit) as ei:
        thief.main()
    assert ei.value.code == 1


def test_cli_verify_mutually_exclusive_with_spray(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["thief", "--verify", "--spray", "-H", "h"])
    with pytest.raises(SystemExit) as ei:
        thief.main()
    assert ei.value.code == 1


def test_show_db_lists_verified_admins(tmp_path, monkeypatch, capsys):
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    thief.log_verification_attempt("cucmX", "admin", "pw", "valid", 302, None, db)
    thief.log_verification_attempt("cucmX", "bad", "nope", "invalid", 200, None, db)

    monkeypatch.setattr(sys, "argv", ["thief", "--show-db", "--db", db])
    with pytest.raises(SystemExit):
        thief.main()
    out = capsys.readouterr().out
    assert "Verified Admin Credentials" in out
    assert "admin" in out and "cucmX" in out
    assert "bad" not in out
