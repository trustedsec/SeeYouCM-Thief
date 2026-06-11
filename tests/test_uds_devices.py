"""Tests for unauthenticated UDS device enumeration."""
import sqlite3
from unittest.mock import MagicMock, patch

import pytest
import requests

from seeyoucm_thief import thief


@pytest.fixture(autouse=True)
def _disable_test_mode(monkeypatch):
    monkeypatch.setattr(thief, '_TEST_MODE', False)


@pytest.fixture
def db_path(tmp_path):
    p = tmp_path / "thief.db"
    thief.init_database(str(p))
    return str(p)


def _rows(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows


# ---------------------------------------------------------------------------
# parse_uds_devices
# ---------------------------------------------------------------------------

UDS_USER_XML = """<?xml version="1.0" encoding="UTF-8"?>
<user>
  <userName>alice</userName>
  <associatedDevices>
    <device>SEP001122334455</device>
    <device>SEP667788990011</device>
  </associatedDevices>
</user>"""

UDS_USER_XML_NO_DEVICES = """<?xml version="1.0" encoding="UTF-8"?>
<user>
  <userName>bob</userName>
</user>"""


def test_parse_uds_devices_returns_sep_names():
    devices = thief.parse_uds_devices(UDS_USER_XML)
    assert devices == ["SEP001122334455", "SEP667788990011"]


def test_parse_uds_devices_returns_empty_when_no_devices():
    assert thief.parse_uds_devices(UDS_USER_XML_NO_DEVICES) == []


def test_parse_uds_devices_returns_empty_on_blank_body():
    assert thief.parse_uds_devices("") == []


def test_parse_uds_devices_ignores_non_sep_device_names():
    xml = "<user><associatedDevices><device>CIPC001122334455</device><device>SEP001122334455</device></associatedDevices></user>"
    assert thief.parse_uds_devices(xml) == ["SEP001122334455"]


# ---------------------------------------------------------------------------
# uds_devices DB table
# ---------------------------------------------------------------------------

def test_init_database_creates_uds_devices_table(db_path):
    conn = sqlite3.connect(db_path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(uds_devices)").fetchall()}
    conn.close()
    assert {"id", "cucm_host", "username", "device_name", "source", "discovery_time"} <= cols


def test_log_uds_device_inserts_row(db_path):
    thief.log_uds_device("cucm.example.com", "alice", "SEP001122334455", "userenum", db_path)
    rows = _rows(db_path, "SELECT cucm_host, username, device_name, source FROM uds_devices")
    assert rows == [("cucm.example.com", "alice", "SEP001122334455", "userenum")]


def test_log_uds_device_ignores_duplicate(db_path):
    thief.log_uds_device("cucm.example.com", "alice", "SEP001122334455", "userenum", db_path)
    thief.log_uds_device("cucm.example.com", "alice", "SEP001122334455", "userenum", db_path)
    rows = _rows(db_path, "SELECT COUNT(*) FROM uds_devices")
    assert rows[0][0] == 1


# ---------------------------------------------------------------------------
# get_user_devices_unauthenticated
# ---------------------------------------------------------------------------

def test_get_user_devices_unauthenticated_returns_devices_on_200():
    fake_resp = MagicMock(status_code=200, text=UDS_USER_XML)
    with patch.object(thief.requests, 'get', return_value=fake_resp) as mock_get:
        devices = thief.get_user_devices_unauthenticated("cucm.example.com", 8443, "alice")
    assert devices == ["SEP001122334455", "SEP667788990011"]
    call_kwargs = mock_get.call_args
    assert 'auth' not in (call_kwargs.kwargs or {})


def test_get_user_devices_unauthenticated_returns_empty_on_401():
    fake_resp = MagicMock(status_code=401, text="")
    with patch.object(thief.requests, 'get', return_value=fake_resp):
        devices = thief.get_user_devices_unauthenticated("cucm.example.com", 8443, "alice")
    assert devices == []


def test_get_user_devices_unauthenticated_returns_empty_on_network_error():
    with patch.object(thief.requests, 'get', side_effect=requests.exceptions.ConnectTimeout("boom")):
        devices = thief.get_user_devices_unauthenticated("cucm.example.com", 8443, "alice")
    assert devices == []


# ---------------------------------------------------------------------------
# get_user_devices_authenticated
# ---------------------------------------------------------------------------

def test_get_user_devices_authenticated_returns_ok_and_devices_on_200():
    fake_resp = MagicMock(status_code=200, text=UDS_USER_XML)
    with patch.object(thief.requests, 'get', return_value=fake_resp) as mock_get:
        status, devices = thief.get_user_devices_authenticated(
            "cucm.example.com", "alice", "Summer2025!", port=8443)
    assert status == "ok"
    assert devices == ["SEP001122334455", "SEP667788990011"]
    # Must send Basic auth as the end user
    assert mock_get.call_args.kwargs.get('auth') == ("alice", "Summer2025!")


def test_get_user_devices_authenticated_returns_unauthorized_on_401():
    fake_resp = MagicMock(status_code=401, text="")
    with patch.object(thief.requests, 'get', return_value=fake_resp):
        status, devices = thief.get_user_devices_authenticated(
            "cucm.example.com", "alice", "wrong", port=8443)
    assert status == "unauthorized"
    assert devices == []


def test_get_user_devices_authenticated_returns_error_on_network_failure():
    with patch.object(thief.requests, 'get',
                      side_effect=requests.exceptions.ConnectTimeout("boom")):
        status, devices = thief.get_user_devices_authenticated(
            "cucm.example.com", "alice", "pw", port=8443)
    assert status == "error"
    assert devices == []


def test_get_user_devices_authenticated_returns_ok_empty_when_no_devices():
    fake_resp = MagicMock(status_code=200, text=UDS_USER_XML_NO_DEVICES)
    with patch.object(thief.requests, 'get', return_value=fake_resp):
        status, devices = thief.get_user_devices_authenticated(
            "cucm.example.com", "bob", "pw", port=8443)
    assert status == "ok"
    assert devices == []


# ---------------------------------------------------------------------------
# enumerate_devices_unauthenticated
# ---------------------------------------------------------------------------

def test_enumerate_devices_unauthenticated_logs_found_devices(db_path):
    def fake_probe(cucm_host, port, username):
        if username == "alice":
            return ["SEP001122334455"]
        return []

    thief.enumerate_devices_unauthenticated(
        "cucm.example.com", 8443, ["alice", "bob"], db_path, threads=2,
        _probe_fn=fake_probe,
    )
    rows = _rows(db_path, "SELECT username, device_name, source FROM uds_devices")
    assert ("alice", "SEP001122334455", "userenum") in rows
    assert not any(r[0] == "bob" for r in rows)


def test_enumerate_devices_unauthenticated_returns_count_found(db_path):
    def fake_probe(cucm_host, port, username):
        return ["SEP001122334455"] if username == "alice" else []

    count = thief.enumerate_devices_unauthenticated(
        "cucm.example.com", 8443, ["alice", "bob"], db_path, threads=2,
        _probe_fn=fake_probe,
    )
    assert count == 1


# ---------------------------------------------------------------------------
# _spray_worker device parsing on 200
# ---------------------------------------------------------------------------

def test_spray_worker_logs_devices_from_200_response(db_path):
    import queue as queue_mod
    import threading

    work = queue_mod.Queue()
    work.put("alice")
    results = {"hits": 0, "misses": 0, "errors": 0, "other": 0, "lock": threading.Lock()}
    fake_resp = MagicMock(status_code=200, text=UDS_USER_XML)
    with patch.object(thief.requests, 'get', return_value=fake_resp):
        thief._spray_worker(
            work_queue=work, results=results, password="Summer2025!",
            cucm_host="cucm.example.com", port=8443, db_file=db_path,
            dead_flag=threading.Event(),
        )
    rows = _rows(db_path, "SELECT username, device_name, source FROM uds_devices")
    assert ("alice", "SEP001122334455", "spray_hit") in rows
    assert ("alice", "SEP667788990011", "spray_hit") in rows


def test_spray_worker_does_not_log_devices_on_401(db_path):
    import queue as queue_mod
    import threading

    work = queue_mod.Queue()
    work.put("bob")
    results = {"hits": 0, "misses": 0, "errors": 0, "other": 0, "lock": threading.Lock()}
    fake_resp = MagicMock(status_code=401, text="")
    with patch.object(thief.requests, 'get', return_value=fake_resp):
        thief._spray_worker(
            work_queue=work, results=results, password="bad",
            cucm_host="cucm.example.com", port=8443, db_file=db_path,
            dead_flag=threading.Event(),
        )
    rows = _rows(db_path, "SELECT COUNT(*) FROM uds_devices")
    assert rows[0][0] == 0


# ---------------------------------------------------------------------------
# --show-db uds_devices section
# ---------------------------------------------------------------------------

def test_show_db_displays_uds_devices(db_path, capsys):
    thief.log_uds_device("cucm.example.com", "alice", "SEP001122334455", "userenum", db_path)
    thief.display_database_summary(db_path)
    out = capsys.readouterr().out
    assert "SEP001122334455" in out
    assert "alice" in out


def test_show_db_omits_uds_devices_section_when_empty(db_path, capsys):
    thief.display_database_summary(db_path)
    out = capsys.readouterr().out
    assert "UDS Devices" not in out


# ---------------------------------------------------------------------------
# download_uds_discovered_configs
# ---------------------------------------------------------------------------

def test_download_uds_discovered_configs_calls_search_for_each_device(db_path, monkeypatch):
    searched = []
    monkeypatch.setattr(thief, 'search_for_secrets',
                        lambda host, filename, use_tftp=True: (searched.append(filename), ([], []))[1])

    thief.download_uds_discovered_configs(
        "cucm.example.com", ["SEP001122334455", "SEP667788990011"], db_path,
    )

    assert "SEP001122334455.cnf.xml" in searched
    assert "SEP667788990011.cnf.xml" in searched


def test_download_uds_discovered_configs_logs_credentials_to_db(db_path, monkeypatch):
    monkeypatch.setattr(thief, 'search_for_secrets',
                        lambda host, filename, use_tftp=True: ([('admin', 'cisco', filename)], []))

    thief.download_uds_discovered_configs(
        "cucm.example.com", ["SEP001122334455"], db_path,
    )

    import sqlite3
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT username, password FROM credentials").fetchall()
    conn.close()
    assert ("admin", "cisco") in rows


def test_download_uds_discovered_configs_returns_hit_count(db_path, monkeypatch):
    def fake_search(host, filename, use_tftp=True):
        if "001122334455" in filename:
            return ([('admin', 'cisco', filename)], [])
        return ([], [])

    monkeypatch.setattr(thief, 'search_for_secrets', fake_search)

    count = thief.download_uds_discovered_configs(
        "cucm.example.com", ["SEP001122334455", "SEP667788990011"], db_path,
    )

    assert count == 1


def test_download_uds_discovered_configs_handles_empty_list(db_path, monkeypatch):
    called = []
    monkeypatch.setattr(thief, 'search_for_secrets', lambda *a, **kw: called.append(1) or ([], []))

    count = thief.download_uds_discovered_configs("cucm.example.com", [], db_path)

    assert count == 0
    assert called == []
