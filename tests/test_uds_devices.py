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
    assert mock_get.call_args.args[0] == "https://cucm.example.com:8443/cucm-uds/user/alice"


def test_get_user_devices_authenticated_queries_target_user_with_caller_auth():
    fake_resp = MagicMock(status_code=200, text=UDS_USER_XML)
    with patch.object(thief.requests, 'get', return_value=fake_resp) as mock_get:
        status, devices = thief.get_user_devices_authenticated(
            "cucm.example.com", "alice", "Summer2025!", port=8443, target_user="bob")
    assert status == "ok"
    assert devices == ["SEP001122334455", "SEP667788990011"]
    # Path targets bob, but auth identity stays alice
    assert mock_get.call_args.args[0] == "https://cucm.example.com:8443/cucm-uds/user/bob"
    assert mock_get.call_args.kwargs.get('auth') == ("alice", "Summer2025!")


def test_get_user_devices_authenticated_defaults_target_to_auth_user():
    fake_resp = MagicMock(status_code=200, text=UDS_USER_XML)
    with patch.object(thief.requests, 'get', return_value=fake_resp) as mock_get:
        thief.get_user_devices_authenticated(
            "cucm.example.com", "alice", "pw", port=8443)
    assert mock_get.call_args.args[0] == "https://cucm.example.com:8443/cucm-uds/user/alice"


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


def test_get_user_devices_authenticated_returns_error_on_unexpected_status():
    fake_resp = MagicMock(status_code=403, text="Forbidden")
    with patch.object(thief.requests, 'get', return_value=fake_resp):
        status, devices = thief.get_user_devices_authenticated(
            "cucm.example.com", "alice", "pw", port=8443)
    assert status == "error"
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


def test_download_uds_discovered_configs_no_db_skips_credential_logging(db_path, monkeypatch):
    monkeypatch.setattr(thief, 'search_for_secrets',
                        lambda host, filename, use_tftp=True: ([('admin', 'cisco', filename)], []))
    logged = []
    monkeypatch.setattr(thief, 'log_credentials_to_db',
                        lambda *a, **kw: logged.append(a))

    count = thief.download_uds_discovered_configs(
        "cucm.example.com", ["SEP001122334455"], db_path, no_db=True,
    )

    assert count == 1          # still counts a hit
    assert logged == []        # but never touches the DB


# ---------------------------------------------------------------------------
# enumerate_devices_authenticated
# ---------------------------------------------------------------------------

def test_enumerate_devices_authenticated_collects_per_user_and_tallies(db_path):
    def fake_probe(cucm_host, username, password, port, target_user):
        if target_user == "alice":
            return "ok", ["SEP001122334455"]
        if target_user == "bob":
            return "unauthorized", []
        return "error", []

    result = thief.enumerate_devices_authenticated(
        "cucm.example.com", "alice", "pw", 8443,
        ["alice", "bob", "carol"], db_path, threads=3,
        _probe_fn=fake_probe,
    )
    assert result["devices"] == {"alice": ["SEP001122334455"]}
    assert result["ok"] == 1
    assert result["denied"] == 1
    assert result["errors"] == 1


def test_enumerate_devices_authenticated_logs_devices_with_uds_auth_source(db_path):
    def fake_probe(cucm_host, username, password, port, target_user):
        return ("ok", ["SEP001122334455"]) if target_user == "alice" else ("ok", [])

    thief.enumerate_devices_authenticated(
        "cucm.example.com", "alice", "pw", 8443,
        ["alice", "bob"], db_path, threads=2,
        _probe_fn=fake_probe,
    )
    rows = _rows(db_path, "SELECT username, device_name, source FROM uds_devices")
    assert ("alice", "SEP001122334455", "uds_auth") in rows


def test_enumerate_devices_authenticated_no_db_skips_logging(db_path):
    def fake_probe(cucm_host, username, password, port, target_user):
        return "ok", ["SEP001122334455"]

    thief.enumerate_devices_authenticated(
        "cucm.example.com", "alice", "pw", 8443,
        ["alice"], db_path, threads=1, no_db=True,
        _probe_fn=fake_probe,
    )
    rows = _rows(db_path, "SELECT COUNT(*) FROM uds_devices")
    assert rows[0][0] == 0


def test_enumerate_devices_authenticated_ok_with_no_devices_counts_ok_only(db_path):
    def fake_probe(cucm_host, username, password, port, target_user):
        return "ok", []

    result = thief.enumerate_devices_authenticated(
        "cucm.example.com", "alice", "pw", 8443,
        ["alice"], db_path, threads=1,
        _probe_fn=fake_probe,
    )
    assert result["ok"] == 1
    assert result["devices"] == {}


# ---------------------------------------------------------------------------
# _iter_uds_user_pages (shared pagination)
# ---------------------------------------------------------------------------

def test_iter_uds_user_pages_yields_each_page_body():
    page1 = '<users totalCount="3"><user><userName>a</userName></user><user><userName>b</userName></user></users>'
    page2 = '<users totalCount="3"><user><userName>c</userName></user></users>'
    responses = [MagicMock(status_code=200, text=page1),
                 MagicMock(status_code=200, text=page2)]

    def side_effect(url, **kwargs):
        return responses.pop(0)

    with patch.object(thief.requests, 'get', side_effect=side_effect):
        bodies = list(thief._iter_uds_user_pages("cucm.example.com", 8443))
    assert bodies == [page1, page2]


# ---------------------------------------------------------------------------
# parse_uds_directory
# ---------------------------------------------------------------------------

UDS_DIRECTORY_XML = """<?xml version="1.0" encoding="UTF-8"?>
<users totalCount="2">
  <user>
    <id>uuid-alice</id>
    <userName>alice</userName>
    <firstName>Alice</firstName>
    <lastName>Smith</lastName>
    <displayName>Alice Smith</displayName>
    <phoneNumber>1001</phoneNumber>
    <email>alice@corp.example</email>
    <department>Finance</department>
    <title>Analyst</title>
    <manager>bob</manager>
  </user>
  <user>
    <id>uuid-bob</id>
    <userName>bob</userName>
    <firstName>Bob</firstName>
  </user>
</users>"""


def test_parse_uds_directory_extracts_all_fields():
    records = thief.parse_uds_directory(UDS_DIRECTORY_XML)
    assert records[0] == {
        "username": "alice", "first_name": "Alice", "middle_name": "",
        "last_name": "Smith", "display_name": "Alice Smith",
        "phone_number": "1001", "home_number": "", "mobile_number": "",
        "email": "alice@corp.example", "ms_uri": "", "department": "Finance",
        "title": "Analyst", "manager": "bob", "user_id": "uuid-alice",
    }


def test_parse_uds_directory_missing_fields_are_empty():
    records = thief.parse_uds_directory(UDS_DIRECTORY_XML)
    assert records[1]["username"] == "bob"
    assert records[1]["first_name"] == "Bob"
    assert records[1]["last_name"] == ""
    assert records[1]["email"] == ""


def test_parse_uds_directory_skips_user_without_username():
    xml = "<users><user><firstName>NoName</firstName></user></users>"
    assert thief.parse_uds_directory(xml) == []


def test_parse_uds_directory_empty_body():
    assert thief.parse_uds_directory("") == []


def test_get_user_directory_api_assembles_records_across_pages():
    page1 = ('<users totalCount="2"><user><userName>alice</userName>'
             '<email>alice@corp.example</email></user></users>')
    page2 = ('<users totalCount="2"><user><userName>bob</userName>'
             '<department>IT</department></user></users>')
    responses = [MagicMock(status_code=200, text=page1),
                 MagicMock(status_code=200, text=page2)]

    def side_effect(url, **kwargs):
        return responses.pop(0)

    with patch.object(thief.requests, 'get', side_effect=side_effect):
        records = thief.get_user_directory_api("cucm.example.com", port=8443)
    assert [r["username"] for r in records] == ["alice", "bob"]
    assert records[0]["email"] == "alice@corp.example"
    assert records[1]["department"] == "IT"


# ---------------------------------------------------------------------------
# uds_directory table + record_uds_directory
# ---------------------------------------------------------------------------

def test_init_database_creates_uds_directory_table(db_path):
    import sqlite3 as _sq
    conn = _sq.connect(db_path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(uds_directory)").fetchall()}
    conn.close()
    assert {"cucm_host", "username", "first_name", "last_name", "display_name",
            "phone_number", "email", "department", "title", "manager", "user_id",
            "first_seen", "last_seen"} <= cols


def test_record_uds_directory_inserts_rows(db_path):
    recs = [{'username': 'alice', 'first_name': 'Alice', 'middle_name': '',
             'last_name': 'Smith', 'display_name': 'Alice Smith',
             'phone_number': '1001', 'home_number': '', 'mobile_number': '',
             'email': 'alice@corp.example', 'ms_uri': '', 'department': 'Finance',
             'title': 'Analyst', 'manager': 'bob', 'user_id': 'uuid-alice'}]
    thief.record_uds_directory("cucm.example.com", recs, db_path)
    rows = _rows(db_path, "SELECT username, email, department FROM uds_directory")
    assert rows == [("alice", "alice@corp.example", "Finance")]


def test_record_uds_directory_upserts_without_duplicates(db_path):
    rec = {'username': 'alice', 'first_name': 'Alice', 'middle_name': '',
           'last_name': 'Smith', 'display_name': '', 'phone_number': '1001',
           'home_number': '', 'mobile_number': '', 'email': 'old@corp.example',
           'ms_uri': '', 'department': '', 'title': '', 'manager': '',
           'user_id': 'uuid-alice'}
    thief.record_uds_directory("cucm.example.com", [rec], db_path)
    rec2 = dict(rec, email="new@corp.example")
    thief.record_uds_directory("cucm.example.com", [rec2], db_path)
    rows = _rows(db_path, "SELECT COUNT(*), MAX(email) FROM uds_directory WHERE username='alice'")
    assert rows[0][0] == 1
    assert rows[0][1] == "new@corp.example"


# ---------------------------------------------------------------------------
# directory CSV export
# ---------------------------------------------------------------------------

def test_directory_csv_name_derives_companion_name():
    assert thief._directory_csv_name("results.csv") == "results-directory.csv"
    assert thief._directory_csv_name("results") == "results-directory"
    assert thief._directory_csv_name("/tmp/out.csv") == "/tmp/out-directory.csv"


def test_export_directory_to_csv_writes_header_and_rows(tmp_path):
    recs = [{'username': 'alice', 'first_name': 'Alice', 'middle_name': '',
             'last_name': 'Smith', 'display_name': 'Alice Smith',
             'phone_number': '1001', 'home_number': '', 'mobile_number': '',
             'email': 'alice@corp.example', 'ms_uri': '', 'department': 'Finance',
             'title': 'Analyst', 'manager': 'bob', 'user_id': 'uuid-alice'}]
    out = tmp_path / "dir.csv"
    thief.export_directory_to_csv(recs, str(out))
    text = out.read_text()
    lines = text.strip().splitlines()
    assert lines[0] == ("username,first_name,last_name,display_name,phone_number,"
                        "home_number,mobile_number,email,ms_uri,department,title,"
                        "manager,user_id")
    assert lines[1].startswith("alice,Alice,Smith,Alice Smith,1001,")
    assert "alice@corp.example" in lines[1]
