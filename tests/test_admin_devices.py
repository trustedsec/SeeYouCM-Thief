import sqlite3
import queue as _queue
import threading as _threading

import pytest

import thief


# --- AXL response parsing ---------------------------------------------------

AXL_LIST_PHONE_RESPONSE = '''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <ns:listPhoneResponse xmlns:ns="http://www.cisco.com/AXL/API/14.0">
      <return>
        <phone uuid="{abc}"><name>SEP001122334455</name></phone>
        <phone uuid="{def}"><name>SEPAABBCCDDEEFF</name></phone>
      </return>
    </ns:listPhoneResponse>
  </soapenv:Body>
</soapenv:Envelope>'''

AXL_FAULT_RESPONSE = '''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <soapenv:Fault>
      <faultcode>soapenv:Client</faultcode>
      <faultstring>Unknown</faultstring>
    </soapenv:Fault>
  </soapenv:Body>
</soapenv:Envelope>'''


def test_parse_axl_phone_names_extracts_sep():
    names = thief.parse_axl_phone_names(AXL_LIST_PHONE_RESPONSE)
    assert names == ["SEP001122334455", "SEPAABBCCDDEEFF"]


def test_parse_axl_phone_names_ignores_non_sep():
    body = ('<return><phone><name>CSFalice</name></phone>'
            '<phone><name>SEP001122334455</name></phone></return>')
    assert thief.parse_axl_phone_names(body) == ["SEP001122334455"]


def test_parse_axl_phone_names_empty():
    assert thief.parse_axl_phone_names("<return/>") == []


# --- CCMAdmin HTML scrape parsing -------------------------------------------

CCMADMIN_PHONE_LIST_HTML = '''<html><body>
<table>
  <tr><td><a href="phoneEdit.do?key=1">SEP001122334455</a></td></tr>
  <tr><td><a href="phoneEdit.do?key=2">SEPAABBCCDDEEFF</a></td></tr>
</table>
<input type="hidden" name="name" value="SEPFFFFFFFFFFFF">
</body></html>'''


def test_parse_ccmadmin_device_names_dedupes_and_orders():
    names = thief.parse_ccmadmin_device_names(CCMADMIN_PHONE_LIST_HTML)
    # Deduped, case-normalised, sorted
    assert names == ["SEP001122334455", "SEPAABBCCDDEEFF", "SEPFFFFFFFFFFFF"]


def test_parse_ccmadmin_device_names_none():
    assert thief.parse_ccmadmin_device_names("<html>no devices</html>") == []


# --- DB: admin_devices table + logging --------------------------------------

def test_init_database_creates_admin_devices(tmp_path):
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    conn = sqlite3.connect(db)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(admin_devices)")]
    conn.close()
    assert cols == ["id", "cucm_host", "device_name", "source", "discovery_time"]


def test_log_admin_device_inserts_and_dedupes(tmp_path):
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    thief.log_admin_device("h1", "SEP001122334455", "axl", db)
    thief.log_admin_device("h1", "SEP001122334455", "axl", db)  # dup ignored
    thief.log_admin_device("h1", "SEPAABBCCDDEEFF", "ccmadmin", db)
    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT cucm_host, device_name, source FROM admin_devices ORDER BY device_name"
    ).fetchall()
    conn.close()
    assert rows == [
        ("h1", "SEP001122334455", "axl"),
        ("h1", "SEPAABBCCDDEEFF", "ccmadmin"),
    ]


# --- AXL fetch (injected POST) ----------------------------------------------

class _FakeResp:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


def test_get_admin_devices_axl_success():
    captured = {}

    def fake_post(url, data=None, headers=None, **kw):
        captured["url"] = url
        captured["data"] = data
        captured["headers"] = headers
        captured["auth"] = kw.get("auth")
        return _FakeResp(200, AXL_LIST_PHONE_RESPONSE)

    names = thief.get_admin_devices_axl("h", 8443, "admin", "pw", _post_fn=fake_post)
    assert names == ["SEP001122334455", "SEPAABBCCDDEEFF"]
    assert captured["url"] == "https://h:8443/axl/"
    assert captured["auth"] == ("admin", "pw")
    assert "listPhone" in captured["data"]


def test_get_admin_devices_axl_forbidden_returns_none():
    def fake_post(url, **kw):
        return _FakeResp(403, "")
    assert thief.get_admin_devices_axl("h", 8443, "admin", "pw", _post_fn=fake_post) is None


def test_get_admin_devices_axl_fault_returns_none():
    def fake_post(url, **kw):
        return _FakeResp(500, AXL_FAULT_RESPONSE)
    assert thief.get_admin_devices_axl("h", 8443, "admin", "pw", _post_fn=fake_post) is None


def test_get_admin_devices_axl_exception_returns_none():
    def fake_post(url, **kw):
        raise ConnectionError("boom")
    assert thief.get_admin_devices_axl("h", 8443, "admin", "pw", _post_fn=fake_post) is None


def test_get_admin_devices_axl_unrecognised_200_returns_none():
    # A 200 that isn't a listPhoneResponse (e.g. Tomcat interstitial) must return
    # None so dump_admin_devices falls back to scraping rather than trusting [].
    def fake_post(url, **kw):
        return _FakeResp(200, "<html>Some unexpected page</html>")
    assert thief.get_admin_devices_axl("h", 8443, "admin", "pw", _post_fn=fake_post) is None


def test_get_admin_devices_axl_empty_result_returns_empty_list():
    # A genuine empty listPhoneResponse is a real (empty) answer, not a fallback trigger.
    empty = ('<ns:listPhoneResponse xmlns:ns="http://www.cisco.com/AXL/API/14.0">'
             '<return></return></ns:listPhoneResponse>')
    def fake_post(url, **kw):
        return _FakeResp(200, empty)
    assert thief.get_admin_devices_axl("h", 8443, "admin", "pw", _post_fn=fake_post) == []


# --- scrape fallback coverage (injected login + GET) ------------------------

def _valid_login(session, host, port, user, pw, timeout=10):
    return ("valid", 302)


def test_get_admin_devices_scrape_login_fails_returns_empty():
    def bad_login(session, host, port, user, pw, timeout=10):
        return ("invalid", 200)

    def get_fn(url, **kw):
        raise AssertionError("GET must not run after a failed login")

    assert thief.get_admin_devices_scrape(
        "h", 8443, "admin", "bad", _login_fn=bad_login, _get_fn=get_fn
    ) == []


def test_get_admin_devices_scrape_paginates_until_short_page():
    # Page 1 full (250 rows), page 2 short (2 rows) -> stop after page 2.
    page1 = "".join(f'<a>SEP{ i:012X}</a>' for i in range(250))
    page2 = '<a>SEPAAAAAAAAAAAA</a><a>SEPBBBBBBBBBBBB</a>'
    pages = {1: page1, 2: page2}

    def get_fn(url, params=None, **kw):
        return _FakeResp(200, pages[int(params["page"])])

    names = thief.get_admin_devices_scrape(
        "h", 8443, "admin", "pw", _login_fn=_valid_login, _get_fn=get_fn
    )
    assert len(names) == 252
    assert "SEPAAAAAAAAAAAA" in names and "SEPBBBBBBBBBBBB" in names


def test_get_admin_devices_scrape_stops_on_http_error():
    # Page 1 returns devices; page 2 is a 500 -> stop, keep page 1's devices.
    def get_fn(url, params=None, **kw):
        page = int(params["page"])
        if page == 1:
            return _FakeResp(200, "".join(f'<a>SEP{i:012X}</a>' for i in range(250)))
        return _FakeResp(500, "")

    names = thief.get_admin_devices_scrape(
        "h", 8443, "admin", "pw", _login_fn=_valid_login, _get_fn=get_fn
    )
    assert len(names) == 250  # page 1 preserved, no crash


def test_get_admin_devices_scrape_handles_get_exception():
    def get_fn(url, **kw):
        raise ConnectionError("down")

    assert thief.get_admin_devices_scrape(
        "h", 8443, "admin", "pw", _login_fn=_valid_login, _get_fn=get_fn
    ) == []


# --- dump orchestration: AXL first, scrape fallback -------------------------

def test_dump_admin_devices_uses_axl_when_available(tmp_path):
    db = str(tmp_path / "t.db")
    thief.init_database(db)

    def fake_axl(host, port, user, pw, timeout=10):
        return ["SEP001122334455", "SEPAABBCCDDEEFF"]

    def fake_scrape(host, port, user, pw, timeout=10):
        raise AssertionError("scrape should not be called when AXL succeeds")

    names = thief.dump_admin_devices(
        "h1", 8443, "admin", "pw", db, _axl_fn=fake_axl, _scrape_fn=fake_scrape
    )
    assert names == ["SEP001122334455", "SEPAABBCCDDEEFF"]
    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT device_name, source FROM admin_devices ORDER BY device_name"
    ).fetchall()
    conn.close()
    assert rows == [
        ("SEP001122334455", "axl"),
        ("SEPAABBCCDDEEFF", "axl"),
    ]


def test_dump_admin_devices_falls_back_to_scrape(tmp_path):
    db = str(tmp_path / "t.db")
    thief.init_database(db)

    def fake_axl(host, port, user, pw, timeout=10):
        return None  # AXL unavailable (no role)

    def fake_scrape(host, port, user, pw, timeout=10):
        return ["SEPAABBCCDDEEFF"]

    names = thief.dump_admin_devices(
        "h1", 8443, "admin", "pw", db, _axl_fn=fake_axl, _scrape_fn=fake_scrape
    )
    assert names == ["SEPAABBCCDDEEFF"]
    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT device_name, source FROM admin_devices").fetchall()
    conn.close()
    assert rows == [("SEPAABBCCDDEEFF", "ccmadmin")]


def test_dump_admin_devices_swallows_errors(tmp_path):
    db = str(tmp_path / "t.db")
    thief.init_database(db)

    def boom(*a, **k):
        raise RuntimeError("network down")

    # Must not raise; returns [] when both paths fail.
    assert thief.dump_admin_devices(
        "h1", 8443, "admin", "pw", db, _axl_fn=boom, _scrape_fn=boom
    ) == []


# --- worker records valid logins --------------------------------------------

def test_verify_worker_records_valid_logins(tmp_path):
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    work = _queue.Queue()
    for t in [("h1", "admin", "pw"), ("h2", "op", "bad")]:
        work.put(t)

    def fake_login(session, host, port, user, password, timeout=10):
        return {"h1": ("valid", 302), "h2": ("invalid", 200)}[host]

    results = {"valid": 0, "invalid": 0, "error": 0, "lock": _threading.Lock()}
    thief._verify_worker(work, results, 8443, db, _login_fn=fake_login)

    assert results["valid_logins"] == {"h1": ("admin", "pw")}


# --- run_verify triggers dump once per valid host ---------------------------

def test_run_verify_dumps_devices_for_valid_hosts(tmp_path, monkeypatch):
    monkeypatch.setattr(thief, "_TEST_MODE", False)
    db = str(tmp_path / "t.db")
    thief.init_database(db)

    def fake_login(session, host, port, user, password, timeout=10):
        return ("valid", 302) if host == "h1" else ("invalid", 200)

    monkeypatch.setattr(thief, "verify_ccmadmin_login", fake_login)

    dumped = []

    def fake_dump(host, port, user, pw, db_file, **kw):
        dumped.append((host, user, pw))
        return ["SEP001122334455"]

    results = thief.run_verify(
        hosts=["h1", "h2"],
        pairs=[("admin", "pw")],
        port=8443,
        threads=4,
        db_file=db,
        _dump_fn=fake_dump,
    )
    assert dumped == [("h1", "admin", "pw")]
    assert results["valid"] == 1


def test_run_verify_dump_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(thief, "_TEST_MODE", False)
    db = str(tmp_path / "t.db")
    thief.init_database(db)

    monkeypatch.setattr(
        thief, "verify_ccmadmin_login",
        lambda *a, **k: ("valid", 302),
    )

    dumped = []
    thief.run_verify(
        hosts=["h1"],
        pairs=[("admin", "pw")],
        port=8443,
        threads=4,
        db_file=db,
        dump_devices=False,
        _dump_fn=lambda *a, **k: dumped.append(a) or [],
    )
    assert dumped == []


def test_run_verify_chases_configs_for_dumped_devices(tmp_path, monkeypatch):
    monkeypatch.setattr(thief, "_TEST_MODE", False)
    db = str(tmp_path / "t.db")
    thief.init_database(db)

    monkeypatch.setattr(
        thief, "verify_ccmadmin_login",
        lambda s, h, p, u, pw, timeout=10: ("valid", 302) if h == "h1" else ("invalid", 200),
    )

    def fake_dump(host, port, user, pw, db_file, **kw):
        return ["SEP001122334455", "SEPAABBCCDDEEFF"]

    chased = {}

    def fake_download(host, device_names, db_file, use_tftp=True, no_db=False):
        chased["args"] = (host, list(device_names), use_tftp)
        return 1

    thief.run_verify(
        hosts=["h1", "h2"],
        pairs=[("admin", "pw")],
        port=8443,
        threads=4,
        db_file=db,
        use_tftp=False,
        _dump_fn=fake_dump,
        _download_fn=fake_download,
    )
    assert chased["args"] == ("h1", ["SEP001122334455", "SEPAABBCCDDEEFF"], False)


def test_run_verify_skips_config_chase_when_no_devices(tmp_path, monkeypatch):
    monkeypatch.setattr(thief, "_TEST_MODE", False)
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    monkeypatch.setattr(
        thief, "verify_ccmadmin_login", lambda *a, **k: ("valid", 302)
    )

    called = []
    thief.run_verify(
        hosts=["h1"],
        pairs=[("admin", "pw")],
        port=8443,
        threads=4,
        db_file=db,
        _dump_fn=lambda *a, **k: [],  # no devices discovered
        _download_fn=lambda *a, **k: called.append(a) or 0,
    )
    assert called == []


def test_run_verify_no_chase_when_dump_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(thief, "_TEST_MODE", False)
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    monkeypatch.setattr(
        thief, "verify_ccmadmin_login", lambda *a, **k: ("valid", 302)
    )

    called = []
    thief.run_verify(
        hosts=["h1"],
        pairs=[("admin", "pw")],
        port=8443,
        threads=4,
        db_file=db,
        dump_devices=False,
        _dump_fn=lambda *a, **k: ["SEP001122334455"],
        _download_fn=lambda *a, **k: called.append(a) or 0,
    )
    assert called == []


def test_show_db_lists_admin_devices(tmp_path, monkeypatch, capsys):
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    thief.log_admin_device("cucmX", "SEP001122334455", "axl", db)
    thief.log_admin_device("cucmX", "SEPAABBCCDDEEFF", "ccmadmin", db)

    monkeypatch.setattr("sys.argv", ["thief", "--show-db", "--db", db])
    with pytest.raises(SystemExit):
        thief.main()
    out = capsys.readouterr().out
    assert "Admin Devices" in out
    assert "SEP001122334455" in out
    assert "SEPAABBCCDDEEFF" in out
