"""Tests for UDS endpoint hardening: usersResourceAuthEnabled parsing and the
8443<->9443 fallback introduced by Contact Search Authentication."""
from unittest.mock import MagicMock

import pytest

from seeyoucm_thief import thief


@pytest.fixture(autouse=True)
def _disable_test_mode(monkeypatch):
    monkeypatch.setattr(thief, '_TEST_MODE', False)


def _version_xml(auth=None):
    """Shaped per the official v14 version.get.xsd: a <versionInformation>
    wrapper whose version= attribute is the UDS schema version, a <version>
    element holding the CUCM version, and the capability flags nested under
    <capabilities>."""
    caps = ''
    if auth is not None:
        caps = ('<capabilities>'
                f"<usersResourceAuthEnabled>{'true' if auth else 'false'}</usersResourceAuthEnabled>"
                '</capabilities>')
    return ('<versionInformation uri="https://cucm/cucm-uds/version" version="10.0.0">'
            f'<version>14.0.1</version>{caps}</versionInformation>')


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.content = text.encode()
    return r


# --- get_version parsing ---------------------------------------------------

def test_get_version_parses_auth_flag_true(monkeypatch):
    monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp(_version_xml(auth=True)))
    info = thief.get_version('cucm', port=8443)
    assert info['version'] == '14.0.1'
    assert info['usersAuthRequired'] is True
    assert info['port'] == 8443


def test_get_version_parses_auth_flag_false(monkeypatch):
    monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp(_version_xml(auth=False)))
    info = thief.get_version('cucm', port=8443)
    assert info['usersAuthRequired'] is False


def test_get_version_absent_auth_flag_omitted(monkeypatch):
    monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp(_version_xml(auth=None)))
    info = thief.get_version('cucm', port=9443)
    assert 'usersAuthRequired' not in info
    assert info['port'] == 9443


# --- probe_uds fallback ----------------------------------------------------

def test_probe_uds_falls_back_to_9443(monkeypatch):
    seen = []

    def fake_get(url, **kw):
        seen.append(url)
        if ':8443/' in url:
            raise thief.requests.exceptions.Timeout('read timed out')
        return _resp(_version_xml(auth=True))

    monkeypatch.setattr(thief.requests, 'get', fake_get)
    info = thief.probe_uds('cucm', port=8443, allow_fallback=True)
    assert info is not None
    assert info['port'] == 9443
    assert any(':8443/' in u for u in seen) and any(':9443/' in u for u in seen)


def test_probe_uds_no_fallback_when_pinned(monkeypatch):
    seen = []

    def fake_get(url, **kw):
        seen.append(url)
        raise thief.requests.exceptions.Timeout('read timed out')

    monkeypatch.setattr(thief.requests, 'get', fake_get)
    info = thief.probe_uds('cucm', port=8443, allow_fallback=False)
    assert info is None
    assert all(':9443/' not in u for u in seen)


def test_probe_uds_no_second_call_when_first_succeeds(monkeypatch):
    seen = []

    def fake_get(url, **kw):
        seen.append(url)
        return _resp(_version_xml(auth=False))

    monkeypatch.setattr(thief.requests, 'get', fake_get)
    info = thief.probe_uds('cucm', port=8443, allow_fallback=True)
    assert info['port'] == 8443
    assert len(seen) == 1


# --- main() wiring ---------------------------------------------------------

def test_main_warns_when_auth_required(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(thief, 'probe_uds',
                        lambda *a, **kw: {'version': '14.0.1', 'usersAuthRequired': True, 'port': 8443})
    monkeypatch.setattr(thief, 'get_users_api', lambda *a, **kw: [])
    db = tmp_path / 'thief.db'
    thief.init_database(str(db))
    monkeypatch.setattr('sys.argv', ['thief', '--userenum', '-H', 'cucm', '--db', str(db)])
    with pytest.raises(SystemExit):
        thief.main()
    out = capsys.readouterr().out
    assert 'usersResourceAuthEnabled=true' in out


def test_main_threads_resolved_port_to_feature(monkeypatch, tmp_path):
    monkeypatch.setattr(thief, 'probe_uds',
                        lambda *a, **kw: {'version': '14.0.1', 'port': 9443})
    used = {}
    monkeypatch.setattr(thief, 'get_servers_api',
                        lambda host, port=8443, **kw: used.update(port=port) or [])
    db = tmp_path / 'thief.db'
    thief.init_database(str(db))
    monkeypatch.setattr('sys.argv', ['thief', '--servers', '-H', 'cucm', '--db', str(db)])
    with pytest.raises(SystemExit):
        thief.main()
    assert used['port'] == 9443
