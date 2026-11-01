"""UDS UserSearchLimit probe and page-size wiring (#34).

Cisco documents UserSearchLimit at GET /cucm-uds/options/userPolicy
(no auth), range 1-500, default 64, and `max` on /cucm-uds/users as the
per-page request size. These tests take that documentation as correct.
"""
from unittest.mock import MagicMock, patch

import pytest

from seeyoucm_thief import thief


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.content = text.encode()
    return r


def _policy_body(value):
    # The wrapper element name is not documented, so the parser must not
    # depend on it; an unrelated policy comes first to prove we pick by name.
    return (
        '<policies uri="https://cucm/cucm-uds/options/userPolicy">'
        '<policy uri="https://cucm/cucm-uds/options/userPolicy/OtherPolicy">'
        '<name>OtherPolicy</name><value>7</value></policy>'
        '<policy uri="https://cucm/cucm-uds/options/userPolicy/UserSearchLimit">'
        f'<name>UserSearchLimit</name><value>{value}</value>'
        '<range><default>64</default><min>1</min><max>500</max></range>'
        '</policy></policies>'
    )


# ---------------------------------------------------------------------------
# get_uds_search_limit
# ---------------------------------------------------------------------------

class TestGetUdsSearchLimit:
    def test_reads_user_search_limit_value(self):
        with patch.object(thief.requests, 'get', return_value=_resp(_policy_body(200))) as get:
            assert thief.get_uds_search_limit('cucm.example.com', 8443) == 200
        assert get.call_args[0][0] == 'https://cucm.example.com:8443/cucm-uds/options/userPolicy'
        assert get.call_args.kwargs['verify'] is False
        assert get.call_args.kwargs['timeout'] == 10

    def test_clamps_above_documented_max(self):
        with patch.object(thief.requests, 'get', return_value=_resp(_policy_body(1000))):
            assert thief.get_uds_search_limit('cucm.example.com', 8443) == thief.UDS_MAX_PAGE_SIZE

    def test_clamps_below_documented_min(self):
        with patch.object(thief.requests, 'get', return_value=_resp(_policy_body(0))):
            assert thief.get_uds_search_limit('cucm.example.com', 8443) == 1

    @pytest.mark.parametrize('body', [
        '<policies></policies>',
        _policy_body('lots'),
        'not xml at all',
    ])
    def test_missing_or_unparseable_value_returns_default(self, body):
        with patch.object(thief.requests, 'get', return_value=_resp(body)):
            assert thief.get_uds_search_limit('cucm.example.com', 8443) == thief.UDS_DEFAULT_PAGE_SIZE

    def test_non_200_returns_default(self):
        with patch.object(thief.requests, 'get', return_value=_resp('nope', status=404)):
            assert thief.get_uds_search_limit('cucm.example.com', 8443) == thief.UDS_DEFAULT_PAGE_SIZE

    def test_request_exception_returns_default(self):
        with patch.object(thief.requests, 'get', side_effect=thief.requests.ConnectionError('boom')):
            assert thief.get_uds_search_limit('cucm.example.com', 8443) == thief.UDS_DEFAULT_PAGE_SIZE

    def test_test_mode_skips_network(self, monkeypatch):
        monkeypatch.setattr(thief, '_TEST_MODE', True)
        with patch.object(thief.requests, 'get') as get:
            assert thief.get_uds_search_limit('cucm.example.com', 8443) == thief.UDS_DEFAULT_PAGE_SIZE
        get.assert_not_called()

    def test_caches_per_host_and_port(self):
        with patch.object(thief.requests, 'get', return_value=_resp(_policy_body(200))) as get:
            assert thief.get_uds_search_limit('cucm.example.com', 8443) == 200
            assert thief.get_uds_search_limit('cucm.example.com', 8443) == 200
            assert get.call_count == 1
            thief.get_uds_search_limit('cucm.example.com', 9443)
            assert get.call_count == 2

    def test_caches_the_default_after_a_failure(self):
        with patch.object(thief.requests, 'get', side_effect=thief.requests.ConnectionError('boom')) as get:
            thief.get_uds_search_limit('cucm.example.com', 8443)
            assert thief.get_uds_search_limit('cucm.example.com', 8443) == thief.UDS_DEFAULT_PAGE_SIZE
        assert get.call_count == 1


# ---------------------------------------------------------------------------
# _iter_uds_user_pages page-size wiring
# ---------------------------------------------------------------------------

def _users_page(users, start, total, requested):
    body = ''.join(f'<user><userName>{u}</userName></user>' for u in users)
    return (f'<users uri="https://cucm/cucm-uds/users" version="14.0" '
            f'start="{start}" requestedCount="{requested}" '
            f'returnedCount="{len(users)}" totalCount="{total}">{body}</users>')


def _fake_users_server(directory, page_size, urls):
    """Serve /users honoring start and max (capped at page_size), like CUCM."""
    import re

    def side_effect(url, **kwargs):
        urls.append(url)
        start_m = re.search(r'[?&]start=(\d+)', url)
        max_m = re.search(r'[?&]max=(\d+)', url)
        start = int(start_m.group(1)) if start_m else 0
        size = min(int(max_m.group(1)), page_size) if max_m else thief.UDS_DEFAULT_PAGE_SIZE
        window = directory[start:start + size]
        return _resp(_users_page(window, start, len(directory), size))
    return side_effect


def test_sends_max_on_every_page_when_limit_is_raised(monkeypatch):
    monkeypatch.setattr(thief, 'get_uds_search_limit', lambda *a, **k: 500)
    directory = [f'user{i:04d}' for i in range(1200)]
    urls = []
    with patch.object(thief.requests, 'get',
                      side_effect=_fake_users_server(directory, 500, urls)):
        users = thief.get_users_api('cucm.example.com', 8443)

    assert users == directory
    assert urls == [
        'https://cucm.example.com:8443/cucm-uds/users?max=500',
        'https://cucm.example.com:8443/cucm-uds/users?max=500&start=500',
        'https://cucm.example.com:8443/cucm-uds/users?max=500&start=1000',
    ]


def test_omits_max_when_limit_is_default(monkeypatch):
    monkeypatch.setattr(thief, 'get_uds_search_limit', lambda *a, **k: thief.UDS_DEFAULT_PAGE_SIZE)
    directory = [f'user{i:03d}' for i in range(100)]
    urls = []
    with patch.object(thief.requests, 'get',
                      side_effect=_fake_users_server(directory, 64, urls)):
        users = thief.get_users_api('cucm.example.com', 8443)

    assert users == directory
    assert urls == [
        'https://cucm.example.com:8443/cucm-uds/users',
        'https://cucm.example.com:8443/cucm-uds/users?start=64',
    ]


def test_omits_max_when_limit_is_below_default(monkeypatch):
    monkeypatch.setattr(thief, 'get_uds_search_limit', lambda *a, **k: 10)
    urls = []
    with patch.object(thief.requests, 'get',
                      side_effect=_fake_users_server(['a', 'b'], 10, urls)):
        thief.get_users_api('cucm.example.com', 8443)
    assert 'max=' not in urls[0]


def test_retries_first_page_without_max_when_server_rejects_it(monkeypatch, capsys):
    monkeypatch.setattr(thief, 'get_uds_search_limit', lambda *a, **k: 500)
    directory = [f'user{i:03d}' for i in range(100)]
    urls = []
    serve = _fake_users_server(directory, 64, urls)

    def side_effect(url, **kwargs):
        if 'max=' in url:
            urls.append(url)
            return _resp('<error/>', status=400)
        return serve(url, **kwargs)

    with patch.object(thief.requests, 'get', side_effect=side_effect):
        users = thief.get_users_api('cucm.example.com', 8443)

    assert users == directory
    assert urls[0] == 'https://cucm.example.com:8443/cucm-uds/users?max=500'
    assert urls[1] == 'https://cucm.example.com:8443/cucm-uds/users'
    assert all('max=' not in u for u in urls[1:])
    out = capsys.readouterr().out
    assert '[!] UDS did not accept max=500' in out
    assert f'continuing at the default {thief.UDS_DEFAULT_PAGE_SIZE} users per page' in out
    assert 'HTTP 400' in out


def test_retries_first_page_without_max_when_server_returns_empty_200(monkeypatch, capsys):
    monkeypatch.setattr(thief, 'get_uds_search_limit', lambda *a, **k: 500)
    directory = [f'user{i:03d}' for i in range(100)]
    urls = []
    serve = _fake_users_server(directory, thief.UDS_DEFAULT_PAGE_SIZE, urls)

    def side_effect(url, **kwargs):
        if 'max=' in url:
            urls.append(url)
            return _resp(_users_page([], 0, len(directory), 500))
        return serve(url, **kwargs)

    with patch.object(thief.requests, 'get', side_effect=side_effect):
        users = thief.get_users_api('cucm.example.com', 8443)

    assert users == directory
    assert urls[0] == 'https://cucm.example.com:8443/cucm-uds/users?max=500'
    assert urls[1] == 'https://cucm.example.com:8443/cucm-uds/users'
    assert all('max=' not in u for u in urls[1:])
    out = capsys.readouterr().out
    assert '[!] UDS did not accept max=500' in out
    assert f'continuing at the default {thief.UDS_DEFAULT_PAGE_SIZE} users per page' in out
    assert 'empty page' in out


def test_pager_probes_limit_with_same_host_port_timeout(monkeypatch):
    seen = []

    def fake_limit(host, port, timeout):
        seen.append((host, port, timeout))
        return thief.UDS_DEFAULT_PAGE_SIZE

    monkeypatch.setattr(thief, 'get_uds_search_limit', fake_limit)
    with patch.object(thief.requests, 'get',
                      side_effect=_fake_users_server(['a'], 64, [])):
        list(thief._iter_uds_user_pages('cucm.example.com', 9443, timeout=7))
    assert seen == [('cucm.example.com', 9443, 7)]


def test_shortfall_warning_explains_user_search_limit(monkeypatch, capsys):
    monkeypatch.setattr(thief, 'get_uds_search_limit', lambda *a, **k: thief.UDS_DEFAULT_PAGE_SIZE)
    # Server claims 10 matches but stops after 2 (returnedCount=0 on page 2).
    page1 = _users_page(['a', 'b'], 0, 10, 64)
    page2 = _users_page([], 2, 10, 64)
    responses = [_resp(page1), _resp(page2)]
    with patch.object(thief.requests, 'get', side_effect=lambda url, **k: responses.pop(0)):
        thief.get_users_api('cucm.example.com', 8443)

    out = capsys.readouterr().out
    assert 'UDS reports 10 matching users but only 2 were retrieved' in out
    assert 'UserSearchLimit' in out


def test_userenum_probes_once_and_pages_at_the_served_limit():
    """End to end: a real userPolicy body drives max= on both directory walks
    that --userenum makes, and the probe is fetched only once."""
    directory = [f'user{i:04d}' for i in range(600)]
    urls = []
    serve = _fake_users_server(directory, 500, urls)

    def side_effect(url, **kwargs):
        if url.endswith('/cucm-uds/options/userPolicy'):
            urls.append(url)
            return _resp(_policy_body(500))
        return serve(url, **kwargs)

    with patch.object(thief.requests, 'get', side_effect=side_effect):
        users = thief.get_users_api('cucm.example.com', 8443)
        records = thief.get_user_directory_api('cucm.example.com', 8443)

    assert users == directory
    assert [r['username'] for r in records] == directory
    assert [u for u in urls if u.endswith('/userPolicy')] == [
        'https://cucm.example.com:8443/cucm-uds/options/userPolicy']
    assert [u for u in urls if '/cucm-uds/users' in u] == [
        'https://cucm.example.com:8443/cucm-uds/users?max=500',
        'https://cucm.example.com:8443/cucm-uds/users?max=500&start=500',
    ] * 2
