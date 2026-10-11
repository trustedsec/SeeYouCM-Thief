"""Tests for UDS parsing robustness against malformed/truncated bodies, and
for the pagination cursor (_uds_next_link) and its termination guarantees
via _iter_uds_user_pages. These parsers are regex-based, so they degrade
silently rather than raising -- this file pins that degrade-gracefully
contract rather than assuming it."""
from unittest.mock import MagicMock

from seeyoucm_thief import thief


def _resp(text, status_code=200):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.content = text.encode()
    return r


# ---------------------------------------------------------------------------
# parse_uds_directory
# ---------------------------------------------------------------------------

class TestParseUdsDirectoryMalformed:
    def test_truncated_user_block_yields_no_records(self):
        # Missing closing </user> -- the non-greedy regex finds no complete block.
        body = "<users><user><userName>alice</userName>"
        assert thief.parse_uds_directory(body) == []

    def test_non_xml_html_error_page_yields_no_records(self):
        body = "<html><body><h1>500 Internal Server Error</h1></body></html>"
        assert thief.parse_uds_directory(body) == []

    def test_missing_optional_fields_default_to_empty_string(self):
        body = "<users><user><userName>alice</userName></user></users>"
        records = thief.parse_uds_directory(body)
        assert len(records) == 1
        assert records[0]['username'] == 'alice'
        assert records[0]['first_name'] == ''
        assert records[0]['email'] == ''

    def test_unescaped_ampersand_does_not_break_neighboring_fields(self):
        body = (
            "<users><user><userName>alice</userName>"
            "<department>R&D</department>"
            "<email>alice@example.com</email></user></users>"
        )
        records = thief.parse_uds_directory(body)
        assert records[0]['department'] == 'R&D'
        assert records[0]['email'] == 'alice@example.com'

    def test_multiple_users_one_malformed_one_valid(self):
        body = (
            "<users>"
            "<user><firstName>Ghost</firstName></user>"  # skipped: no userName
            "<user><userName>bob</userName><lastName>Smith</lastName></user>"
            "</users>"
        )
        records = thief.parse_uds_directory(body)
        assert len(records) == 1
        assert records[0]['username'] == 'bob'
        assert records[0]['last_name'] == 'Smith'


# ---------------------------------------------------------------------------
# parse_uds_devices
# ---------------------------------------------------------------------------

class TestParseUdsDevicesMalformed:
    def test_html_error_body_yields_no_devices(self):
        assert thief.parse_uds_devices('<html>500 error</html>') == []

    def test_truncated_device_tag_is_ignored(self):
        assert thief.parse_uds_devices('<device>SEP001122334455') == []


# ---------------------------------------------------------------------------
# _uds_next_link
# ---------------------------------------------------------------------------

class TestUdsNextLink:
    def test_appends_start_param_to_base_url_without_query_string(self):
        # Base URL without query string: append ?start=N
        url = thief._uds_next_link('https://cucm1:8443/cucm-uds/users', 0)
        assert url == 'https://cucm1:8443/cucm-uds/users?start=0'

    def test_appends_start_param_with_ampersand_when_query_string_exists(self):
        # Base URL with existing query string: append &start=N
        url = thief._uds_next_link('https://cucm1:8443/cucm-uds/users?foo=bar', 10)
        assert url == 'https://cucm1:8443/cucm-uds/users?foo=bar&start=10'

    def test_appends_nonzero_start_offset(self):
        # Nonzero offset: append ?start=N
        url = thief._uds_next_link('https://cucm1:8443/cucm-uds/users', 33)
        assert url == 'https://cucm1:8443/cucm-uds/users?start=33'


# ---------------------------------------------------------------------------
# _iter_uds_user_pages termination guarantees
# ---------------------------------------------------------------------------

class TestIterUdsUserPagesTermination:
    def test_terminates_on_empty_page(self, monkeypatch):
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp('<users></users>'))
        pages = list(thief._iter_uds_user_pages('cucm1'))
        assert pages == []

    def test_terminates_via_total_count(self, monkeypatch):
        page1 = '<users totalCount="2"><user><userName>a</userName></user></users>'
        calls = {'n': 0}

        def fake_get(url, **kw):
            calls['n'] += 1
            if calls['n'] == 1:
                return _resp(page1)
            return _resp('<users><user><userName>b</userName></user></users>')

        monkeypatch.setattr(thief.requests, 'get', fake_get)
        pages = list(thief._iter_uds_user_pages('cucm1'))
        assert len(pages) == 2
        assert calls['n'] == 2

    def test_terminates_on_pagination_loop_detection(self, monkeypatch):
        # Server always returns start="0" returnedCount="1", so the arithmetic
        # next_start = start + returnedCount always yields 1. This causes
        # _uds_next_link(base, 1) to produce the same URL on every iteration,
        # which the seen_urls set detects and breaks the loop.
        body = '<users start="0" returnedCount="1" totalCount="1000"><user><userName>a</userName></user></users>'

        calls = []
        def capture_get(url, **kw):
            calls.append(url)
            return _resp(body)

        monkeypatch.setattr(thief.requests, 'get', capture_get)
        pages = list(thief._iter_uds_user_pages('cucm1', max_pages=100))
        # Page 1: base URL (no start param), next_start = 0 + 1 = 1
        # Page 2: ?start=1, next_start = 0 + 1 = 1 (same calculation)
        # Next URL would be ?start=1 again, but it's already in seen_urls
        assert len(pages) == 2
        assert len(calls) == 2
        assert calls[1].endswith('/cucm-uds/users?start=1')

    def test_terminates_on_non_200_response(self, monkeypatch):
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp('error', status_code=500))
        assert list(thief._iter_uds_user_pages('cucm1')) == []

    def test_terminates_on_request_exception(self, monkeypatch):
        def raise_error(*a, **kw):
            raise thief.requests.exceptions.ConnectionError("boom")
        monkeypatch.setattr(thief.requests, 'get', raise_error)
        assert list(thief._iter_uds_user_pages('cucm1')) == []

    def test_respects_max_pages_guard(self, monkeypatch):
        # Responses omit start/returnedCount, so the fallback arithmetic
        # (next_start = collected) produces a fresh URL on each page; max_pages
        # must still bound the iteration.
        calls = {'n': 0}

        def fake_get(url, **kw):
            calls['n'] += 1
            return _resp(f'<users><user><userName>u{calls["n"]}</userName></user></users>')

        monkeypatch.setattr(thief.requests, 'get', fake_get)
        pages = list(thief._iter_uds_user_pages('cucm1', max_pages=3))
        assert len(pages) == 3
