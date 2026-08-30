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
    def test_user_without_username_is_skipped(self):
        body = "<users><user><firstName>NoName</firstName></user></users>"
        assert thief.parse_uds_directory(body) == []

    def test_truncated_user_block_yields_no_records(self):
        # Missing closing </user> -- the non-greedy regex finds no complete block.
        body = "<users><user><userName>alice</userName>"
        assert thief.parse_uds_directory(body) == []

    def test_empty_body_yields_no_records(self):
        assert thief.parse_uds_directory('') == []

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
    def test_empty_body_yields_no_devices(self):
        assert thief.parse_uds_devices('') == []

    def test_html_error_body_yields_no_devices(self):
        assert thief.parse_uds_devices('<html>500 error</html>') == []

    def test_non_sep_device_names_are_ignored(self):
        assert thief.parse_uds_devices('<device>CSFALICE</device>') == []

    def test_truncated_device_tag_is_ignored(self):
        assert thief.parse_uds_devices('<device>SEP00112233') == []

    def test_multiple_valid_devices(self):
        body = "<devices><device>SEP001122334455</device><device>SEPAABBCCDDEEFF</device></devices>"
        assert thief.parse_uds_devices(body) == ['SEP001122334455', 'SEPAABBCCDDEEFF']


# ---------------------------------------------------------------------------
# _uds_next_link
# ---------------------------------------------------------------------------

class TestUdsNextLink:
    def test_prefers_hateoas_rel_next_link(self):
        body = '<link rel="next" href="https://cucm1:8443/cucm-uds/users?start=50"/>'
        assert thief._uds_next_link(body, 'https://cucm1:8443/cucm-uds/users', 1) == \
            'https://cucm1:8443/cucm-uds/users?start=50'

    def test_falls_back_to_next_tag(self):
        body = '<next>https://cucm1:8443/cucm-uds/users?start=50</next>'
        assert thief._uds_next_link(body, 'https://cucm1:8443/cucm-uds/users', 1) == \
            'https://cucm1:8443/cucm-uds/users?start=50'

    def test_falls_back_to_synthesized_start_param(self):
        assert thief._uds_next_link('no pagination hints here', 'https://cucm1:8443/cucm-uds/users', 33) == \
            'https://cucm1:8443/cucm-uds/users?start=33'

    def test_never_returns_none(self):
        # Documented behavior: always synthesizes a URL even on garbage input.
        assert thief._uds_next_link('', '', 0) is not None


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
        # _uds_next_link never returns None, so if the server keeps returning
        # the SAME next-link, seen_urls must break the loop rather than
        # spinning forever.
        loop_url = 'https://cucm1:8443/cucm-uds/users?start=1'
        body = f'<users><user><userName>a</userName></user><next>{loop_url}</next></users>'

        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp(body))
        pages = list(thief._iter_uds_user_pages('cucm1'))
        # base is fetched, yields <next>loop_url</next>; loop_url is fetched
        # once (still novel), yields the same <next>loop_url</next> again;
        # on the third attempt loop_url is already in seen_urls and the
        # generator stops rather than looping forever.
        assert len(pages) == 2

    def test_terminates_on_non_200_response(self, monkeypatch):
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp('error', status_code=500))
        assert list(thief._iter_uds_user_pages('cucm1')) == []

    def test_terminates_on_request_exception(self, monkeypatch):
        def raise_error(*a, **kw):
            raise thief.requests.exceptions.ConnectionError("boom")
        monkeypatch.setattr(thief.requests, 'get', raise_error)
        assert list(thief._iter_uds_user_pages('cucm1')) == []

    def test_respects_max_pages_guard(self, monkeypatch):
        # Server always returns a fresh next-link with data but no totalCount:
        # max_pages must still bound the iteration.
        calls = {'n': 0}

        def fake_get(url, **kw):
            calls['n'] += 1
            return _resp(f'<users><user><userName>u{calls["n"]}</userName></user></users>')

        monkeypatch.setattr(thief.requests, 'get', fake_get)
        pages = list(thief._iter_uds_user_pages('cucm1', max_pages=3))
        assert len(pages) == 3
