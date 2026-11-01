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
        with patch.object(thief.requests, 'get', return_value=_resp(_policy_body(500))) as get:
            assert thief.get_uds_search_limit('cucm.example.com', 8443) == 500
        assert get.call_args[0][0] == 'https://cucm.example.com:8443/cucm-uds/options/userPolicy'

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
