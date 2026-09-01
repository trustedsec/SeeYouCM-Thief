"""Tests pinning UDS parsing to the official Cisco v14 XML schemas
(UDS-xsd-14.zip, developer.cisco.com/site/user-data-services/downloads/schemas/).

The schemas are the authoritative source here — Cisco's prose docs stop at
12.5(1) and disagree with themselves in places. Element/attribute shapes
asserted below are quoted from the XSDs in the docstrings.
"""
import re
from unittest.mock import MagicMock, patch

import pytest

from seeyoucm_thief import thief


@pytest.fixture(autouse=True)
def _disable_test_mode(monkeypatch):
    monkeypatch.setattr(thief, '_TEST_MODE', False)


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.content = text.encode()
    return r


def _users_page(users, start, total, requested=None, returned=None):
    """A schema-conformant <users> page.

    users.get.xsd declares start/requestedCount/returnedCount/totalCount as
    use="required" on the <users> wrapper.
    """
    returned = len(users) if returned is None else returned
    requested = returned if requested is None else requested
    body = ''.join(
        f'<user uri="https://cucm/cucm-uds/user/{u}"><id>id-{u}</id>'
        f'<userName>{u}</userName></user>'
        for u in users
    )
    return (f'<users uri="https://cucm/cucm-uds/users" version="14.0" '
            f'start="{start}" requestedCount="{requested}" '
            f'returnedCount="{returned}" totalCount="{total}">{body}</users>')


# ---------------------------------------------------------------------------
# Pagination (#33): start is 0-based; drive paging off the wrapper attributes
# ---------------------------------------------------------------------------

def test_next_page_offset_comes_from_start_plus_returned_count():
    """A full first page of 64 must be followed by start=64, not start=65."""
    page1 = _users_page([f'u{i}' for i in range(64)], start=0, total=100)
    page2 = _users_page([f'u{i}' for i in range(64, 100)], start=64, total=100)
    urls = []

    def side_effect(url, **kwargs):
        urls.append(url)
        return _resp(page1 if len(urls) == 1 else page2)

    with patch.object(thief.requests, 'get', side_effect=side_effect):
        users = thief.get_users_api('cucm.example.com', 8443)

    assert urls[1] == 'https://cucm.example.com:8443/cucm-uds/users?start=64'
    assert len(users) == 100


def test_no_user_is_skipped_across_the_page_boundary():
    """The off-by-one in #33 silently dropped the first user of every page
    after the first.

    The fake server honours the requested ``start`` offset by slicing the
    directory, exactly as a real CUCM does. That is what makes this a real
    regression test: an off-by-one in the requested offset makes the server
    genuinely skip a user, so the assertion on the collected set fails on its
    own rather than relying on the URL assertions below.
    """
    expected = [f'user{i:03d}' for i in range(130)]
    page_size = 64
    seen = []

    def side_effect(url, **kwargs):
        seen.append(url)
        m = re.search(r'[?&]start=(\d+)', url)
        start = int(m.group(1)) if m else 0
        window = expected[start:start + page_size]
        return _resp(_users_page(window, start=start, total=len(expected),
                                 requested=page_size))

    with patch.object(thief.requests, 'get', side_effect=side_effect):
        users = thief.get_users_api('cucm.example.com', 8443)

    assert users == expected
    assert seen[1].endswith('?start=64')
    assert seen[2].endswith('?start=128')


def test_pagination_tolerates_a_server_clamping_the_page_size():
    """requestedCount > returnedCount means UserSearchLimit clamped the page.
    That is normal; paging must follow returnedCount, not requestedCount."""
    page1 = _users_page(['a', 'b'], start=0, total=4, requested=64, returned=2)
    page2 = _users_page(['c', 'd'], start=2, total=4, requested=64, returned=2)
    urls = []

    def side_effect(url, **kwargs):
        urls.append(url)
        return _resp(page1 if len(urls) == 1 else page2)

    with patch.object(thief.requests, 'get', side_effect=side_effect):
        users = thief.get_users_api('cucm.example.com', 8443)

    assert urls[1].endswith('?start=2')
    assert users == ['a', 'b', 'c', 'd']


def test_pagination_falls_back_to_collected_count_without_wrapper_attrs():
    """A non-conformant server that omits start/returnedCount still pages, and
    the fallback offset is 0-based (collected, not collected + 1)."""
    page1 = '<users totalCount="3"><user><userName>a</userName></user>' \
            '<user><userName>b</userName></user></users>'
    page2 = '<users totalCount="3"><user><userName>c</userName></user></users>'
    urls = []

    def side_effect(url, **kwargs):
        urls.append(url)
        return _resp(page1 if len(urls) == 1 else page2)

    with patch.object(thief.requests, 'get', side_effect=side_effect):
        users = thief.get_users_api('cucm.example.com', 8443)

    assert urls[1].endswith('?start=2')
    assert users == ['a', 'b', 'c']


def test_pagination_stops_when_returned_count_is_zero():
    page1 = _users_page(['a'], start=0, total=99, returned=0)
    calls = []

    def side_effect(url, **kwargs):
        calls.append(url)
        return _resp(page1)

    with patch.object(thief.requests, 'get', side_effect=side_effect):
        users = thief.get_users_api('cucm.example.com', 8443)

    assert len(calls) == 1
    assert users == ['a']


def test_uds_next_link_appends_start_to_a_bare_base():
    assert thief._uds_next_link('https://c:8443/cucm-uds/users', 64) == \
        'https://c:8443/cucm-uds/users?start=64'


def test_uds_next_link_uses_ampersand_when_query_already_present():
    assert thief._uds_next_link('https://c:8443/cucm-uds/users?max=500', 64) == \
        'https://c:8443/cucm-uds/users?max=500&start=64'


def test_parse_uds_users_wrapper_reads_all_four_required_attrs():
    w = thief._parse_uds_users_wrapper(_users_page(['a'], start=8, total=9))
    assert w == {'start': 8, 'requestedCount': 1, 'returnedCount': 1,
                 'totalCount': 9}


def test_parse_uds_users_wrapper_returns_empty_without_a_wrapper():
    assert thief._parse_uds_users_wrapper('<nope/>') == {}


# ---------------------------------------------------------------------------
# /cucm-uds/servers (#36): <server> is type="xs:string"
# ---------------------------------------------------------------------------

SERVERS_XML = (
    '<servers uri="https://cucm/cucm-uds/servers" version="14.0">'
    '<server>cucm-pub.example.com</server>'
    '<server>cucm-sub1.example.com</server>'
    '<server>10.0.0.9</server>'
    '</servers>'
)


def test_servers_parsed_as_plain_text_hostnames(monkeypatch):
    """servers.get.xsd: <xs:element type="xs:string" name="server"/> — a bare
    hostname, no child elements, on every release 10.0(1) through 14."""
    monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp(SERVERS_XML))
    servers = thief.get_servers_api('cucm', port=8443)
    assert servers == [
        {'hostName': 'cucm-pub.example.com'},
        {'hostName': 'cucm-sub1.example.com'},
        {'hostName': '10.0.0.9'},
    ]


def test_servers_parse_tolerates_pretty_printed_whitespace(monkeypatch):
    xml = ('<servers uri="https://cucm/cucm-uds/servers" version="14.0">\n'
           '   <server>\n      cucm-pub.example.com\n   </server>\n'
           '</servers>\n')
    monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp(xml))
    assert thief.get_servers_api('cucm', port=8443) == \
        [{'hostName': 'cucm-pub.example.com'}]


def test_servers_parse_skips_empty_server_elements(monkeypatch):
    xml = ('<servers uri="u" version="14.0"><server></server>'
           '<server>real.example.com</server></servers>')
    monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp(xml))
    assert thief.get_servers_api('cucm', port=8443) == \
        [{'hostName': 'real.example.com'}]


def test_servers_result_never_carries_axl_style_fields(monkeypatch):
    """hostName/ipv4Address/ipv6Address/serverType were AXL vocabulary that UDS
    never returns. Only hostName should ever be present."""
    monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp(SERVERS_XML))
    for srv in thief.get_servers_api('cucm', port=8443):
        assert set(srv) == {'hostName'}


def test_servers_empty_on_non_200(monkeypatch):
    monkeypatch.setattr(thief.requests, 'get',
                        lambda *a, **kw: _resp('<html>nope</html>', status=401))
    assert thief.get_servers_api('cucm', port=8443) == []


# ---------------------------------------------------------------------------
# /cucm-uds/version (#35, #37)
# ---------------------------------------------------------------------------

def _version_xml(auth=None, upgrading=None, schema='10.0.0', cucm='14.0.1'):
    """A schema-conformant version.get.xsd response."""
    caps = ''
    if auth is not None:
        caps += f"<usersResourceAuthEnabled>{'true' if auth else 'false'}</usersResourceAuthEnabled>"
    if upgrading is not None:
        caps += f"<upgradeInProgress>{'true' if upgrading else 'false'}</upgradeInProgress>"
    if caps:
        caps = f'<capabilities>{caps}</capabilities>'
    return (f'<versionInformation uri="https://cucm/cucm-uds/version" '
            f'version="{schema}"><version>{cucm}</version>{caps}'
            f'</versionInformation>')


def test_version_parse_has_no_prefix_key(monkeypatch):
    """version.get.xsd permits only <version> and <capabilities>; there is no
    <prefix> element on any release."""
    monkeypatch.setattr(thief.requests, 'get',
                        lambda *a, **kw: _resp(_version_xml(auth=False)))
    info = thief.get_version('cucm', port=8443)
    assert 'prefix' not in info
    assert info['version'] == '14.0.1'


def test_version_parses_schema_version_from_wrapper_attribute(monkeypatch):
    """The version= attribute is the UDS schema version and is distinct from
    the <version> element's CUCM version."""
    monkeypatch.setattr(
        thief.requests, 'get',
        lambda *a, **kw: _resp(_version_xml(auth=False, schema='10.0.0', cucm='14.0.1')))
    info = thief.get_version('cucm', port=8443)
    assert info['schemaVersion'] == '10.0.0'
    assert info['version'] == '14.0.1'


@pytest.mark.parametrize('flag', [True, False])
def test_version_parses_upgrade_in_progress(monkeypatch, flag):
    monkeypatch.setattr(thief.requests, 'get',
                        lambda *a, **kw: _resp(_version_xml(auth=False, upgrading=flag)))
    assert thief.get_version('cucm', port=8443)['upgradeInProgress'] is flag


def test_version_omits_upgrade_flag_when_capabilities_absent(monkeypatch):
    """<capabilities> is mandatory in v14 but absent before 11.5(1). A missing
    flag must stay absent rather than defaulting to a value."""
    monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp(_version_xml()))
    info = thief.get_version('cucm', port=8443)
    assert 'upgradeInProgress' not in info
    assert 'usersAuthRequired' not in info


def test_version_parses_both_capability_flags_together(monkeypatch):
    monkeypatch.setattr(
        thief.requests, 'get',
        lambda *a, **kw: _resp(_version_xml(auth=True, upgrading=True)))
    info = thief.get_version('cucm', port=8443)
    assert info['usersAuthRequired'] is True
    assert info['upgradeInProgress'] is True


# ---------------------------------------------------------------------------
# main() wiring for the upgrade warning (#37)
# ---------------------------------------------------------------------------

def test_main_warns_when_upgrade_in_progress(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(thief, 'probe_uds',
                        lambda *a, **kw: {'version': '14.0.1', 'port': 8443,
                                          'upgradeInProgress': True})
    monkeypatch.setattr(thief, 'get_users_api', lambda *a, **kw: [])
    db = tmp_path / 'thief.db'
    thief.init_database(str(db))
    monkeypatch.setattr('sys.argv',
                        ['thief', '--userenum', '-H', 'cucm', '--db', str(db)])
    with pytest.raises(SystemExit):
        thief.main()
    out = capsys.readouterr().out
    assert 'upgradeInProgress=true' in out


def test_main_silent_when_no_upgrade_in_progress(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(thief, 'probe_uds',
                        lambda *a, **kw: {'version': '14.0.1', 'port': 8443,
                                          'upgradeInProgress': False})
    monkeypatch.setattr(thief, 'get_users_api', lambda *a, **kw: [])
    db = tmp_path / 'thief.db'
    thief.init_database(str(db))
    monkeypatch.setattr('sys.argv',
                        ['thief', '--userenum', '-H', 'cucm', '--db', str(db)])
    with pytest.raises(SystemExit):
        thief.main()
    assert 'upgradeInProgress' not in capsys.readouterr().out


def test_main_reports_uds_schema_version(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(thief, 'probe_uds',
                        lambda *a, **kw: {'version': '14.0.1', 'port': 8443,
                                          'schemaVersion': '10.0.0'})
    monkeypatch.setattr(thief, 'get_users_api', lambda *a, **kw: [])
    db = tmp_path / 'thief.db'
    thief.init_database(str(db))
    monkeypatch.setattr('sys.argv',
                        ['thief', '--userenum', '-H', 'cucm', '--db', str(db)])
    with pytest.raises(SystemExit):
        thief.main()
    assert 'UDS schema 10.0.0' in capsys.readouterr().out


# ---------------------------------------------------------------------------
# parse_uds_directory: elements may legally carry attributes
# ---------------------------------------------------------------------------

def test_directory_uri_parsed_when_exist_attribute_present():
    """users.get.xsd gives <directoryUri> an optional exist="true|false"
    attribute. A bare-tag regex silently yielded '' whenever CUCM set it,
    dropping the SIP/Jabber URI from every harvested record."""
    xml = ('<users uri="u" version="14.0" start="0" requestedCount="1" '
           'returnedCount="1" totalCount="1">'
           '<user uri="https://cucm/cucm-uds/user/alice">'
           '<id>uuid-alice</id><userName>alice</userName>'
           '<directoryUri exist="true">alice@corp.example</directoryUri>'
           '</user></users>')
    records = thief.parse_uds_directory(xml)
    assert records[0]['directory_uri'] == 'alice@corp.example'


def test_directory_uri_still_parsed_without_attributes():
    xml = ('<users uri="u" version="14.0" start="0" requestedCount="1" '
           'returnedCount="1" totalCount="1"><user><userName>bob</userName>'
           '<directoryUri>bob@corp.example</directoryUri></user></users>')
    assert thief.parse_uds_directory(xml)[0]['directory_uri'] == 'bob@corp.example'


def test_directory_user_id_not_confused_by_a_longer_tag():
    """The <id> pattern must not match a tag that merely starts with "id"."""
    xml = ('<users uri="u" version="14.0" start="0" requestedCount="1" '
           'returnedCount="1" totalCount="1"><user>'
           '<identityHint>not-the-id</identityHint>'
           '<userName>carol</userName><id>uuid-carol</id>'
           '</user></users>')
    assert thief.parse_uds_directory(xml)[0]['user_id'] == 'uuid-carol'
