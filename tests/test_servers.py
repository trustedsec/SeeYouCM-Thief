"""Unit tests for the --servers cluster-discovery feature: get_servers_api
(thief.py) and log_cluster_servers_to_db. Previously zero coverage."""
import sqlite3
from unittest.mock import MagicMock

import pytest

from seeyoucm_thief import thief


SERVERS_XML = """<servers>
<server uri="/cucm-uds/servers/1">
<hostName>cucm-pub.example.com</hostName>
<ipv4Address>10.0.0.1</ipv4Address>
<ipv6Address></ipv6Address>
<serverType>Publisher</serverType>
</server>
<server uri="/cucm-uds/servers/2">
<hostName>cucm-sub1.example.com</hostName>
<ipv4Address>10.0.0.2</ipv4Address>
<serverType>Subscriber</serverType>
</server>
</servers>"""

SERVERS_XML_15X_PLAINTEXT = """<servers>
<server uri="/cucm-uds/servers/1">cucm-pub.example.com</server>
<server uri="/cucm-uds/servers/2">cucm-sub1.example.com</server>
</servers>"""


def _resp(text, status_code=200):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    r.content = text.encode()
    return r


class TestGetServersApi:
    def test_parses_standard_server_blocks(self, monkeypatch):
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp(SERVERS_XML))
        servers = thief.get_servers_api('cucm1')
        assert servers == [
            {'hostName': 'cucm-pub.example.com', 'ipv4Address': '10.0.0.1', 'serverType': 'Publisher'},
            {'hostName': 'cucm-sub1.example.com', 'ipv4Address': '10.0.0.2', 'serverType': 'Subscriber'},
        ]

    def test_falls_back_to_plaintext_for_15x_servers(self, monkeypatch):
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp(SERVERS_XML_15X_PLAINTEXT))
        servers = thief.get_servers_api('cucm1')
        assert servers == [
            {'hostName': 'cucm-pub.example.com'},
            {'hostName': 'cucm-sub1.example.com'},
        ]

    def test_returns_empty_list_on_non_200(self, monkeypatch):
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp('error', status_code=500))
        assert thief.get_servers_api('cucm1') == []

    def test_returns_empty_list_on_request_exception(self, monkeypatch):
        def raise_error(*a, **kw):
            raise thief.requests.exceptions.ConnectionError("boom")
        monkeypatch.setattr(thief.requests, 'get', raise_error)
        assert thief.get_servers_api('cucm1') == []

    def test_returns_empty_list_when_no_server_blocks(self, monkeypatch):
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: _resp('<servers></servers>'))
        assert thief.get_servers_api('cucm1') == []


class TestLogClusterServersToDb:
    def test_inserts_servers_with_any_identifying_field(self, db_path):
        servers = [
            {'hostName': 'cucm-pub.example.com', 'ipv4Address': '10.0.0.1', 'serverType': 'Publisher'},
            {'ipv4Address': '10.0.0.2'},
            {'ipv6Address': 'fe80::1'},
        ]
        inserted = thief.log_cluster_servers_to_db('cucm1', servers, db_file=db_path)
        assert inserted == 3

        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT hostname, ipv4, ipv6, server_type FROM cluster_servers ORDER BY id"
        ).fetchall()
        conn.close()
        assert rows == [
            ('cucm-pub.example.com', '10.0.0.1', '', 'Publisher'),
            ('', '10.0.0.2', '', ''),
            ('', '', 'fe80::1', ''),
        ]

    def test_skips_entries_with_no_identifying_field(self, db_path):
        servers = [{'serverType': 'Publisher'}]  # no hostname/ipv4/ipv6
        inserted = thief.log_cluster_servers_to_db('cucm1', servers, db_file=db_path)
        assert inserted == 0

        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM cluster_servers").fetchone()[0]
        conn.close()
        assert count == 0

    def test_ignores_duplicate_inserts(self, db_path):
        servers = [{'hostName': 'cucm-pub.example.com', 'ipv4Address': '10.0.0.1', 'serverType': 'Publisher'}]
        thief.log_cluster_servers_to_db('cucm1', servers, db_file=db_path)
        inserted_again = thief.log_cluster_servers_to_db('cucm1', servers, db_file=db_path)
        # UNIQUE constraint on the combination -> second insert is a no-op via INSERT OR IGNORE
        assert inserted_again == 0

    def test_returns_zero_on_db_error(self, tmp_path):
        missing_db = str(tmp_path / 'does-not-exist' / 'thief.db')
        result = thief.log_cluster_servers_to_db('cucm1', [{'hostName': 'x'}], db_file=missing_db)
        assert result == 0
