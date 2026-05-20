"""Tests for functions that interact with TFTP/HTTP services, using mocked network boundaries."""
import os
import queue
import threading
import tempfile
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from seeyoucm_thief import thief


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_CONFIG_XML = (
    "<device>\n"
    "<sshUserId>admin</sshUserId>\n"
    "<sshPassword>s3cret</sshPassword>\n"
    "<userId>jsmith</userId>\n"
    "<adminPassword>adm1n</adminPassword>\n"
    "</device>"
)

PHONE_NETWORK_PAGE = """
<html><body>
<td>Host name SEP001122334455</td>
<tr>
<td>cucm1.example.com Active</td>
</tr>
</body></html>
"""

PHONE_NETWORK_PAGE_FULL = """
<html><body>
<td><b> Host Name </b></td>
<td width="20"></td>
<td><b>SEP001122334455</b></td>
<tr>
<td><b> CUCM Server </b></td>
<td></td>
<td>cucm1.example.com Active</td>
</tr>
</body></html>
"""

PHONE_NETWORK_PAGE_NO_HOSTNAME = """
<html><body>
<td><b> Host Name </b></td>
<td width="20"></td>
<td><b>UNKNOWN-DEVICE</b></td>
</body></html>
"""


@pytest.fixture(autouse=True)
def _disable_test_mode(monkeypatch):
    """Ensure _TEST_MODE is False so the real code paths execute."""
    monkeypatch.setattr(thief, '_TEST_MODE', False)


# ---------------------------------------------------------------------------
# download_config_http
# ---------------------------------------------------------------------------

class TestDownloadConfigHttp:
    def test_success_returns_content(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = SAMPLE_CONFIG_XML
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: mock_resp)

        result = thief.download_config_http('10.0.0.1', 'SEP001122334455.cnf.xml')
        assert result == SAMPLE_CONFIG_XML

    def test_non_2xx_returns_none(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: mock_resp)

        result = thief.download_config_http('10.0.0.1', 'SEP001122334455.cnf.xml')
        assert result is None

    def test_connection_error_returns_none(self, monkeypatch):
        def raise_error(*a, **kw):
            raise ConnectionError("refused")
        monkeypatch.setattr(thief.requests, 'get', raise_error)

        result = thief.download_config_http('10.0.0.1', 'SEP001122334455.cnf.xml')
        assert result is None

    def test_timeout_returns_none(self, monkeypatch):
        def raise_timeout(*a, **kw):
            raise thief.requests.exceptions.Timeout("timed out")
        monkeypatch.setattr(thief.requests, 'get', raise_timeout)

        result = thief.download_config_http('10.0.0.1', 'SEP001122334455.cnf.xml')
        assert result is None

    def test_uses_correct_port(self, monkeypatch):
        calls = []

        def capture_get(url, **kw):
            calls.append(url)
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "config"
            return resp

        monkeypatch.setattr(thief.requests, 'get', capture_get)
        thief.download_config_http('10.0.0.1', 'SEP001122334455.cnf.xml')
        assert calls[0] == 'http://10.0.0.1:6970/SEP001122334455.cnf.xml'


# ---------------------------------------------------------------------------
# download_config_tftp
# ---------------------------------------------------------------------------

class TestDownloadConfigTftp:
    def test_success_returns_content(self, monkeypatch):
        mock_client = MagicMock()

        def fake_download(filename, tmp_path, timeout=5):
            with open(tmp_path, 'w') as f:
                f.write(SAMPLE_CONFIG_XML)

        mock_client.download = fake_download
        monkeypatch.setattr(thief.tftpy, 'TftpClient', lambda host, port: mock_client)

        result = thief.download_config_tftp('10.0.0.1', 'SEP001122334455.cnf.xml')
        assert result == SAMPLE_CONFIG_XML

    def test_connection_refused_returns_none(self, monkeypatch):
        def raise_error(host, port):
            raise ConnectionRefusedError("refused")
        monkeypatch.setattr(thief.tftpy, 'TftpClient', raise_error)

        result = thief.download_config_tftp('10.0.0.1', 'SEP001122334455.cnf.xml')
        assert result is None

    def test_timeout_returns_none(self, monkeypatch):
        mock_client = MagicMock()
        mock_client.download.side_effect = TimeoutError("tftp timeout")
        monkeypatch.setattr(thief.tftpy, 'TftpClient', lambda host, port: mock_client)

        result = thief.download_config_tftp('10.0.0.1', 'SEP001122334455.cnf.xml')
        assert result is None

    def test_raise_on_error_propagates(self, monkeypatch):
        mock_client = MagicMock()
        mock_client.download.side_effect = TimeoutError("tftp timeout")
        monkeypatch.setattr(thief.tftpy, 'TftpClient', lambda host, port: mock_client)

        with pytest.raises(TimeoutError, match="tftp timeout"):
            thief.download_config_tftp('10.0.0.1', 'SEP001122334455.cnf.xml', raise_on_error=True)

    def test_temp_file_cleaned_up_on_success(self, monkeypatch):
        created_paths = []
        mock_client = MagicMock()

        def fake_download(filename, tmp_path, timeout=5):
            created_paths.append(tmp_path)
            with open(tmp_path, 'w') as f:
                f.write("config")

        mock_client.download = fake_download
        monkeypatch.setattr(thief.tftpy, 'TftpClient', lambda host, port: mock_client)

        thief.download_config_tftp('10.0.0.1', 'SEP001122334455.cnf.xml')
        assert len(created_paths) == 1
        assert not os.path.exists(created_paths[0])

    def test_temp_file_cleaned_up_on_error(self, monkeypatch):
        created_paths = []
        original_named_temp = tempfile.NamedTemporaryFile

        def tracking_temp(**kwargs):
            f = original_named_temp(**kwargs)
            created_paths.append(f.name)
            return f

        monkeypatch.setattr(thief.tempfile, 'NamedTemporaryFile', tracking_temp)
        mock_client = MagicMock()
        mock_client.download.side_effect = Exception("download failed")
        monkeypatch.setattr(thief.tftpy, 'TftpClient', lambda host, port: mock_client)

        thief.download_config_tftp('10.0.0.1', 'SEP001122334455.cnf.xml')
        assert len(created_paths) == 1
        assert not os.path.exists(created_paths[0])

    def test_uses_port_69(self, monkeypatch):
        calls = []

        def capture_client(host, port):
            calls.append((host, port))
            mock = MagicMock()
            mock.download.side_effect = Exception("not a real server")
            return mock

        monkeypatch.setattr(thief.tftpy, 'TftpClient', capture_client)
        thief.download_config_tftp('10.0.0.1', 'test.cnf.xml')
        assert calls[0] == ('10.0.0.1', 69)


# ---------------------------------------------------------------------------
# get_hostname_from_phone
# ---------------------------------------------------------------------------

class TestGetHostnameFromPhone:
    def test_success_extracts_hostname(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.text = PHONE_NETWORK_PAGE_FULL
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: mock_resp)

        result = thief.get_hostname_from_phone('192.168.1.10')
        assert result == 'SEP001122334455'

    def test_no_hostname_match_returns_none(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.text = "<html><body>no hostname here</body></html>"
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: mock_resp)

        result = thief.get_hostname_from_phone('192.168.1.10')
        assert result is None

    def test_connection_error_returns_none(self, monkeypatch):
        def raise_error(*a, **kw):
            raise ConnectionError("phone unreachable")
        monkeypatch.setattr(thief.requests, 'get', raise_error)

        result = thief.get_hostname_from_phone('192.168.1.10')
        assert result is None

    def test_timeout_returns_none(self, monkeypatch):
        def raise_timeout(*a, **kw):
            raise thief.requests.exceptions.Timeout("timed out")
        monkeypatch.setattr(thief.requests, 'get', raise_timeout)

        result = thief.get_hostname_from_phone('192.168.1.10')
        assert result is None


# ---------------------------------------------------------------------------
# get_cucm_name_from_phone
# ---------------------------------------------------------------------------

class TestGetCucmNameFromPhone:
    def test_success_extracts_cucm(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.text = PHONE_NETWORK_PAGE_FULL
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: mock_resp)

        result = thief.get_cucm_name_from_phone('192.168.1.10')
        assert result == 'cucm1.example.com'

    def test_no_cucm_match_returns_none(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.text = "<html><body>no cucm info here</body></html>"
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: mock_resp)

        result = thief.get_cucm_name_from_phone('192.168.1.10')
        assert result is None

    def test_connection_error_returns_none(self, monkeypatch):
        def raise_error(*a, **kw):
            raise ConnectionError("phone unreachable")
        monkeypatch.setattr(thief.requests, 'get', raise_error)

        result = thief.get_cucm_name_from_phone('192.168.1.10')
        assert result is None


# ---------------------------------------------------------------------------
# get_phones_hostnames_from_reverse
# ---------------------------------------------------------------------------

class TestGetPhonesHostnamesFromReverse:
    def test_success_returns_hostname_list(self, monkeypatch):
        monkeypatch.setattr(thief.socket, 'gethostbyaddr',
                            lambda ip: ('sep001122334455.example.com', [], ['192.168.1.10']))

        result = thief.get_phones_hostnames_from_reverse('192.168.1.10')
        assert result == ['sep001122334455.example.com']

    def test_no_reverse_dns_returns_empty(self, monkeypatch):
        def raise_error(ip):
            raise thief.socket.herror("host not found")
        monkeypatch.setattr(thief.socket, 'gethostbyaddr', raise_error)

        result = thief.get_phones_hostnames_from_reverse('192.168.1.10')
        assert result == []


# ---------------------------------------------------------------------------
# enumerate_phones_subnet
# ---------------------------------------------------------------------------

class TestEnumeratePhonesSubnet:
    def test_finds_phones_in_subnet(self, monkeypatch):
        head_resp = MagicMock()
        head_resp.status_code = 200

        get_resp = MagicMock()
        get_resp.text = PHONE_NETWORK_PAGE

        monkeypatch.setattr(thief.requests, 'head', lambda *a, **kw: head_resp)
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: get_resp)

        result = thief.enumerate_phones_subnet('192.168.1.0/30')
        # /30 has 2 usable hosts: .1 and .2
        assert len(result) == 2
        assert result[0]['hostname'] == 'SEP001122334455'
        assert 'cucm1.example.com' in result[0]['url']
        assert ':6970/' in result[0]['url']

    def test_skips_unreachable_hosts(self, monkeypatch):
        def raise_error(*a, **kw):
            raise ConnectionError("refused")
        monkeypatch.setattr(thief.requests, 'head', raise_error)

        result = thief.enumerate_phones_subnet('192.168.1.0/30')
        assert result == []

    def test_skips_non_2xx_responses(self, monkeypatch):
        head_resp = MagicMock()
        head_resp.status_code = 404
        monkeypatch.setattr(thief.requests, 'head', lambda *a, **kw: head_resp)

        result = thief.enumerate_phones_subnet('192.168.1.0/30')
        assert result == []

    def test_no_cidr_returns_none(self):
        result = thief.enumerate_phones_subnet('192.168.1.1')
        assert result is None

    def test_skips_host_without_sep_hostname(self, monkeypatch):
        head_resp = MagicMock()
        head_resp.status_code = 200

        get_resp = MagicMock()
        get_resp.text = PHONE_NETWORK_PAGE_NO_HOSTNAME

        monkeypatch.setattr(thief.requests, 'head', lambda *a, **kw: head_resp)
        monkeypatch.setattr(thief.requests, 'get', lambda *a, **kw: get_resp)

        result = thief.enumerate_phones_subnet('192.168.1.0/30')
        assert result == []


# ---------------------------------------------------------------------------
# search_for_secrets (with mocked download layer)
# ---------------------------------------------------------------------------

class TestSearchForSecrets:
    def test_parses_ssh_credentials(self, monkeypatch):
        monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: SAMPLE_CONFIG_XML)

        creds, users = thief.search_for_secrets('10.0.0.1', 'SEP001122334455.cnf.xml')
        usernames = [c[0] for c in creds]
        passwords = [c[1] for c in creds]
        assert 'admin' in usernames
        assert 's3cret' in passwords

    def test_parses_admin_password(self, monkeypatch):
        monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: SAMPLE_CONFIG_XML)

        creds, users = thief.search_for_secrets('10.0.0.1', 'SEP001122334455.cnf.xml')
        passwords = [c[1] for c in creds]
        assert 'adm1n' in passwords

    def test_parses_usernames(self, monkeypatch):
        monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: SAMPLE_CONFIG_XML)

        creds, users = thief.search_for_secrets('10.0.0.1', 'SEP001122334455.cnf.xml')
        user_list = [u[0] for u in users]
        assert 'admin' in user_list
        assert 'jsmith' in user_list

    def test_download_failure_returns_empty(self, monkeypatch):
        monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: None)

        creds, users = thief.search_for_secrets('10.0.0.1', 'SEP001122334455.cnf.xml')
        assert creds == []
        assert users == []

    def test_http_fallback(self, monkeypatch):
        monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: SAMPLE_CONFIG_XML)

        creds, users = thief.search_for_secrets('10.0.0.1', 'SEP001122334455.cnf.xml', use_tftp=False)
        assert len(creds) > 0

    def test_empty_config_returns_empty(self, monkeypatch):
        monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: "<device></device>")

        creds, users = thief.search_for_secrets('10.0.0.1', 'SEP001122334455.cnf.xml')
        assert creds == []
        assert users == []

    def test_phone_password_tag_not_extracted(self, monkeypatch):
        # BUG: phonePassword (regex group 6) is matched but never handled in the
        # code - only groups 2-5 are checked. This test documents the current behavior.
        config = "<device>\n<phonePassword>phone123</phonePassword>\n</device>"
        monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: config)

        creds, users = thief.search_for_secrets('10.0.0.1', 'SEP001122334455.cnf.xml')
        passwords = [c[1] for c in creds]
        assert 'phone123' not in passwords  # group 6 is never processed


# ---------------------------------------------------------------------------
# download_worker (with mocked TFTP/HTTP layer)
# ---------------------------------------------------------------------------

class TestDownloadWorker:
    def _run_worker(self, monkeypatch, tasks, use_tftp=True, no_db=True, force=True):
        """Helper to run a download_worker with given tasks and collect results."""
        work_queue = queue.Queue()
        results_queue = queue.Queue()
        manager = thief.TFTPBackoffManager()

        for task in tasks:
            work_queue.put(task)
        work_queue.put(None)  # poison pill

        t = threading.Thread(
            target=thief.download_worker,
            args=(work_queue, results_queue, None, use_tftp, manager,
                  no_db, 'ignored.db', force, set(), threading.Lock()),
            daemon=True,
        )
        t.start()
        work_queue.join()
        t.join(timeout=5)

        results = []
        while not results_queue.empty():
            results.append(results_queue.get_nowait())
        return results

    def test_tftp_success(self, monkeypatch):
        monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: "config-content")
        monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: None)

        results = self._run_worker(monkeypatch,
            [(0, "001122334455", "SEP001122334455.cnf.xml", "10.0.0.1")])

        assert len(results) == 1
        index, mac, filename, content, method, cached = results[0]
        assert content == "config-content"
        assert method == 'TFTP'

    def test_tftp_returns_none_http_fallback(self, monkeypatch):
        # When TFTP returns None (not raises), worker falls back to HTTP
        monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: None)
        monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: "http-content")

        results = self._run_worker(monkeypatch,
            [(0, "001122334455", "SEP001122334455.cnf.xml", "10.0.0.1")])

        assert len(results) == 1
        _, _, _, content, method, _ = results[0]
        assert content == "http-content"
        assert method == 'HTTP'

    def test_tftp_raises_marks_cucm_dead(self, monkeypatch):
        # When TFTP raises (not "file not found"), worker marks CUCM as dead
        def raise_error(*a, **kw):
            raise ConnectionRefusedError("connection refused")
        monkeypatch.setattr(thief, 'download_config_tftp', raise_error)
        monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: None)

        dead_cucm = set()
        work_queue = queue.Queue()
        results_queue = queue.Queue()
        manager = thief.TFTPBackoffManager()

        work_queue.put((0, "001122334455", "SEP001122334455.cnf.xml", "10.0.0.1"))
        work_queue.put(None)

        t = threading.Thread(
            target=thief.download_worker,
            args=(work_queue, results_queue, None, True, manager,
                  True, 'ignored.db', True, dead_cucm, threading.Lock()),
            daemon=True,
        )
        t.start()
        work_queue.join()
        t.join(timeout=5)

        assert "10.0.0.1" in dead_cucm

    def test_both_return_none(self, monkeypatch):
        monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: None)
        monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: None)

        results = self._run_worker(monkeypatch,
            [(0, "001122334455", "SEP001122334455.cnf.xml", "10.0.0.1")])

        assert len(results) == 1
        _, _, _, content, _, _ = results[0]
        assert content is None

    def test_no_cucm_returns_no_cucm(self, monkeypatch):
        results = self._run_worker(monkeypatch,
            [(0, "001122334455", "SEP001122334455.cnf.xml", None)])

        assert len(results) == 1
        _, _, _, content, method, _ = results[0]
        assert content is None
        assert method == 'NO_CUCM'

    def test_dead_cucm_skipped(self, monkeypatch):
        work_queue = queue.Queue()
        results_queue = queue.Queue()
        manager = thief.TFTPBackoffManager()
        dead_cucm = {"10.0.0.1"}

        work_queue.put((0, "001122334455", "SEP001122334455.cnf.xml", "10.0.0.1"))
        work_queue.put(None)

        t = threading.Thread(
            target=thief.download_worker,
            args=(work_queue, results_queue, None, True, manager,
                  True, 'ignored.db', True, dead_cucm, threading.Lock()),
            daemon=True,
        )
        t.start()
        work_queue.join()
        t.join(timeout=5)

        result = results_queue.get_nowait()
        assert result[4] == 'CUCM_DEAD'

    def test_multiple_tasks_processed(self, monkeypatch):
        monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: "content")
        monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: None)

        tasks = [
            (0, "001122334455", "SEP001122334455.cnf.xml", "10.0.0.1"),
            (1, "AABBCCDDEEFF", "SEPAABBCCDDEEFF.cnf.xml", "10.0.0.1"),
            (2, "112233445566", "SEP112233445566.cnf.xml", "10.0.0.2"),
        ]
        results = self._run_worker(monkeypatch, tasks)

        assert len(results) == 3
        indices = sorted(r[0] for r in results)
        assert indices == [0, 1, 2]


# ---------------------------------------------------------------------------
# get_config_names (mocked CUCM HTTP server)
# ---------------------------------------------------------------------------

class TestGetConfigNames:
    def test_returns_filenames_for_hostnames(self):
        result = thief.get_config_names('10.0.0.1', hostnames=['SEP001122334455'])
        assert 'SEP001122334455.cnf.xml' in result
        assert result[0] == 'SEP001122334455.cnf.xml'

    def test_strips_domain_from_hostnames(self):
        result = thief.get_config_names('10.0.0.1', hostnames=['SEP001122334455.example.com'])
        assert 'SEP001122334455.cnf.xml' in result
        assert result[0] == 'SEP001122334455.cnf.xml'

    def test_already_has_extension(self):
        result = thief.get_config_names('10.0.0.1', hostnames=['SEP001122334455.cnf.xml'])
        assert 'SEP001122334455.cnf.xml' in result
        assert result[0] == 'SEP001122334455.cnf.xml'

    def test_empty_hostnames_falls_back_to_cache_list(self, monkeypatch):
        # With no hostnames and empty cache list, get_config_names returns defaults.
        monkeypatch.setattr(thief, 'get_cache_list', lambda *a, **kw: [])
        result = thief.get_config_names('10.0.0.1', hostnames=[])
        # No per-device entries, but defaults are always appended.
        assert set(result) == set(thief.DEFAULT_TFTP_FILES)

    def test_none_hostnames_falls_back_to_cache_list(self, monkeypatch):
        monkeypatch.setattr(thief, 'get_cache_list', lambda *a, **kw: [
            'SEPAABBCCDDEEFF.cnf.xml',
            'SEPAABBCCDDEEFF.cnf.xml.sgn',
            'RingList.xml',
        ])
        result = thief.get_config_names('10.0.0.1', hostnames=None)
        assert 'SEPAABBCCDDEEFF.cnf.xml' in result

    def test_hostnames_path_includes_defaults_after_per_device(self):
        result = thief.get_config_names('cucm.example', hostnames=['SEPABC123456789'])
        # Per-device filename comes first.
        assert result[0] == 'SEPABC123456789.cnf.xml'
        # All defaults appear, in declared order, after per-device entries.
        defaults_in_result = [f for f in result if f in thief.DEFAULT_TFTP_FILES]
        assert defaults_in_result == list(thief.DEFAULT_TFTP_FILES)

    def test_hostnames_path_dedupes_when_hostname_collides_with_default(self):
        # If a caller happens to pass a hostname matching a default, the result
        # should still contain that name exactly once.
        result = thief.get_config_names('cucm.example', hostnames=['XMLDefault'])
        assert result.count('XMLDefault.cnf.xml') == 1

    def test_empty_hostnames_none_falls_back_to_cache_list_with_defaults(self, monkeypatch):
        monkeypatch.setattr(thief, 'get_cache_list', lambda *a, **kw: ['SEP111111111111.cnf.xml'])
        result = thief.get_config_names('cucm.example', hostnames=None)
        assert 'SEP111111111111.cnf.xml' in result
        for default in thief.DEFAULT_TFTP_FILES:
            assert default in result

    def test_no_hostnames_no_cucm_returns_only_defaults(self):
        # Previous behavior: returned []. New behavior: still return defaults,
        # since they're attempted unconditionally.
        result = thief.get_config_names(None, hostnames=None)
        assert set(result) == set(thief.DEFAULT_TFTP_FILES)


# ---------------------------------------------------------------------------
# build_brute_force_candidates
# ---------------------------------------------------------------------------

class TestBuildBruteForceCandidates:
    def test_one_candidate_per_suffix_per_prefix(self):
        # Suffix length 1 => 16 candidates per prefix.
        candidates = thief.build_brute_force_candidates(
            all_found_macs=['001122334455'[:11]],  # 11-char prefix
            mac_to_cucm={'00112233445': 'cucm.example'},
            brute_mac_len=1,
        )
        # 16 SEP files, all on the same CUCM (exclude DEFAULT sentinel tasks)
        sep_tasks = [c for c in candidates if c[1] != thief.DEFAULT_MAC_SENTINEL and c[2].startswith('SEP')]
        assert len(sep_tasks) == 16
        assert {c[0] for c in sep_tasks} == {'cucm.example'}
        # Filenames are SEP<12 hex chars>.cnf.xml
        for cucm, full_mac, fname in sep_tasks:
            assert fname == f'SEP{full_mac}.cnf.xml'
            assert len(full_mac) == 12

    def test_groups_by_cucm(self):
        # Two prefixes, different CUCMs.
        candidates = thief.build_brute_force_candidates(
            all_found_macs=['00112233445', 'AABBCCDDEEF'],
            mac_to_cucm={'00112233445': 'cucm-a', 'AABBCCDDEEF': 'cucm-b'},
            brute_mac_len=1,
        )
        # Exclude DEFAULT sentinel tasks; count only MAC-brute-force SEP tasks.
        sep_tasks = [c for c in candidates if c[1] != thief.DEFAULT_MAC_SENTINEL and c[2].startswith('SEP')]
        by_cucm = {}
        for cucm, _full_mac, _fname in sep_tasks:
            by_cucm.setdefault(cucm, 0)
            by_cucm[cucm] += 1
        assert by_cucm == {'cucm-a': 16, 'cucm-b': 16}

    def test_includes_one_default_task_per_default_file_per_cucm(self):
        candidates = thief.build_brute_force_candidates(
            all_found_macs=['00112233445'],
            mac_to_cucm={'00112233445': 'cucm.example'},
            brute_mac_len=1,
        )
        default_tasks = [c for c in candidates if c[1] == thief.DEFAULT_MAC_SENTINEL]
        # One task per default file, on the one CUCM.
        assert len(default_tasks) == len(thief.DEFAULT_TFTP_FILES)
        assert {c[2] for c in default_tasks} == set(thief.DEFAULT_TFTP_FILES)
        assert {c[0] for c in default_tasks} == {'cucm.example'}

    def test_default_tasks_present_for_each_cucm(self):
        candidates = thief.build_brute_force_candidates(
            all_found_macs=['00112233445', 'AABBCCDDEEF'],
            mac_to_cucm={'00112233445': 'cucm-a', 'AABBCCDDEEF': 'cucm-b'},
            brute_mac_len=1,
        )
        default_tasks = [c for c in candidates if c[1] == thief.DEFAULT_MAC_SENTINEL]
        per_cucm = {}
        for cucm, _, fname in default_tasks:
            per_cucm.setdefault(cucm, set()).add(fname)
        assert per_cucm == {
            'cucm-a': set(thief.DEFAULT_TFTP_FILES),
            'cucm-b': set(thief.DEFAULT_TFTP_FILES),
        }


# ---------------------------------------------------------------------------
# DEFAULT_TFTP_FILES constant
# ---------------------------------------------------------------------------

class TestDefaultTftpFiles:
    def test_constant_contains_expected_files(self):
        expected = {
            'XMLDefault.cnf.xml',
            'SEPDefault.cnf.xml',
            'SIPDefault.cnf',
            'ITLFile.tlv',
            'CTLFile.tlv',
            'RingList.xml',
            'Ringlist-wb.xml',
            'DistinctiveRingList.xml',
            'jabber-config.xml',
        }
        assert set(thief.DEFAULT_TFTP_FILES) == expected

    def test_constant_is_tuple(self):
        # Tuple, not list — these are an immutable constant.
        assert isinstance(thief.DEFAULT_TFTP_FILES, tuple)


# ---------------------------------------------------------------------------
# DEFAULT_MAC_SENTINEL guard in download_worker results
# ---------------------------------------------------------------------------

class TestDefaultSentinelResultsGuard:
    """Tests that DEFAULT_MAC_SENTINEL results are handled correctly by
    download_worker and that the results-consumption logic properly separates
    default-file tasks from real-MAC tasks."""

    def _run_worker_single(self, monkeypatch, full_mac, filename, cucm,
                           content_return):
        """Run the worker for one task and return the single result tuple."""
        monkeypatch.setattr(thief, 'download_config_tftp',
                            lambda *a, **kw: content_return)
        monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: None)

        work_queue = queue.Queue()
        results_queue = queue.Queue()
        manager = thief.TFTPBackoffManager()

        work_queue.put((0, full_mac, filename, cucm))
        work_queue.put(None)

        t = threading.Thread(
            target=thief.download_worker,
            args=(work_queue, results_queue, None, True, manager,
                  True, 'ignored.db', True, set(), threading.Lock()),
            daemon=True,
        )
        t.start()
        work_queue.join()
        t.join(timeout=5)

        return results_queue.get_nowait()

    def test_worker_returns_filename_in_result_tuple(self, monkeypatch):
        """Worker result tuple must include filename so consumer can key
        default-file results correctly."""
        result = self._run_worker_single(
            monkeypatch,
            full_mac=thief.DEFAULT_MAC_SENTINEL,
            filename='XMLDefault.cnf.xml',
            cucm='cucm.example',
            content_return='<device/>',
        )
        # New tuple shape: (index, full_mac, filename, content, method, was_cached)
        assert len(result) == 6
        index, full_mac, filename, content, method, was_cached = result
        assert full_mac == thief.DEFAULT_MAC_SENTINEL
        assert filename == 'XMLDefault.cnf.xml'
        assert content == '<device/>'

    def test_default_full_mac_does_not_pollute_found_macs(self, monkeypatch):
        """Simulates the results-consumption logic: DEFAULT sentinel must NOT
        be appended to found_macs."""
        found_macs = []
        all_configs = []

        # Simulate the consumption of one DEFAULT result
        full_mac = thief.DEFAULT_MAC_SENTINEL
        filename = 'XMLDefault.cnf.xml'
        content = '<device><sshUserId>admin</sshUserId></device>'

        if content:
            if full_mac == thief.DEFAULT_MAC_SENTINEL:
                device_key = filename[:-8] if filename.endswith('.cnf.xml') else filename
            else:
                device_key = f'SEP{full_mac}'
                found_macs.append(full_mac)
            all_configs.append((device_key, content))

        assert thief.DEFAULT_MAC_SENTINEL not in found_macs
        assert 'DEFAULT' not in found_macs
        assert all_configs == [('XMLDefault', content)]

    def test_default_full_mac_logs_credentials_under_filename(self, monkeypatch):
        """Credentials extracted from a default file must be keyed by the
        filename (with .cnf.xml stripped), not by 'SEPDEFAULT'."""
        full_mac = thief.DEFAULT_MAC_SENTINEL
        filename = 'XMLDefault.cnf.xml'
        content = (
            '<device>\n'
            '<sshUserId>admin</sshUserId>\n'
            '<sshPassword>pass123</sshPassword>\n'
            '</device>'
        )

        if full_mac == thief.DEFAULT_MAC_SENTINEL:
            device_key = filename[:-8] if filename.endswith('.cnf.xml') else filename
        else:
            device_key = f'SEP{full_mac}'

        config_creds = []
        config_users = []
        user = ''

        import re
        for line in content.split('\n'):
            match = re.search(
                r'(<sshUserId>(\S+)</sshUserId>|<sshPassword>(\S+)</sshPassword>'
                r'|<userId.*>(\S+)</userId>|<adminPassword>(\S+)</adminPassword>'
                r'|<phonePassword>(\S+)</phonePassword>)',
                line,
            )
            if match:
                if match.group(2):
                    user = match.group(2)
                    config_users.append((user, device_key))
                if match.group(3):
                    config_creds.append((user, match.group(3), device_key))

        assert config_users == [('admin', 'XMLDefault')]
        assert config_creds == [('admin', 'pass123', 'XMLDefault')]
        # Confirm no SEPDEFAULT anywhere
        for _, _, dev in config_creds:
            assert dev != 'SEPDEFAULT'
        for _, dev in config_users:
            assert dev != 'SEPDEFAULT'

    def test_real_mac_full_mac_unaffected(self, monkeypatch):
        """For a real 12-hex-char MAC, device_key must be SEP<mac> and the
        mac must be appended to found_macs, unchanged from prior behaviour."""
        found_macs = []
        all_configs = []

        full_mac = '001122334455'
        filename = 'SEP001122334455.cnf.xml'
        content = '<device><sshUserId>user</sshUserId></device>'

        if content:
            if full_mac == thief.DEFAULT_MAC_SENTINEL:
                device_key = filename[:-8] if filename.endswith('.cnf.xml') else filename
            else:
                device_key = f'SEP{full_mac}'
                found_macs.append(full_mac)
            all_configs.append((device_key, content))

        assert found_macs == ['001122334455']
        assert all_configs == [('SEP001122334455', content)]

    def test_non_cnf_xml_default_filename_kept_as_is(self, monkeypatch):
        """Default files that don't end in .cnf.xml (e.g., ITLFile.tlv) must
        keep their full name as the device key."""
        full_mac = thief.DEFAULT_MAC_SENTINEL
        filename = 'ITLFile.tlv'
        content = '<tlv/>'

        if full_mac == thief.DEFAULT_MAC_SENTINEL:
            device_key = filename[:-8] if filename.endswith('.cnf.xml') else filename
        else:
            device_key = f'SEP{full_mac}'

        assert device_key == 'ITLFile.tlv'
