import os
import sqlite3
import subprocess
import pytest

TEST_DB = 'test_pytest.db'
MOCK_CONFIG = '''<device>
<sshUserId>admin</sshUserId>
<sshPassword>pass123</sshPassword>
<userId>user</userId>
<adminPassword>secret</adminPassword>
</device>'''

def setup_module(module):
    # Remove any existing test DB
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

@pytest.fixture
def patch_download(monkeypatch):
    # Patch download_config_tftp and download_config_http to return MOCK_CONFIG
    import thief
    monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: MOCK_CONFIG)
    monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: MOCK_CONFIG)

@pytest.mark.usefixtures('patch_download')
def test_db_write_and_show_db(tmp_path):
    # Run the script to scan and write to DB
    db_path = tmp_path / TEST_DB
    result = subprocess.run([
        'python3', 'thief.py', '-H', 'mock-cucm', '-p', '1.2.3.4', '--db', str(db_path)
    ], capture_output=True, text=True)
    assert result.returncode == 0
    # Now check the DB contents
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT username, password FROM credentials')
    rows = c.fetchall()
    conn.close()
    usernames = [r[0] for r in rows]
    passwords = [r[1] for r in rows]
    assert 'admin' in usernames
    assert 'pass123' in passwords
    # Check --show-db output
    show_result = subprocess.run([
        'python3', 'thief.py', '--show-db', '--db', str(db_path)
    ], capture_output=True, text=True)
    assert 'admin' in show_result.stdout
    assert 'pass123' in show_result.stdout
    assert show_result.returncode == 0
