import os
import sqlite3
import subprocess
import pytest
from unittest.mock import patch, MagicMock

TEST_DB = 'test_pytest.db'
MOCK_CONFIG = '''<device>\n<sshUserId>admin</sshUserId>\n<sshPassword>pass123</sshPassword>\n<userId>user</userId>\n<adminPassword>secret</adminPassword>\n</device>'''

def setup_module(module):
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

@pytest.fixture
def patch_network(monkeypatch):
    # Patch requests.get and requests.head to return mock responses
    import thief
    class MockResponse:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code
    monkeypatch.setattr('requests.get', lambda *a, **kw: MockResponse(MOCK_CONFIG, 200))
    monkeypatch.setattr('requests.head', lambda *a, **kw: MockResponse('', 200))
    # Patch config downloaders
    monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: MOCK_CONFIG)
    monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: MOCK_CONFIG)

@pytest.mark.usefixtures('patch_network')
def test_db_write_and_show_db(tmp_path):
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
