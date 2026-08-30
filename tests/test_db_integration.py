import os
import sqlite3
import subprocess
import pytest

pytestmark = pytest.mark.e2e

TEST_DB = 'test_pytest.db'
MOCK_CONFIG = '''<device>
<sshUserId>admin</sshUserId>
<sshPassword>pass123</sshPassword>
<userId>user</userId>
<adminPassword>secret</adminPassword>
</device>'''

@pytest.fixture
def patch_download(monkeypatch):
    # Patch download_config_tftp and download_config_http to return MOCK_CONFIG
    import thief
    monkeypatch.setattr(thief, 'download_config_tftp', lambda *a, **kw: MOCK_CONFIG)
    monkeypatch.setattr(thief, 'download_config_http', lambda *a, **kw: MOCK_CONFIG)

@pytest.mark.usefixtures('patch_download')
def test_db_write_and_show_db(tmp_path, thief_script):
    db_path = str(tmp_path / TEST_DB)
    env = os.environ.copy()
    env["PYTEST_CURRENT_TEST"] = "1"
    result = subprocess.run([
        'python3', thief_script, '-H', 'mock-cucm', '-p', '1.2.3.4', '--db', db_path
    ], capture_output=True, text=True, env=env)
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
        'python3', thief_script, '--show-db', '--db', db_path
    ], capture_output=True, text=True, env=env)
    assert 'admin' in show_result.stdout
    assert 'pass123' in show_result.stdout
    assert show_result.returncode == 0
