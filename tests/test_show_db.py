import os
import sqlite3
import subprocess
import pytest

TEST_DB = 'test_pytest.db'

@pytest.fixture(scope='module')
def setup_test_db():
    # Remove any existing test DB
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    # Create DB and all required tables
    conn = sqlite3.connect(TEST_DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cucm_host TEXT NOT NULL,
        device TEXT NOT NULL,
        username TEXT,
        password TEXT,
        discovery_time TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS usernames (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cucm_host TEXT NOT NULL,
        device TEXT NOT NULL,
        username TEXT NOT NULL,
        discovery_time TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS mac_prefixes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cucm_host TEXT NOT NULL,
        phone_ip TEXT NOT NULL,
        full_mac TEXT NOT NULL,
        partial_mac TEXT NOT NULL,
        discovery_time TEXT NOT NULL,
        UNIQUE(cucm_host, full_mac)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS download_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cucm_host TEXT NOT NULL,
        filename TEXT NOT NULL,
        attempt_time TEXT NOT NULL,
        success INTEGER NOT NULL,
        method TEXT,
        content TEXT,
        UNIQUE(cucm_host, filename)
    )''')
    # Insert mock credentials
    c.executemany('''INSERT INTO credentials (cucm_host, device, username, password, discovery_time) VALUES (?, ?, ?, ?, ?)''', [
        ('mock-cucm', 'SEP001122334455', 'admin', 'pass123', '2026-01-29 12:00:00'),
        ('mock-cucm', 'SEP001122334456', 'user', 'secret', '2026-01-29 12:01:00'),
    ])
    conn.commit()
    conn.close()
    yield TEST_DB
    # Teardown
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

def test_credentials_query(setup_test_db):
    conn = sqlite3.connect(setup_test_db)
    c = conn.cursor()
    c.execute('SELECT * FROM credentials LIMIT 5;')
    rows = c.fetchall()
    conn.close()
    assert len(rows) == 2
    assert rows[0][2] == 'SEP001122334455'
    assert rows[1][3] == 'user'

def test_show_db_output(setup_test_db):
    # Run the script with --show-db and the test DB
    result = subprocess.run([
        'python3', 'thief.py', '--show-db', '--db', setup_test_db
    ], capture_output=True, text=True)
    # Output should mention the mock credentials
    assert 'SEP001122334455' in result.stdout
    assert 'admin' in result.stdout
    assert 'pass123' in result.stdout
    assert result.returncode == 0
