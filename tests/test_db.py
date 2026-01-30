import os
import sqlite3
import pytest
from unittest import mock

import thief

def test_init_database(tmp_path):
    db_path = tmp_path / "test_thief.db"
    # Should create the DB and all tables
    thief.init_database(str(db_path))
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Check tables exist
    for table in ["download_attempts", "credentials", "usernames", "mac_prefixes", "phone_cucm"]:
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
        assert cursor.fetchone() is not None
    conn.close()

def test_log_download_and_credentials(tmp_path):
    db_path = tmp_path / "test_thief.db"
    thief.init_database(str(db_path))
    cucm_host = "1.2.3.4"
    filename = "SEP001122334455.cnf.xml"
    # Log a download attempt
    thief.log_download_attempt(cucm_host, filename, True, "TFTP", "config-contents", str(db_path))
    # Check download_attempts table
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cucm_host, filename, success, content FROM download_attempts")
    row = cursor.fetchone()
    assert row[0] == cucm_host
    assert row[1] == filename
    assert row[2] == 1
    assert row[3] == "config-contents"
    # Log credentials
    credentials = [("user1", "pass1", "device1")]
    usernames = [("user2", "device2")]
    thief.log_credentials_to_db(cucm_host, credentials, usernames, str(db_path))
    cursor.execute("SELECT cucm_host, device, username, password FROM credentials")
    cred_row = cursor.fetchone()
    assert cred_row[0] == cucm_host
    assert cred_row[1] == "device1"
    assert cred_row[2] == "user1"
    assert cred_row[3] == "pass1"
    cursor.execute("SELECT cucm_host, device, username FROM usernames")
    user_row = cursor.fetchone()
    assert user_row[0] == cucm_host
    assert user_row[1] == "device2"
    assert user_row[2] == "user2"
    conn.close()
