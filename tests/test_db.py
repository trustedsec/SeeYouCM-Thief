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

def test_get_mac_prefixes_from_db(tmp_path):
    db_path = tmp_path / "test_thief.db"
    thief.init_database(str(db_path))
    # Two prefixes with CUCM hosts, plus one row with no CUCM that must be dropped.
    thief.log_mac_prefix_to_db("10.0.0.1", "192.168.1.10", "AABBCCDDEE01", "AABBCCDDE", str(db_path))
    thief.log_mac_prefix_to_db("10.0.0.2", "192.168.1.11", "112233445566", "112233445", str(db_path))
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT OR IGNORE INTO mac_prefixes (cucm_host, phone_ip, full_mac, partial_mac, discovery_time)"
        " VALUES ('', '192.168.1.12', 'FFEEDDCCBBAA', 'FFEEDDCCB', '2024-01-01 00:00:00')"
    )
    conn.commit()
    conn.close()

    rows = thief.get_mac_prefixes_from_db(str(db_path))
    assert ("AABBCCDDEE01", "10.0.0.1") in rows
    assert ("112233445566", "10.0.0.2") in rows
    # Row without a CUCM host is excluded
    assert all(cucm for _, cucm in rows)
    assert len(rows) == 2

def test_get_mac_prefixes_from_db_missing_table(tmp_path):
    # An empty/blank DB file with no tables returns [] rather than raising.
    db_path = tmp_path / "empty.db"
    sqlite3.connect(db_path).close()
    assert thief.get_mac_prefixes_from_db(str(db_path)) == []
