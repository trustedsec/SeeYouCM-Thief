import os
import sqlite3
import pytest
import thief

def test_log_uds_usernames_to_db(tmp_path):
    db_path = tmp_path / "test_thief.db"
    thief.init_database(str(db_path))
    cucm_host = "1.2.3.4"
    usernames = ["alice", "bob"]
    # Log UDS usernames
    result = thief.log_uds_usernames_to_db(cucm_host, usernames, str(db_path))
    assert result is True
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cucm_host, device, username FROM usernames WHERE device = 'UDS_API'")
    rows = cursor.fetchall()
    assert len(rows) == 2
    assert set(r[2] for r in rows) == {"alice", "bob"}
    # Always dump DB for verification
    dump_db(str(db_path))
    conn.close()

def dump_db(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    print("\n--- DATABASE DUMP ---")
    for table in ["download_attempts", "credentials", "usernames", "mac_prefixes"]:
        print(f"\nTable: {table}")
        try:
            cursor.execute(f"SELECT * FROM {table}")
            rows = cursor.fetchall()
            for row in rows:
                print(row)
        except Exception as e:
            print(f"Error reading {table}: {e}")
    conn.close()

def test_log_mac_prefix_to_db(tmp_path):
    db_path = tmp_path / "test_thief.db"
    thief.init_database(str(db_path))
    cucm_host = "1.2.3.4"
    phone_ip = "10.0.0.1"
    full_mac = "AABBCCDDEEFF"
    partial_mac = "AABBCCDDE"
    # Log MAC prefix
    result = thief.log_mac_prefix_to_db(cucm_host, phone_ip, full_mac, partial_mac, str(db_path))
    assert result is True
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cucm_host, phone_ip, full_mac, partial_mac FROM mac_prefixes")
    row = cursor.fetchone()
    assert row[0] == cucm_host
    assert row[1] == phone_ip
    assert row[2] == full_mac
    assert row[3] == partial_mac


def test_log_phone_cucm_to_db(tmp_path):
    db_path = tmp_path / 'test.db'
    thief.init_database(str(db_path))
    cucm_host = "1.2.3.4"
    phone_ip = "10.0.0.5"
    assert thief.log_phone_cucm_to_db(cucm_host, phone_ip, str(db_path)) is True

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cucm_host, phone_ip FROM phone_cucm")
    row = cursor.fetchone()
    conn.close()
    assert row[0] == cucm_host
    assert row[1] == phone_ip
    # Always dump DB for verification
    dump_db(str(db_path))
    conn.close()

def test_check_already_attempted(tmp_path):
    db_path = tmp_path / "test_thief.db"
    thief.init_database(str(db_path))
    cucm_host = "1.2.3.4"
    filename = "SEP001122334455.cnf.xml"
    # Should not exist yet
    attempted, successful, content = thief.check_already_attempted(cucm_host, filename, str(db_path))
    assert attempted is False
    # Log a failed attempt
    thief.log_download_attempt(cucm_host, filename, False, "TFTP", None, str(db_path))
    attempted, successful, content = thief.check_already_attempted(cucm_host, filename, str(db_path))
    assert attempted is True
    assert successful is False
    assert content is None
    # Log a successful attempt
    thief.log_download_attempt(cucm_host, filename, True, "TFTP", "config-contents", str(db_path))
    attempted, successful, content = thief.check_already_attempted(cucm_host, filename, str(db_path))
    assert attempted is True
    assert successful is True
    assert content == "config-contents"
    # Always dump DB for verification
    dump_db(str(db_path))
