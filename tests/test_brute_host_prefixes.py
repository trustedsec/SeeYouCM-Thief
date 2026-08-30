import sqlite3

import pytest

import thief


def _db(tmp_path):
    db_file = str(tmp_path / 'thief.db')
    thief.init_database(db_file)
    return db_file


def test_uds_device_macs_scoped_to_host(tmp_path):
    db_file = _db(tmp_path)
    thief.log_uds_device('cucm1', 'alice', 'SEPAABBCCDDEEFF', 'userenum', db_file)
    thief.log_uds_device('cucm2', 'bob', 'SEP112233445566', 'userenum', db_file)

    assert thief.get_uds_device_macs_from_db('cucm1', db_file) == [
        ('AABBCCDDEEFF', 'cucm1')
    ]
    assert thief.get_uds_device_macs_from_db('cucm3', db_file) == []


def test_uds_device_macs_ignores_non_sep_names(tmp_path):
    db_file = _db(tmp_path)
    thief.log_uds_device('cucm1', 'alice', 'CSFALICE', 'userenum', db_file)
    assert thief.get_uds_device_macs_from_db('cucm1', db_file) == []


def test_uds_device_macs_missing_table(tmp_path):
    db_file = str(tmp_path / 'empty.db')
    sqlite3.connect(db_file).close()
    assert thief.get_uds_device_macs_from_db('cucm1', db_file) == []


@pytest.mark.e2e
def test_brute_mac_accepts_host_without_phone(tmp_path, thief_script):
    import os
    import subprocess

    db_file = str(tmp_path / 'thief.db')
    thief.init_database(db_file)
    thief.log_uds_device('cucm1', 'alice', 'SEPAABBCCDDEEFF', 'userenum', db_file)

    env = os.environ.copy()
    env['PYTEST_CURRENT_TEST'] = '1'
    result = subprocess.run(
        ['python3', thief_script, '-b', '1', '-H', 'cucm1', '--db', db_file],
        capture_output=True, text=True, env=env, timeout=300,
    )
    assert 'You must specify at least one phone' not in result.stdout
    assert 'MAC brute force mode enabled using 1 MAC prefix' in result.stdout
