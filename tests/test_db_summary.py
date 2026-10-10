import sqlite3

import pytest

from seeyoucm_thief import thief


@pytest.fixture
def seeded_db(tmp_path):
    db = str(tmp_path / 'thief.db')
    thief.init_database(db)
    thief.log_credentials_to_db(
        'cucm-a',
        [('admin', 'pw1', 'SEP001122334455.cnf.xml')],
        [('bob', 'SEP001122334455.cnf.xml')],
        db,
    )
    thief.log_credentials_to_db('cucm-b', [('root', 'pw2', 'SEPAABBCCDDEEFF.cnf.xml')], [], db)
    thief.log_mac_prefix_to_db('cucm-a', '10.0.0.5', '001122334455', '001122334', db)
    return db


def test_missing_db_prints_hint(tmp_path, capsys):
    thief.display_database_summary(str(tmp_path / 'nope.db'))
    out = capsys.readouterr().out
    assert 'Database not found' in out


def test_credentials_section_lists_all_hosts(seeded_db, capsys):
    thief.display_database_summary(seeded_db)
    out = capsys.readouterr().out
    assert 'CREDENTIALS FOUND (2 total)' in out
    assert 'CUCM Hosts: cucm-a, cucm-b' in out
    assert 'admin' in out and 'root' in out
    assert 'Total credentials discovered: 2' in out


def test_cucm_filter_limits_output(seeded_db, capsys):
    thief.display_database_summary(seeded_db, cucm_filter='cucm-a')
    out = capsys.readouterr().out
    assert 'CREDENTIALS FOUND (1 total)' in out
    assert 'CUCM Hosts:' not in out  # only printed for >1 host
    assert 'root' not in out


def test_mac_prefix_stats(seeded_db, capsys):
    thief.display_database_summary(seeded_db)
    out = capsys.readouterr().out
    assert 'MAC prefixes discovered:      1' in out
    assert 'Unique MAC prefixes:          1' in out


def test_legacy_db_with_only_credentials_table(tmp_path, capsys):
    """A DB from an old version, with every optional table missing, must still render."""
    db = str(tmp_path / 'old.db')
    conn = sqlite3.connect(db)
    conn.execute('CREATE TABLE credentials (cucm_host TEXT, device TEXT, username TEXT, '
                 'password TEXT, discovery_time TEXT)')
    conn.execute("INSERT INTO credentials VALUES ('c', 'SEP1', 'u', 'p', '2026-01-01')")
    conn.commit()
    conn.close()
    thief.display_database_summary(db)
    out = capsys.readouterr().out
    assert 'Database error' not in out
    assert 'Total usernames discovered:   0' in out
    assert 'Total credentials discovered: 1' in out
