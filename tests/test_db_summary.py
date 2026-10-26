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
    thief.log_credentials_to_db(
        'cucm-b',
        [('root', 'pw2', 'SEPAABBCCDDEEFF.cnf.xml')],
        [('carol', 'SEPAABBCCDDEEFF.cnf.xml')],
        db,
    )
    thief.log_mac_prefix_to_db('cucm-a', '10.0.0.5', '001122334455', '001122334', db)
    thief.log_mac_prefix_to_db('cucm-b', '10.0.0.6', 'AABBCCDDEEFF', 'AABBCCDDE', db)
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
    # Verify the rendered row format (device padded to 20, then username)
    assert 'SEP001122334455      admin' in out
    assert 'SEPAABBCCDDEEFF      root' in out
    assert 'Total credentials discovered: 2' in out


def test_cucm_filter_limits_output(seeded_db, capsys):
    thief.display_database_summary(seeded_db, cucm_filter='cucm-a')
    out = capsys.readouterr().out
    assert 'CREDENTIALS FOUND (1 total)' in out
    assert 'CUCM Hosts:' not in out  # only printed for >1 host
    assert 'root' not in out
    # Verify that cucm-b data is filtered out
    assert 'carol' not in out  # username from cucm-b
    assert 'AABBCCDDE' not in out  # MAC prefix from cucm-b


def test_mac_prefix_stats(seeded_db, capsys):
    thief.display_database_summary(seeded_db)
    out = capsys.readouterr().out
    assert 'MAC prefixes discovered:      2' in out
    assert 'Unique MAC prefixes:          2' in out


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
    assert 'Error displaying database summary' not in out
    assert 'Total usernames discovered:   0' in out
    assert 'Total credentials discovered: 1' in out


def test_empty_initialized_db_reports_no_data(tmp_path, capsys):
    """An initialized DB with no rows should display 'No data found'."""
    db = str(tmp_path / 'empty.db')
    thief.init_database(db)
    thief.display_database_summary(db)
    out = capsys.readouterr().out
    assert 'No data found in database' in out


def test_sections_credentials_only(seeded_db, capsys):
    thief.display_database_summary(seeded_db, sections={'credentials'})
    out = capsys.readouterr().out
    assert 'CREDENTIALS FOUND (2 total)' in out
    assert 'Total credentials discovered: 2' in out
    assert 'USERNAMES FOUND' not in out
    assert 'Total usernames discovered' not in out
    assert 'MAC PREFIXES' not in out
    assert 'Total download attempts' not in out


def test_sections_usernames_only(seeded_db, capsys):
    thief.display_database_summary(seeded_db, sections={'usernames'})
    out = capsys.readouterr().out
    assert 'USERNAMES FOUND (2 total)' in out
    assert 'carol' in out
    assert 'CREDENTIALS FOUND' not in out
    assert 'pw1' not in out
    assert 'Total credentials discovered' not in out
    assert 'MAC PREFIXES' not in out


def test_sections_both_omits_recon(seeded_db, capsys):
    thief.display_database_summary(seeded_db, sections={'credentials', 'usernames'})
    out = capsys.readouterr().out
    assert 'CREDENTIALS FOUND (2 total)' in out
    assert 'USERNAMES FOUND (2 total)' in out
    assert 'MAC PREFIXES' not in out
    assert 'MAC prefixes discovered' not in out


def test_sections_credentials_includes_spray_and_verified(tmp_path, capsys):
    db = str(tmp_path / 'thief.db')
    thief.init_database(db)
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT INTO spray_attempts (cucm_host, username, password, status_code, attempt_time)"
        " VALUES ('cucm-a', 'sprayuser', 'Spring2026!', 200, '2026-10-26 12:00:00')"
    )
    conn.execute(
        "INSERT INTO verification_attempts (cucm_host, username, password, result, attempt_time)"
        " VALUES ('cucm-a', 'ccmadmin', 'Adm1n!', 'valid', '2026-10-26 12:00:00')"
    )
    conn.commit()
    conn.close()
    thief.display_database_summary(db, sections={'credentials'})
    out = capsys.readouterr().out
    assert 'sprayuser : Spring2026!' in out
    assert 'ccmadmin : Adm1n!' in out
    thief.display_database_summary(db, sections={'usernames'})
    out = capsys.readouterr().out
    assert 'No data found' in out


@pytest.mark.smoke
@pytest.mark.parametrize('flags, expect, reject', [
    (['--credentials'], 'CREDENTIALS FOUND', 'USERNAMES FOUND'),
    (['--usernames'], 'USERNAMES FOUND', 'CREDENTIALS FOUND'),
    (['--show-db', '--usernames'], 'USERNAMES FOUND', 'CREDENTIALS FOUND'),
])
def test_cli_section_flags_imply_show_db(seeded_db, capsys, monkeypatch, flags, expect, reject):
    monkeypatch.setattr('sys.argv', ['thief', *flags, '--db', seeded_db])
    with pytest.raises(SystemExit) as exc:
        thief.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert expect in out
    assert reject not in out
    assert 'MAC PREFIXES' not in out
