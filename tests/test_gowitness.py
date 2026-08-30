"""Unit tests for get_phones_from_gowitness: extracts Cisco phone IPs from a
gowitness screenshot-recon SQLite database. Previously zero coverage -
foreign-schema parser, exactly the kind of thing that breaks silently."""
import sqlite3

from seeyoucm_thief import thief


def _make_gowitness_db(path, rows):
    """rows: list of (url, title) tuples."""
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE results (id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
    conn.executemany("INSERT INTO results (url, title) VALUES (?, ?)", rows)
    conn.commit()
    conn.close()


def test_extracts_ips_from_cisco_titled_entries(tmp_path):
    db = tmp_path / "gowitness.sqlite3"
    _make_gowitness_db(db, [
        ("https://10.0.0.5:443/", "Cisco CP-8845"),
        ("https://10.0.0.6:443/", "Cisco CP-7841"),
        ("https://10.0.0.7:443/", "Some Other Device"),
    ])
    phones = thief.get_phones_from_gowitness(str(db))
    assert phones == ["10.0.0.5", "10.0.0.6"]


def test_returns_empty_list_when_no_cisco_titles_match(tmp_path):
    db = tmp_path / "gowitness.sqlite3"
    _make_gowitness_db(db, [("https://10.0.0.5:443/", "Not a match")])
    assert thief.get_phones_from_gowitness(str(db)) == []


def test_returns_empty_list_for_missing_file(tmp_path):
    missing = tmp_path / "nope.sqlite3"
    assert thief.get_phones_from_gowitness(str(missing)) == []


def test_returns_empty_list_when_results_table_missing(tmp_path):
    db = tmp_path / "empty.sqlite3"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE unrelated (id INTEGER)")
    conn.commit()
    conn.close()
    assert thief.get_phones_from_gowitness(str(db)) == []


def test_returns_empty_list_for_non_sqlite_file(tmp_path):
    not_a_db = tmp_path / "notadb.sqlite3"
    not_a_db.write_text("this is not a sqlite database")
    assert thief.get_phones_from_gowitness(str(not_a_db)) == []


def test_deduplicates_and_sorts_ips(tmp_path):
    db = tmp_path / "gowitness.sqlite3"
    _make_gowitness_db(db, [
        ("https://10.0.0.9:443/", "Cisco CP-8845"),
        ("https://10.0.0.9:443/", "Cisco CP-8845 (retry)"),
        ("https://10.0.0.2:443/", "Cisco CP-7841"),
    ])
    phones = thief.get_phones_from_gowitness(str(db))
    assert phones == ["10.0.0.2", "10.0.0.9"]
