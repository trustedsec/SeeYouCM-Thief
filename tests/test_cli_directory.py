import csv
import os
import pathlib
import subprocess

_THIEF = str(pathlib.Path(__file__).resolve().parent.parent / "thief.py")


def _env():
    env = os.environ.copy()
    env["PYTEST_CURRENT_TEST"] = "1"
    return env


def test_directory_requires_host():
    result = subprocess.run(
        ["python3", "thief.py", "--directory"],
        capture_output=True, text=True, env=_env(),
    )
    assert result.returncode == 1
    assert "--directory requires -H/--host" in result.stdout


def test_directory_writes_csv_and_table_without_csv_flag(tmp_path):
    out_csv = tmp_path / "dir.csv"
    db_path = tmp_path / "d.db"
    result = subprocess.run(
        ["python3", "thief.py", "--directory", "-H", "mock-cucm",
         "--directory-outfile", str(out_csv), "--db", str(db_path)],
        capture_output=True, text=True, env=_env(),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # console table rendered
    assert "Extension" in result.stdout
    assert "testuser1" in result.stdout and "1001" in result.stdout
    # CSV written even though --csv was never passed
    assert out_csv.exists()
    with out_csv.open(newline="") as fh:
        rows = list(csv.reader(fh))
    assert rows[0][0] == "username"          # header from _DIRECTORY_CSV_COLUMNS
    assert any("testuser1" in r for r in rows[1:])
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    try:
        count = conn.execute("SELECT COUNT(*) FROM uds_directory").fetchone()[0]
    finally:
        conn.close()
    assert count >= 1


def test_directory_no_db_still_writes_csv(tmp_path):
    out_csv = tmp_path / "dir.csv"
    result = subprocess.run(
        ["python3", "thief.py", "--directory", "-H", "mock-cucm",
         "--directory-outfile", str(out_csv), "--no-db"],
        capture_output=True, text=True, env=_env(),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert out_csv.exists()
    assert "testuser1" in result.stdout


def test_userenum_writes_directory_without_csv_flag(tmp_path):
    db_path = tmp_path / "u.db"
    out_users = tmp_path / "users.txt"
    result = subprocess.run(
        ["python3", _THIEF,
         "--userenum", "-H", "mock-cucm",
         "--db", str(db_path), "--outfile", str(out_users)],
        capture_output=True, text=True, env=_env(), cwd=str(tmp_path),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # The default directory CSV is created even though --csv was not passed.
    expected = tmp_path / "cucm_directory.csv"
    assert expected.exists(), result.stdout
    assert "Directory written to" in result.stdout
