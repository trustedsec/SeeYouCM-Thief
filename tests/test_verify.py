import sqlite3
import sys
import queue as _queue
import threading as _threading

import pytest

import thief


def test_init_database_creates_verification_attempts(tmp_path):
    db = str(tmp_path / "t.db")
    thief.init_database(db)
    conn = sqlite3.connect(db)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(verification_attempts)")]
    conn.close()
    assert cols == [
        "id", "cucm_host", "username", "password",
        "result", "status_code", "error", "attempt_time",
    ]
