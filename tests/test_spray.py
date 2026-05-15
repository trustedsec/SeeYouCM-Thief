"""Tests for the UDS password-spray feature."""
import os
import sqlite3
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
import requests

from seeyoucm_thief import thief


@pytest.fixture(autouse=True)
def _disable_test_mode(monkeypatch):
    """Ensure _TEST_MODE is False so the real code paths execute."""
    monkeypatch.setattr(thief, '_TEST_MODE', False)


@pytest.fixture
def db_path(tmp_path):
    """Return a path to a freshly-initialized thief.db in tmp_path."""
    p = tmp_path / "thief.db"
    thief.init_database(str(p))
    return str(p)


def _table_columns(db_path, table):
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    finally:
        conn.close()
    return {row[1] for row in rows}  # column name is index 1


def _index_exists(db_path, index_name):
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
            (index_name,),
        ).fetchone()
    finally:
        conn.close()
    return row is not None


def test_init_database_creates_uds_users_table(db_path):
    cols = _table_columns(db_path, "uds_users")
    assert {"id", "cucm_host", "username", "first_seen", "last_seen"} <= cols


def test_init_database_creates_spray_attempts_table(db_path):
    cols = _table_columns(db_path, "spray_attempts")
    assert {
        "id", "cucm_host", "username", "password",
        "status_code", "error", "attempt_time",
    } <= cols


def test_init_database_creates_spray_attempts_index(db_path):
    assert _index_exists(db_path, "idx_spray_attempts_user_time")
