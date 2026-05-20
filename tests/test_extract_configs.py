import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

import thief


def _make_db_with_rows(db_path, rows):
    """Create a thief-schema DB at db_path and insert the given rows.

    rows is a list of dicts with keys: cucm_host, filename, success,
    content (any of which may be omitted to use defaults).
    """
    thief.init_database(str(db_path))
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    for row in rows:
        cursor.execute(
            '''INSERT OR REPLACE INTO download_attempts
               (cucm_host, filename, attempt_time, success, method, content)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (
                row.get('cucm_host', '10.0.0.1'),
                row.get('filename', 'SEP000000000001.cnf.xml'),
                '2026-05-20 12:00:00',
                row.get('success', 1),
                row.get('method', 'TFTP'),
                row.get('content', '<xml>ok</xml>'),
            ),
        )
    conn.commit()
    conn.close()


class TestExtractConfigsHappyPath:
    def test_writes_files_under_per_cucm_subdirs(self, tmp_path):
        db_path = tmp_path / 'thief.db'
        out_dir = tmp_path / 'configs'
        _make_db_with_rows(db_path, [
            {'cucm_host': '10.0.1.5', 'filename': 'SEPAABBCC112233.cnf.xml',
             'success': 1, 'content': '<xml>device-a</xml>'},
            {'cucm_host': '10.0.1.5', 'filename': 'XMLDefault.cnf.xml',
             'success': 1, 'content': '<xml>default-a</xml>'},
            {'cucm_host': '10.0.1.6', 'filename': 'SEPAABBCC445566.cnf.xml',
             'success': 1, 'content': '<xml>device-b</xml>'},
        ])

        written, skipped, errors = thief.extract_configs_from_db(
            str(db_path), str(out_dir)
        )

        assert written == 3
        assert skipped == 0
        assert errors == 0

        assert (out_dir / '10.0.1.5' / 'SEPAABBCC112233.cnf.xml').read_text() == '<xml>device-a</xml>'
        assert (out_dir / '10.0.1.5' / 'XMLDefault.cnf.xml').read_text() == '<xml>default-a</xml>'
        assert (out_dir / '10.0.1.6' / 'SEPAABBCC445566.cnf.xml').read_text() == '<xml>device-b</xml>'
