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


class TestExtractConfigsFilter:
    def test_skips_failures_null_and_empty_content(self, tmp_path):
        db_path = tmp_path / 'thief.db'
        out_dir = tmp_path / 'configs'
        _make_db_with_rows(db_path, [
            # Should be written
            {'cucm_host': '10.0.1.5', 'filename': 'KEEP1.cnf.xml',
             'success': 1, 'content': '<xml>keep</xml>'},
            # success=0 — must be skipped even if content is present
            {'cucm_host': '10.0.1.5', 'filename': 'FAIL.cnf.xml',
             'success': 0, 'content': '<xml>should-not-write</xml>'},
            # content is NULL — must be skipped
            {'cucm_host': '10.0.1.5', 'filename': 'NULL.cnf.xml',
             'success': 1, 'content': None},
            # content is empty string — must be skipped
            {'cucm_host': '10.0.1.5', 'filename': 'EMPTY.cnf.xml',
             'success': 1, 'content': ''},
        ])

        written, skipped, errors = thief.extract_configs_from_db(
            str(db_path), str(out_dir)
        )

        assert written == 1
        assert skipped == 0
        assert errors == 0
        assert (out_dir / '10.0.1.5' / 'KEEP1.cnf.xml').exists()
        assert not (out_dir / '10.0.1.5' / 'FAIL.cnf.xml').exists()
        assert not (out_dir / '10.0.1.5' / 'NULL.cnf.xml').exists()
        assert not (out_dir / '10.0.1.5' / 'EMPTY.cnf.xml').exists()


class TestExtractConfigsSkipExisting:
    def test_existing_file_is_left_untouched(self, tmp_path):
        db_path = tmp_path / 'thief.db'
        out_dir = tmp_path / 'configs'
        _make_db_with_rows(db_path, [
            {'cucm_host': '10.0.1.5', 'filename': 'SEP1.cnf.xml',
             'success': 1, 'content': '<xml>from-db</xml>'},
        ])
        # Pre-create the target file with different content.
        target = out_dir / '10.0.1.5' / 'SEP1.cnf.xml'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('manually-edited')

        written, skipped, errors = thief.extract_configs_from_db(
            str(db_path), str(out_dir)
        )

        assert written == 0
        assert skipped == 1
        assert errors == 0
        # The manually-edited content must NOT be overwritten.
        assert target.read_text() == 'manually-edited'


class TestExtractConfigsPathTraversal:
    def test_malicious_filename_is_rejected(self, tmp_path):
        db_path = tmp_path / 'thief.db'
        out_dir = tmp_path / 'configs'
        outside = tmp_path / 'evil.txt'

        _make_db_with_rows(db_path, [
            # filename contains traversal — must be rejected.
            {'cucm_host': '10.0.1.5',
             'filename': '../evil.txt',
             'success': 1, 'content': 'pwned'},
            # cucm_host contains traversal — must be rejected.
            {'cucm_host': '../../etc',
             'filename': 'passwd',
             'success': 1, 'content': 'pwned'},
            # One clean row to ensure the loop continues after rejects.
            {'cucm_host': '10.0.1.5', 'filename': 'OK.cnf.xml',
             'success': 1, 'content': '<xml>ok</xml>'},
        ])

        written, skipped, errors = thief.extract_configs_from_db(
            str(db_path), str(out_dir)
        )

        assert written == 1
        assert skipped == 0
        assert errors == 2
        # The clean row was written.
        assert (out_dir / '10.0.1.5' / 'OK.cnf.xml').exists()
        # Nothing escaped output_dir.
        assert not outside.exists()
        assert not (tmp_path / 'evil.txt').exists()
