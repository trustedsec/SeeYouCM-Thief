"""Tests for the CSV export helpers: export_to_csv, export_directory_to_csv,
and _directory_csv_name. Previously only covered indirectly via one
subprocess e2e test."""
import csv

from seeyoucm_thief import thief


# ---------------------------------------------------------------------------
# _directory_csv_name
# ---------------------------------------------------------------------------

class TestDirectoryCsvName:
    def test_inserts_directory_before_extension(self):
        assert thief._directory_csv_name('cucm_users.csv') == 'cucm_users-directory.csv'

    def test_appends_when_no_extension(self):
        assert thief._directory_csv_name('cucm_users') == 'cucm_users-directory'

    def test_handles_multiple_dots(self):
        assert thief._directory_csv_name('archive.tar.csv') == 'archive.tar-directory.csv'


# ---------------------------------------------------------------------------
# export_directory_to_csv
# ---------------------------------------------------------------------------

class TestExportDirectoryToCsv:
    def test_header_matches_column_contract(self, tmp_path):
        out = tmp_path / 'dir.csv'
        thief.export_directory_to_csv([], str(out))
        with out.open(newline='') as f:
            rows = list(csv.reader(f))
        assert tuple(rows[0]) == thief._DIRECTORY_CSV_COLUMNS

    def test_one_row_per_record_missing_fields_blank(self, tmp_path):
        out = tmp_path / 'dir.csv'
        records = [{'username': 'alice', 'email': 'alice@example.com'}]
        thief.export_directory_to_csv(records, str(out))
        with out.open(newline='') as f:
            rows = list(csv.reader(f))
        assert len(rows) == 2
        row = dict(zip(thief._DIRECTORY_CSV_COLUMNS, rows[1]))
        assert row['username'] == 'alice'
        assert row['email'] == 'alice@example.com'
        assert row['first_name'] == ''


# ---------------------------------------------------------------------------
# export_to_csv
# ---------------------------------------------------------------------------

class TestExportToCsv:
    def test_header_row(self, tmp_path):
        out = tmp_path / 'out.csv'
        assert thief.export_to_csv([], [], str(out)) is True
        with out.open(newline='') as f:
            rows = list(csv.reader(f))
        assert rows[0] == ['Timestamp', 'Type', 'Device', 'Username', 'Password']

    def test_strips_cnf_xml_suffix_from_device_name(self, tmp_path):
        out = tmp_path / 'out.csv'
        credentials = [('admin', 'pw123', 'SEP001122334455.cnf.xml')]
        thief.export_to_csv(credentials, [], str(out))
        with out.open(newline='') as f:
            rows = list(csv.reader(f))
        assert rows[1][2] == 'SEP001122334455'

    def test_non_cnf_xml_device_name_is_untouched(self, tmp_path):
        out = tmp_path / 'out.csv'
        credentials = [('admin', 'pw123', 'ITLFile.tlv')]
        thief.export_to_csv(credentials, [], str(out))
        with out.open(newline='') as f:
            rows = list(csv.reader(f))
        assert rows[1][2] == 'ITLFile.tlv'

    def test_credential_without_username_becomes_na(self, tmp_path):
        out = tmp_path / 'out.csv'
        credentials = [('', 'pw123', 'SEP1.cnf.xml')]
        thief.export_to_csv(credentials, [], str(out))
        with out.open(newline='') as f:
            rows = list(csv.reader(f))
        assert rows[1][3] == 'N/A'

    def test_username_row_suppressed_when_already_a_credential(self, tmp_path):
        out = tmp_path / 'out.csv'
        credentials = [('alice', 'pw123', 'SEP1.cnf.xml')]
        usernames = [('alice', 'SEP1.cnf.xml')]
        thief.export_to_csv(credentials, usernames, str(out))
        with out.open(newline='') as f:
            rows = list(csv.reader(f))
        # Only the Credential row for alice/SEP1 -- no duplicate Username row.
        assert len(rows) == 2
        assert rows[1][1] == 'Credential'

    def test_username_row_kept_when_device_differs_from_credential(self, tmp_path):
        out = tmp_path / 'out.csv'
        credentials = [('alice', 'pw123', 'SEP1.cnf.xml')]
        usernames = [('alice', 'SEP2.cnf.xml')]
        thief.export_to_csv(credentials, usernames, str(out))
        with out.open(newline='') as f:
            rows = list(csv.reader(f))
        types = [r[1] for r in rows[1:]]
        assert types.count('Credential') == 1
        assert types.count('Username') == 1

    def test_username_only_row_reports_na_password(self, tmp_path):
        out = tmp_path / 'out.csv'
        thief.export_to_csv([], [('bob', 'SEP2.cnf.xml')], str(out))
        with out.open(newline='') as f:
            rows = list(csv.reader(f))
        assert rows[1] == [rows[1][0], 'Username', 'SEP2', 'bob', 'N/A']

    def test_returns_false_on_permission_error(self, tmp_path, monkeypatch):
        def raise_permission_error(*a, **kw):
            raise PermissionError("denied")
        monkeypatch.setattr('builtins.open', raise_permission_error)
        assert thief.export_to_csv([], [], str(tmp_path / 'out.csv')) is False
