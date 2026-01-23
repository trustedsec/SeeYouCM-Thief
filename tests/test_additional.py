#!/usr/bin/env python3
"""
Additional test suggestions for thief.py functionality
"""
import pytest
import sqlite3
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from thief import (
    export_to_csv, 
    init_database,
    check_already_attempted,
    log_download_attempt,
    log_credentials_to_db,
    get_phones_from_gowitness,
    brute_force_mac_configs,
    download_config_tftp,
    download_config_http,
    search_for_secrets
)


class TestDatabaseFunctions:
    """Test database initialization and operations"""
    
    def test_init_database_creates_tables(self):
        """Test that database initialization creates all required tables"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_file = tmp.name
        
        try:
            init_database(db_file)
            
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Check download_attempts table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='download_attempts'")
            assert cursor.fetchone() is not None
            
            # Check credentials table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'")
            assert cursor.fetchone() is not None
            
            # Check usernames table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usernames'")
            assert cursor.fetchone() is not None
            
            conn.close()
        finally:
            os.unlink(db_file)
    
    def test_log_download_attempt(self):
        """Test logging download attempts to database"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_file = tmp.name
        
        try:
            init_database(db_file)
            log_download_attempt('10.10.10.1', 'SEP001122334455.cnf.xml', True, 'TFTP', db_file)
            
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM download_attempts WHERE filename=?', ('SEP001122334455.cnf.xml',))
            result = cursor.fetchone()
            conn.close()
            
            assert result is not None
            assert result[1] == '10.10.10.1'  # cucm_host
            assert result[2] == 'SEP001122334455.cnf.xml'  # filename
            assert result[4] == 1  # success
            assert result[5] == 'TFTP'  # method
        finally:
            os.unlink(db_file)
    
    def test_check_already_attempted(self):
        """Test checking if file was previously attempted"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_file = tmp.name
        
        try:
            init_database(db_file)
            
            # Should return (False, False) for new file
            attempted, successful = check_already_attempted('10.10.10.1', 'SEP001122334455.cnf.xml', db_file)
            assert attempted == False
            
            # Log an attempt
            log_download_attempt('10.10.10.1', 'SEP001122334455.cnf.xml', True, 'HTTP', db_file)
            
            # Should now return (True, True)
            attempted, successful = check_already_attempted('10.10.10.1', 'SEP001122334455.cnf.xml', db_file)
            assert attempted == True
            assert successful == True
        finally:
            os.unlink(db_file)
    
    def test_log_credentials_to_db(self):
        """Test logging discovered credentials"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_file = tmp.name
        
        try:
            init_database(db_file)
            
            credentials = [
                ('admin', 'password123', 'SEP001122334455'),
                (None, 'secret456', 'SEP001122334455')
            ]
            usernames = [
                ('testuser', 'SEP001122334456')
            ]
            
            log_credentials_to_db('10.10.10.1', credentials, usernames, db_file)
            
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Check credentials
            cursor.execute('SELECT * FROM credentials')
            creds = cursor.fetchall()
            assert len(creds) == 2
            
            # Check usernames
            cursor.execute('SELECT * FROM usernames')
            users = cursor.fetchall()
            assert len(users) == 1
            
            conn.close()
        finally:
            os.unlink(db_file)


class TestCSVExport:
    """Test CSV export functionality"""
    
    def test_export_to_csv_creates_file(self):
        """Test that CSV export creates file with correct structure"""
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as tmp:
            csv_file = tmp.name
        
        try:
            credentials = [
                ('admin', 'password123', 'SEP001122334455'),
                ('user1', 'secret456', 'SEP001122334456')
            ]
            usernames = [
                ('testuser', 'SEP001122334457')
            ]
            
            result = export_to_csv(credentials, usernames, csv_file)
            assert result == True
            
            # Verify file exists and has content
            with open(csv_file, 'r') as f:
                lines = f.readlines()
                assert len(lines) > 0
                assert 'Timestamp,Type,Device,Username,Password' in lines[0]
                assert len(lines) == 4  # header + 2 creds + 1 username
        finally:
            os.unlink(csv_file)
    
    def test_export_to_csv_handles_permission_error(self):
        """Test CSV export handles permission errors gracefully"""
        # Try to write to a read-only location
        result = export_to_csv([], [], '/root/no-permission/test.csv')
        assert result == False


class TestGoWitnessIntegration:
    """Test gowitness database integration"""
    
    def test_get_phones_from_gowitness_valid_db(self):
        """Test extracting phones from valid gowitness database"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_file = tmp.name
        
        try:
            # Create mock gowitness database
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE results (
                    id INTEGER PRIMARY KEY,
                    url TEXT,
                    title TEXT
                )
            ''')
            cursor.execute("INSERT INTO results (url, title) VALUES ('http://10.10.10.1:80/', 'Cisco CP-8841')")
            cursor.execute("INSERT INTO results (url, title) VALUES ('http://10.10.10.2:80/', 'Cisco CP-7841')")
            cursor.execute("INSERT INTO results (url, title) VALUES ('http://10.10.10.3:80/', 'Some Other Device')")
            conn.commit()
            conn.close()
            
            phones = get_phones_from_gowitness(db_file)
            
            assert len(phones) == 2
            assert '10.10.10.1' in phones
            assert '10.10.10.2' in phones
        finally:
            os.unlink(db_file)
    
    def test_get_phones_from_gowitness_missing_file(self):
        """Test handling of missing gowitness database"""
        phones = get_phones_from_gowitness('/nonexistent/path/db.sqlite3')
        assert phones == []
    
    def test_get_phones_from_gowitness_invalid_db(self):
        """Test handling of invalid database structure"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_file = tmp.name
        
        try:
            # Create database without results table
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute('CREATE TABLE dummy (id INTEGER)')
            conn.commit()
            conn.close()
            
            phones = get_phones_from_gowitness(db_file)
            assert phones == []
        finally:
            os.unlink(db_file)


class TestMACBruteForce:
    """Test MAC address brute forcing functionality"""
    
    @patch('thief.download_config_http')
    @patch('thief.download_config_tftp')
    def test_brute_force_mac_with_valid_partial(self, mock_tftp, mock_http):
        """Test brute forcing with valid partial MAC"""
        # Mock successful downloads for specific MACs
        def http_side_effect(host, filename):
            if 'SEPA4B239B6CE00' in filename or 'SEPA4B239B6CEFF' in filename:
                return '<xml>config content</xml>'
            return None
        
        mock_http.side_effect = http_side_effect
        mock_tftp.return_value = None
        
        # Note: This will still try 256 iterations but we're just testing the logic
        # In real tests, you'd want to mock the loop or test smaller ranges
        configs = brute_force_mac_configs('10.10.10.1', 'A4B239B6CE', use_tftp=False)
        
        # Should find at least the mocked configs
        assert isinstance(configs, list)
    
    def test_brute_force_mac_short_partial(self):
        """Test that short partial MAC is rejected"""
        configs = brute_force_mac_configs('10.10.10.1', 'A4B2', use_tftp=False)
        assert configs == []


class TestConfigDownload:
    """Test configuration file download methods"""
    
    @patch('thief.requests.get')
    def test_download_config_http_success(self, mock_get):
        """Test successful HTTP download"""
        mock_response = Mock()
        mock_response.text = '<xml>test config</xml>'
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        content = download_config_http('10.10.10.1', 'SEP001122334455.cnf.xml')
        assert content == '<xml>test config</xml>'
    
    @patch('thief.requests.get')
    def test_download_config_http_failure(self, mock_get):
        """Test failed HTTP download"""
        mock_get.side_effect = Exception('Connection error')
        
        content = download_config_http('10.10.10.1', 'SEP001122334455.cnf.xml')
        assert content is None
    
    @patch('thief.tftpy.TftpClient')
    def test_download_config_tftp_success(self, mock_tftp_client):
        """Test successful TFTP download"""
        # Mock TFTP client download
        mock_client_instance = Mock()
        mock_tftp_client.return_value = mock_client_instance
        
        # This is tricky to test due to file operations
        # In real implementation, you'd mock tempfile and file operations
        pass  # Placeholder for full implementation
    
    @patch('thief.tftpy.TftpClient')
    def test_download_config_tftp_not_found(self, mock_tftp_client):
        """Test TFTP download with file not found"""
        mock_client_instance = Mock()
        mock_client_instance.download.side_effect = Exception('File not found')
        mock_tftp_client.return_value = mock_client_instance
        
        content = download_config_tftp('10.10.10.1', 'SEP001122334455.cnf.xml')
        assert content is None


class TestCredentialExtraction:
    """Test credential extraction from config files"""
    
    @patch('thief.download_config_http')
    def test_search_for_secrets_finds_credentials(self, mock_http):
        """Test that credentials are properly extracted from config"""
        config_xml = '''
        <xml>
            <sshUserId>admin</sshUserId>
            <sshPassword>secret123</sshPassword>
            <phonePassword>phone456</phonePassword>
        </xml>
        '''
        mock_http.return_value = config_xml
        
        # This would need to set global variables properly
        # Full test would require more setup
        pass  # Placeholder
    
    @patch('thief.download_config_http')
    def test_search_for_secrets_no_credentials(self, mock_http):
        """Test config file with no credentials"""
        config_xml = '<xml><config>basic settings</config></xml>'
        mock_http.return_value = config_xml
        
        # Should not find any credentials
        pass  # Placeholder


class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_database_init_with_nested_path(self):
        """Test database initialization in nested directory"""
        db_path = '/tmp/test_thief/nested/dir/thief.db'
        try:
            if os.path.exists(db_path):
                os.unlink(db_path)
            
            init_database(db_path)
            assert os.path.exists(db_path)
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)
                # Clean up directories
                import shutil
                if os.path.exists('/tmp/test_thief'):
                    shutil.rmtree('/tmp/test_thief')
    
    def test_csv_export_empty_data(self):
        """Test CSV export with empty credentials"""
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as tmp:
            csv_file = tmp.name
        
        try:
            result = export_to_csv([], [], csv_file)
            assert result == True
            
            with open(csv_file, 'r') as f:
                lines = f.readlines()
                assert len(lines) == 1  # Just header
        finally:
            os.unlink(csv_file)
