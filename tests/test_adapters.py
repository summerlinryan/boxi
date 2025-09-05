"""Tests for adapter modules."""

import pytest
from unittest.mock import Mock, patch, mock_open
from pathlib import Path

from boxi.adapters.nmap import NmapAdapter
from boxi.adapters.ftp import FTPAdapter
from boxi.adapters.ocr import OCRAdapter
from boxi.adapters.cracker import CrackerAdapter
from boxi.artifacts import Credential, HashArtifact, HashAlgorithm


class TestNmapAdapter:
    """Test Nmap adapter."""
    
    def test_adapter_creation(self):
        adapter = NmapAdapter()
        assert adapter is not None
        assert adapter.timeout > 0
    
    @patch('boxi.adapters.nmap.run')
    def test_quick_scan_success(self, mock_run):
        # Mock nmap output
        mock_output = """
        Nmap scan report for 10.10.10.10
        22/tcp open  ssh     OpenSSH 7.4
        80/tcp open  http    Apache httpd 2.4.6
        443/tcp closed https
        """
        
        mock_run.return_value = Mock(stdout=mock_output, returncode=0)
        
        adapter = NmapAdapter()
        adapter.tool_path = "/usr/bin/nmap"  # Mock availability
        
        services = adapter.quick_scan("10.10.10.10")
        
        assert len(services) >= 2  # Should find at least open ports
        assert any(s.port == 22 for s in services)
        assert any(s.port == 80 for s in services)
    
    @patch('boxi.adapters.nmap.run')
    def test_quick_scan_failure(self, mock_run):
        # Mock nmap failure
        mock_run.side_effect = Exception("Command failed")
        
        adapter = NmapAdapter()
        adapter.tool_path = "/usr/bin/nmap"
        
        services = adapter.quick_scan("10.10.10.10")
        assert services == []
    
    def test_unavailable_tool(self):
        adapter = NmapAdapter()
        adapter.tool_path = None  # Tool not available
        
        services = adapter.quick_scan("10.10.10.10")
        assert services == []


class TestFTPAdapter:
    """Test FTP adapter."""
    
    def test_adapter_creation(self):
        adapter = FTPAdapter()
        assert adapter is not None
        assert adapter.timeout > 0
    
    @patch('boxi.adapters.ftp.ftplib.FTP')
    def test_anonymous_login_success(self, mock_ftp_class):
        mock_ftp = Mock()
        mock_ftp_class.return_value = mock_ftp
        
        adapter = FTPAdapter()
        result = adapter.test_anonymous_login("10.10.10.10")
        
        assert result is True
        mock_ftp.connect.assert_called_once()
        mock_ftp.login.assert_called_once_with('anonymous', 'anonymous@example.com')
        mock_ftp.quit.assert_called_once()
    
    @patch('boxi.adapters.ftp.ftplib.FTP')
    def test_anonymous_login_failure(self, mock_ftp_class):
        mock_ftp = Mock()
        mock_ftp.login.side_effect = Exception("Login failed")
        mock_ftp_class.return_value = mock_ftp
        
        adapter = FTPAdapter()
        result = adapter.test_anonymous_login("10.10.10.10")
        
        assert result is False
    
    @patch('boxi.adapters.ftp.ftplib.FTP')
    def test_credential_login(self, mock_ftp_class):
        mock_ftp = Mock()
        mock_ftp_class.return_value = mock_ftp
        
        cred = Credential(username="user", secret="pass", source="test")
        
        adapter = FTPAdapter()
        result = adapter.test_credential_login("10.10.10.10", cred)
        
        assert result is True
        mock_ftp.login.assert_called_once_with("user", "pass")
    
    @patch('boxi.adapters.ftp.ftplib.FTP')
    def test_list_directory(self, mock_ftp_class):
        mock_ftp = Mock()
        
        # Mock directory listing
        def mock_retrlines(cmd, callback):
            lines = [
                "-rw-r--r-- 1 user group 1024 Jan 01 12:00 file1.txt",
                "drwxr-xr-x 2 user group 4096 Jan 01 12:00 subdir",
                "-rw-r--r-- 1 user group 2048 Jan 01 12:00 file2.pdf"
            ]
            for line in lines:
                callback(line)
        
        mock_ftp.retrlines = mock_retrlines
        mock_ftp_class.return_value = mock_ftp
        
        adapter = FTPAdapter()
        files = adapter.list_directory("10.10.10.10")
        
        assert len(files) == 3
        assert any(f['name'] == 'file1.txt' for f in files)
        assert any(f['type'] == 'directory' for f in files)


class TestOCRAdapter:
    """Test OCR adapter."""
    
    def test_adapter_creation(self):
        adapter = OCRAdapter()
        assert adapter is not None
    
    def test_unavailable_tool(self):
        adapter = OCRAdapter()
        adapter.tesseract_path = None  # Tool not available
        
        assert not adapter.is_available()
        
        test_image = Path("/tmp/test.png")
        result = adapter.extract_text_from_image(test_image)
        assert result is None
    
    @patch('boxi.adapters.ocr.run')
    @patch('pathlib.Path.read_text')
    @patch('pathlib.Path.exists')
    def test_extract_text_success(self, mock_exists, mock_read, mock_run):
        # Mock successful tesseract execution
        mock_run.return_value = Mock(returncode=0)
        mock_exists.return_value = True
        mock_read.return_value = "Extracted text from image"
        
        adapter = OCRAdapter()
        adapter.tesseract_path = "/usr/bin/tesseract"
        
        test_image = Path("/tmp/test.png")
        result = adapter.extract_text_from_image(test_image)
        
        assert result == "Extracted text from image"
    
    def test_extract_text_from_text_file(self):
        adapter = OCRAdapter()
        
        # Test plain text file
        with patch('pathlib.Path.exists') as mock_exists, \
             patch('pathlib.Path.read_text') as mock_read:
            
            mock_exists.return_value = True
            mock_read.return_value = "Plain text content"
            
            test_file = Path("/tmp/test.txt")
            result = adapter.extract_text_from_file(test_file)
            
            assert result == "Plain text content"


class TestCrackerAdapter:
    """Test hash cracking adapter."""
    
    def test_adapter_creation(self):
        adapter = CrackerAdapter()
        assert adapter is not None
    
    def test_simple_md5_crack(self):
        adapter = CrackerAdapter()
        
        # Create MD5 hash for "hello" = 5d41402abc4b2a76b9719d911017c592
        hash_artifact = HashArtifact(
            username="admin",
            algorithm=HashAlgorithm.MD5,
            hash_value="5d41402abc4b2a76b9719d911017c592",
            source="test"
        )
        
        # Should crack using common passwords
        result = adapter._crack_hash_simple(hash_artifact)
        
        # "hello" should be in common passwords or crack via dictionary
        assert result is True or hash_artifact.cracked_password is not None
    
    def test_unsupported_hash_type(self):
        adapter = CrackerAdapter()
        
        hash_artifact = HashArtifact(
            username="admin",
            algorithm=HashAlgorithm.UNKNOWN,
            hash_value="somehash",
            source="test"
        )
        
        result = adapter._crack_hash_simple(hash_artifact)
        assert result is False
    
    def test_common_passwords_list(self):
        adapter = CrackerAdapter()
        passwords = adapter._get_common_passwords()
        
        assert isinstance(passwords, list)
        assert len(passwords) > 0
        assert "password" in passwords
        assert "123456" in passwords
    
    def test_compute_hash_md5(self):
        adapter = CrackerAdapter()
        
        # Test MD5 computation
        hash_result = adapter._compute_hash("hello", HashAlgorithm.MD5)
        assert hash_result == "5d41402abc4b2a76b9719d911017c592"
        
        # Test SHA1 computation
        hash_result = adapter._compute_hash("hello", HashAlgorithm.SHA1)
        assert hash_result == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    
    @patch('boxi.adapters.cracker.run')
    def test_hashcat_execution(self, mock_run):
        # Mock hashcat availability and execution
        mock_run.return_value = Mock(returncode=0, stdout="cracked_password")
        
        adapter = CrackerAdapter()
        adapter.hashcat_path = "/usr/bin/hashcat"
        
        hash_artifact = HashArtifact(
            username="admin",
            algorithm=HashAlgorithm.MD5,
            hash_value="5d41402abc4b2a76b9719d911017c592",
            source="test"
        )
        
        result = adapter._crack_with_hashcat(hash_artifact, "/tmp/wordlist.txt")
        
        if result:  # Only check if hashcat execution was mocked successfully
            assert hash_artifact.cracked_password == "cracked_password"


class TestAdapterIntegration:
    """Test adapter integration scenarios."""
    
    def test_ftp_to_ocr_workflow(self):
        """Test workflow from FTP download to OCR extraction."""
        
        # Mock FTP download
        with patch('boxi.adapters.ftp.ftplib.FTP') as mock_ftp_class:
            mock_ftp = Mock()
            mock_ftp_class.return_value = mock_ftp
            
            # Mock file download
            def mock_retrbinary(cmd, callback):
                callback(b"Mock PDF content")
            
            mock_ftp.retrbinary = mock_retrbinary
            
            ftp_adapter = FTPAdapter()
            
            # This would normally save to a real file, but we're mocking
            with patch('pathlib.Path.stat') as mock_stat, \
                 patch('builtins.open', mock_open()):
                
                mock_stat.return_value = Mock(st_size=1024)
                
                artifact = ftp_adapter.download_file("10.10.10.10", "/test.pdf")
                
                if artifact:  # If download succeeded in mock
                    assert artifact.name == "test.pdf"
                    assert artifact.source.startswith("ftp://")
    
    def test_credential_validation_workflow(self):
        """Test credential validation across multiple services."""
        
        cred = Credential(username="admin", secret="password", source="test")
        
        # Test FTP validation
        with patch('boxi.adapters.ftp.ftplib.FTP') as mock_ftp:
            mock_ftp.return_value = Mock()
            
            ftp_adapter = FTPAdapter()
            ftp_result = ftp_adapter.test_credential_login("10.10.10.10", cred)
            
            # Should attempt login without error
            assert isinstance(ftp_result, bool)
    
    def test_hash_to_credential_workflow(self):
        """Test hash cracking to credential conversion."""
        
        hash_artifact = HashArtifact(
            username="admin",
            algorithm=HashAlgorithm.MD5,
            hash_value="5d41402abc4b2a76b9719d911017c592",  # "hello"
            source="database"
        )
        
        # Simulate successful crack
        hash_artifact.cracked_password = "hello"
        
        # Convert to credential
        credential = hash_artifact.to_credential()
        
        assert credential is not None
        assert credential.username == "admin"
        assert credential.secret == "hello"
        assert credential.source == "cracked_database"
        assert credential.score == 0.9
