"""Tests for artifact models."""

import pytest
from datetime import datetime
from pathlib import Path

from boxi.artifacts import (
    Credential, CredentialType, FileArtifact, Flag, HashArtifact, HashAlgorithm,
    RunState, Service, ServiceState, Target
)


class TestTarget:
    """Test Target artifact."""
    
    def test_basic_target(self):
        target = Target(host="10.10.10.10")
        assert target.host == "10.10.10.10"
        assert target.os_guess is None
        assert target.domain_joined is None
        assert isinstance(target.discovered_at, datetime)
    
    def test_target_with_details(self):
        target = Target(
            host="10.10.10.10",
            os_guess="Windows Server 2019",
            domain_joined=True,
            hostname="DC01.example.com"
        )
        assert target.os_guess == "Windows Server 2019"
        assert target.domain_joined is True
        assert target.hostname == "DC01.example.com"
    
    def test_target_str(self):
        target = Target(host="192.168.1.1")
        assert str(target) == "Target(192.168.1.1)"


class TestService:
    """Test Service artifact."""
    
    def test_basic_service(self):
        service = Service(
            target_host="10.10.10.10",
            port=80,
            protocol="tcp"
        )
        assert service.target_host == "10.10.10.10"
        assert service.port == 80
        assert service.protocol == "tcp"
        assert service.state == ServiceState.UNKNOWN
    
    def test_service_with_details(self):
        service = Service(
            target_host="10.10.10.10",
            port=443,
            protocol="tcp",
            service_name="https",
            banner="Apache/2.4.41",
            state=ServiceState.OPEN
        )
        assert service.service_name == "https"
        assert service.banner == "Apache/2.4.41"
        assert service.state == ServiceState.OPEN
    
    def test_service_port_validation(self):
        # Valid port
        service = Service(target_host="host", port=443, protocol="tcp")
        assert service.port == 443
        
        # Invalid port should raise validation error
        with pytest.raises(ValueError):
            Service(target_host="host", port=0, protocol="tcp")
        
        with pytest.raises(ValueError):
            Service(target_host="host", port=65536, protocol="tcp")
    
    def test_service_str(self):
        service = Service(target_host="test.com", port=22, protocol="tcp")
        assert str(service) == "Service(test.com:22/tcp)"


class TestCredential:
    """Test Credential artifact."""
    
    def test_basic_credential(self):
        cred = Credential(
            username="admin",
            secret="password123",
            source="manual"
        )
        assert cred.username == "admin"
        assert cred.secret == "password123"
        assert cred.credential_type == CredentialType.PASSWORD
        assert cred.score == 1.0
        assert cred.domain is None
    
    def test_credential_with_domain(self):
        cred = Credential(
            username="admin",
            secret="password123",
            source="ldap",
            domain="EXAMPLE"
        )
        assert cred.domain == "EXAMPLE"
        assert cred.full_username == "EXAMPLE\\admin"
    
    def test_credential_without_domain(self):
        cred = Credential(
            username="admin",
            secret="password123",
            source="local"
        )
        assert cred.full_username == "admin"
    
    def test_credential_types(self):
        # Password credential
        pwd_cred = Credential(
            username="user",
            secret="pass",
            credential_type=CredentialType.PASSWORD,
            source="test"
        )
        assert pwd_cred.credential_type == CredentialType.PASSWORD
        
        # Hash credential
        hash_cred = Credential(
            username="user",
            secret="5d41402abc4b2a76b9719d911017c592",
            credential_type=CredentialType.HASH,
            source="test"
        )
        assert hash_cred.credential_type == CredentialType.HASH
    
    def test_credential_score_validation(self):
        # Valid score
        cred = Credential(username="user", secret="pass", source="test", score=0.8)
        assert cred.score == 0.8
        
        # Invalid scores should be clamped or raise errors
        with pytest.raises(ValueError):
            Credential(username="user", secret="pass", source="test", score=-0.1)
        
        with pytest.raises(ValueError):
            Credential(username="user", secret="pass", source="test", score=1.1)


class TestHashArtifact:
    """Test HashArtifact artifact."""
    
    def test_basic_hash(self):
        hash_artifact = HashArtifact(
            username="admin",
            algorithm=HashAlgorithm.MD5,
            hash_value="5d41402abc4b2a76b9719d911017c592",
            source="database"
        )
        assert hash_artifact.username == "admin"
        assert hash_artifact.algorithm == HashAlgorithm.MD5
        assert hash_artifact.hash_value == "5d41402abc4b2a76b9719d911017c592"
        assert hash_artifact.cracked_password is None
    
    def test_cracked_hash(self):
        hash_artifact = HashArtifact(
            username="admin",
            algorithm=HashAlgorithm.MD5,
            hash_value="5d41402abc4b2a76b9719d911017c592",
            source="database",
            cracked_password="hello"
        )
        assert hash_artifact.cracked_password == "hello"
        assert hash_artifact.cracked_at is None
    
    def test_hash_to_credential(self):
        # Uncracked hash
        hash_artifact = HashArtifact(
            username="admin",
            algorithm=HashAlgorithm.MD5,
            hash_value="5d41402abc4b2a76b9719d911017c592",
            source="database"
        )
        assert hash_artifact.to_credential() is None
        
        # Cracked hash
        hash_artifact.cracked_password = "hello"
        hash_artifact.cracked_at = datetime.now()
        
        cred = hash_artifact.to_credential()
        assert cred is not None
        assert cred.username == "admin"
        assert cred.secret == "hello"
        assert cred.credential_type == CredentialType.PASSWORD
        assert cred.source == "cracked_database"
        assert cred.score == 0.9
    
    def test_hash_str(self):
        hash_artifact = HashArtifact(
            username="user",
            algorithm=HashAlgorithm.SHA1,
            hash_value="aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
            source="test"
        )
        assert str(hash_artifact) == "HashArtifact(user, sha1, uncracked)"
        
        hash_artifact.cracked_password = "hello"
        assert str(hash_artifact) == "HashArtifact(user, sha1, cracked)"


class TestFileArtifact:
    """Test FileArtifact artifact."""
    
    def test_basic_file(self):
        file_artifact = FileArtifact(
            path="/tmp/test.txt",
            name="test.txt",
            source="ftp"
        )
        assert file_artifact.name == "test.txt"
        assert str(file_artifact.path) == "/tmp/test.txt"
        assert file_artifact.source == "ftp"
        assert file_artifact.size is None
    
    def test_file_with_details(self):
        file_artifact = FileArtifact(
            path="/tmp/document.pdf",
            name="document.pdf",
            size=1024,
            mime_type="application/pdf",
            hash_md5="d41d8cd98f00b204e9800998ecf8427e",
            source="smb",
            local_path=Path("/loot/document.pdf")
        )
        assert file_artifact.size == 1024
        assert file_artifact.mime_type == "application/pdf"
        assert file_artifact.hash_md5 == "d41d8cd98f00b204e9800998ecf8427e"
        assert file_artifact.local_path == Path("/loot/document.pdf")
    
    def test_file_size_validation(self):
        # Valid size
        file_artifact = FileArtifact(path="/test", name="test", source="test", size=1000)
        assert file_artifact.size == 1000
        
        # Invalid size
        with pytest.raises(ValueError):
            FileArtifact(path="/test", name="test", source="test", size=-1)


class TestFlag:
    """Test Flag artifact."""
    
    def test_basic_flag(self):
        flag = Flag(
            path="/root/flag.txt",
            source="filesystem"
        )
        assert flag.path == "/root/flag.txt"
        assert flag.source == "filesystem"
        assert flag.value is None
    
    def test_flag_with_value(self):
        flag = Flag(
            path="/root/flag.txt",
            value="HTB{test_flag_12345}",
            pattern="HTB{.*}",
            source="grep"
        )
        assert flag.value == "HTB{test_flag_12345}"
        assert flag.pattern == "HTB{.*}"


class TestRunState:
    """Test RunState management."""
    
    def test_basic_run_state(self):
        state = RunState(target="10.10.10.10")
        assert state.target == "10.10.10.10"
        assert state.status == "running"
        assert len(state.targets) == 0
        assert len(state.services) == 0
        assert len(state.credentials) == 0
    
    def test_add_credential(self):
        state = RunState(target="test")
        
        cred1 = Credential(username="admin", secret="pass1", source="test")
        cred2 = Credential(username="admin", secret="pass1", source="test")  # Duplicate
        cred3 = Credential(username="user", secret="pass2", source="test")
        
        state.add_credential(cred1)
        assert len(state.credentials) == 1
        
        # Adding duplicate should not increase count
        state.add_credential(cred2)
        assert len(state.credentials) == 1
        
        # Adding different credential should increase count
        state.add_credential(cred3)
        assert len(state.credentials) == 2
    
    def test_add_service(self):
        state = RunState(target="test")
        
        service1 = Service(target_host="host", port=80, protocol="tcp")
        service2 = Service(target_host="host", port=80, protocol="tcp")  # Duplicate
        service3 = Service(target_host="host", port=443, protocol="tcp")
        
        state.add_service(service1)
        assert len(state.services) == 1
        
        # Adding duplicate should not increase count
        state.add_service(service2)
        assert len(state.services) == 1
        
        # Adding different service should increase count
        state.add_service(service3)
        assert len(state.services) == 2
    
    def test_get_open_services(self):
        state = RunState(target="test")
        
        # Add various services
        open_service = Service(target_host="host", port=80, protocol="tcp", state=ServiceState.OPEN)
        closed_service = Service(target_host="host", port=81, protocol="tcp", state=ServiceState.CLOSED)
        ftp_service = Service(target_host="host", port=21, protocol="tcp", service_name="ftp", state=ServiceState.OPEN)
        
        state.add_service(open_service)
        state.add_service(closed_service)
        state.add_service(ftp_service)
        
        # Get all open services
        open_services = state.get_open_services()
        assert len(open_services) == 2
        
        # Get specific service type
        ftp_services = state.get_open_services("ftp")
        assert len(ftp_services) == 1
        assert ftp_services[0].service_name == "ftp"
    
    def test_get_valid_credentials(self):
        state = RunState(target="test")
        
        # Add credentials with different scores
        high_score = Credential(username="admin", secret="pass1", source="test", score=0.9)
        low_score = Credential(username="user", secret="pass2", source="test", score=0.5)
        
        state.add_credential(high_score)
        state.add_credential(low_score)
        
        # Only high-confidence credentials should be returned
        valid_creds = state.get_valid_credentials()
        assert len(valid_creds) == 1
        assert valid_creds[0].username == "admin"
