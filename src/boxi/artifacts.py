"""
Artifact models for tracking discovered items during pentest runs.

These Pydantic models represent the core data structures that flow through
the boxi pipeline - targets, services, credentials, files, hashes, and flags.
"""

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class CredentialType(str, Enum):
    """Types of credentials found during testing."""
    PASSWORD = "password"
    HASH = "hash" 
    KEY = "key"
    TOKEN = "token"
    CERTIFICATE = "certificate"


class ServiceState(str, Enum):
    """State of a discovered service."""
    UNKNOWN = "unknown"
    OPEN = "open"
    FILTERED = "filtered"
    CLOSED = "closed"


class HashAlgorithm(str, Enum):
    """Supported hash algorithms."""
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    NTLM = "ntlm"
    LM = "lm"
    BCRYPT = "bcrypt"
    SCRYPT = "scrypt"
    UNKNOWN = "unknown"


class Target(BaseModel):
    """A target host or network being tested."""
    host: str = Field(..., description="IP address or hostname")
    os_guess: Optional[str] = Field(None, description="Detected operating system")
    domain_joined: Optional[bool] = Field(None, description="Whether host appears domain-joined")
    hostname: Optional[str] = Field(None, description="Resolved hostname")
    discovered_at: datetime = Field(default_factory=datetime.now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def __str__(self) -> str:
        return f"Target({self.host})"


class Service(BaseModel):
    """A network service running on a target."""
    target_host: str = Field(..., description="Host where service is running")
    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field(..., description="Protocol (tcp/udp)")
    service_name: Optional[str] = Field(None, description="Detected service name")
    banner: Optional[str] = Field(None, description="Service banner or version info")
    state: ServiceState = Field(ServiceState.UNKNOWN, description="Service state")
    discovered_at: datetime = Field(default_factory=datetime.now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def __str__(self) -> str:
        return f"Service({self.target_host}:{self.port}/{self.protocol})"


class Credential(BaseModel):
    """A discovered or provided credential."""
    username: str = Field(..., description="Username or identifier")
    secret: str = Field(..., description="Password, hash, or other secret")
    credential_type: CredentialType = Field(CredentialType.PASSWORD)
    source: str = Field(..., description="How this credential was discovered")
    score: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score")
    domain: Optional[str] = Field(None, description="Domain or realm")
    discovered_at: datetime = Field(default_factory=datetime.now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def __str__(self) -> str:
        domain_part = f"{self.domain}\\" if self.domain else ""
        return f"Credential({domain_part}{self.username})"

    @property
    def full_username(self) -> str:
        """Get username with domain prefix if available."""
        return f"{self.domain}\\{self.username}" if self.domain else self.username


class FileArtifact(BaseModel):
    """A file discovered during testing."""
    path: Union[str, Path] = Field(..., description="File path (local or remote)")
    name: str = Field(..., description="Filename")
    size: Optional[int] = Field(None, ge=0, description="File size in bytes")
    mime_type: Optional[str] = Field(None, description="MIME type")
    hash_md5: Optional[str] = Field(None, description="MD5 hash")
    hash_sha256: Optional[str] = Field(None, description="SHA256 hash")
    source: str = Field(..., description="How this file was discovered")
    local_path: Optional[Path] = Field(None, description="Local path if downloaded")
    discovered_at: datetime = Field(default_factory=datetime.now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def __str__(self) -> str:
        return f"FileArtifact({self.name})"


class HashArtifact(BaseModel):
    """A password hash discovered during testing."""
    username: str = Field(..., description="Username associated with hash")
    algorithm: HashAlgorithm = Field(..., description="Hash algorithm")
    hash_value: str = Field(..., description="The hash value")
    salt: Optional[str] = Field(None, description="Salt if applicable")
    source: str = Field(..., description="How this hash was discovered")
    cracked_password: Optional[str] = Field(None, description="Cracked plaintext password")
    discovered_at: datetime = Field(default_factory=datetime.now)
    cracked_at: Optional[datetime] = Field(None, description="When hash was cracked")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def __str__(self) -> str:
        status = "cracked" if self.cracked_password else "uncracked"
        return f"HashArtifact({self.username}, {self.algorithm.value}, {status})"

    def to_credential(self) -> Optional[Credential]:
        """Convert cracked hash to credential."""
        if not self.cracked_password:
            return None
        
        return Credential(
            username=self.username,
            secret=self.cracked_password,
            credential_type=CredentialType.PASSWORD,
            source=f"cracked_{self.source}",
            score=0.9,  # High confidence for cracked hashes
            discovered_at=self.cracked_at or datetime.now()
        )


class Flag(BaseModel):
    """A CTF flag or other target artifact."""
    path: str = Field(..., description="Where the flag was found")
    value: Optional[str] = Field(None, description="Flag value if extracted")
    pattern: Optional[str] = Field(None, description="Flag pattern matched")
    source: str = Field(..., description="How this flag was discovered")
    discovered_at: datetime = Field(default_factory=datetime.now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def __str__(self) -> str:
        return f"Flag({self.path})"


class RunState(BaseModel):
    """Overall state of a boxi run."""
    target: str = Field(..., description="Primary target being tested")
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = Field(None)
    status: str = Field(default="running", description="Run status")
    
    # Collected artifacts
    targets: List[Target] = Field(default_factory=list)
    services: List[Service] = Field(default_factory=list)
    credentials: List[Credential] = Field(default_factory=list)
    files: List[FileArtifact] = Field(default_factory=list)
    hashes: List[HashArtifact] = Field(default_factory=list)
    flags: List[Flag] = Field(default_factory=list)
    
    # User-provided overrides
    ignore_patterns: List[str] = Field(default_factory=list)
    hints: List[str] = Field(default_factory=list)
    
    # Stage tracking
    completed_stages: List[str] = Field(default_factory=list)
    failed_stages: List[str] = Field(default_factory=list)
    
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def add_credential(self, credential: Credential) -> None:
        """Add a credential, avoiding duplicates."""
        existing = [c for c in self.credentials 
                   if c.username == credential.username and c.secret == credential.secret]
        if not existing:
            self.credentials.append(credential)

    def add_service(self, service: Service) -> None:
        """Add a service, avoiding duplicates."""
        existing = [s for s in self.services 
                   if s.target_host == service.target_host and 
                      s.port == service.port and 
                      s.protocol == service.protocol]
        if not existing:
            self.services.append(service)

    def get_open_services(self, service_name: Optional[str] = None) -> List[Service]:
        """Get all open services, optionally filtered by name."""
        services = [s for s in self.services if s.state == ServiceState.OPEN]
        if service_name:
            services = [s for s in services if s.service_name == service_name]
        return services

    def get_valid_credentials(self) -> List[Credential]:
        """Get credentials with high confidence scores."""
        return [c for c in self.credentials if c.score >= 0.7]
