"""
Configuration management for boxi.

Uses Pydantic Settings for environment variable loading and validation.
Supports .env files and BOXI_ prefixed environment variables.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class BoxiSettings(BaseSettings):
    """Main configuration class for boxi."""
    
    model_config = SettingsConfigDict(
        env_prefix="BOXI_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="allow"
    )

    # Core paths
    workspace_root: Path = Field(
        default_factory=lambda: Path.home() / ".boxi",
        description="Root directory for boxi workspace"
    )
    
    # Tool paths (auto-discovered if not set)
    tool_paths: Dict[str, Optional[str]] = Field(
        default_factory=dict,
        description="Override paths for external tools"
    )
    
    # Timeouts (in seconds)
    default_timeout: int = Field(default=30, description="Default command timeout")
    nmap_timeout: int = Field(default=300, description="Nmap scan timeout") 
    ftp_timeout: int = Field(default=60, description="FTP operation timeout")
    smb_timeout: int = Field(default=120, description="SMB operation timeout")
    winrm_timeout: int = Field(default=60, description="WinRM operation timeout")
    crack_timeout: int = Field(default=600, description="Hash cracking timeout")
    
    # Wordlists and dictionaries
    wordlist_paths: List[str] = Field(
        default_factory=lambda: [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/fasttrack.txt", 
            "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
            str(Path.home() / "wordlists" / "rockyou.txt"),
        ],
        description="Paths to wordlist files"
    )
    
    # Concurrency limits
    max_concurrent_scans: int = Field(default=10, description="Max concurrent port scans")
    max_concurrent_cracks: int = Field(default=4, description="Max concurrent hash cracks")
    
    # Safety settings
    safe_mode: bool = Field(default=True, description="Enable safe mode (no destructive actions)")
    require_confirmation: bool = Field(default=True, description="Require confirmation for risky actions")
    
    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: Optional[Path] = Field(None, description="Log file path")
    verbose: bool = Field(default=False, description="Enable verbose output")
    quiet: bool = Field(default=False, description="Suppress non-critical output")
    
    # Database
    database_url: str = Field(
        default="sqlite:///boxi.db",
        description="Database connection URL"
    )
    
    # Report settings
    report_format: str = Field(default="markdown", description="Default report format")
    include_screenshots: bool = Field(default=True, description="Include screenshots in reports")
    
    def __init__(self, **data) -> None:
        super().__init__(**data)
        # Ensure workspace directory exists
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (self.workspace_root / "runs").mkdir(exist_ok=True)
        (self.workspace_root / "loot").mkdir(exist_ok=True)
        (self.workspace_root / "logs").mkdir(exist_ok=True)
    
    @property
    def loot_dir(self) -> Path:
        """Directory for storing looted files."""
        return self.workspace_root / "loot"
    
    @property
    def runs_dir(self) -> Path:
        """Directory for storing run data."""
        return self.workspace_root / "runs"
        
    @property
    def logs_dir(self) -> Path:
        """Directory for storing log files."""
        return self.workspace_root / "logs"
    
    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """Get the path for a specific tool."""
        # Check explicit override first
        if tool_name in self.tool_paths:
            return self.tool_paths[tool_name]
        
        # Try to find in PATH
        import shutil
        return shutil.which(tool_name)
    
    def set_tool_path(self, tool_name: str, path: str) -> None:
        """Set the path for a specific tool."""
        self.tool_paths[tool_name] = path
    
    def get_wordlist(self) -> Optional[str]:
        """Get the first available wordlist file."""
        for path_str in self.wordlist_paths:
            path = Path(path_str)
            if path.exists() and path.is_file():
                return str(path)
        return None
    
    def create_run_dir(self, target: str) -> Path:
        """Create a run directory for the given target."""
        # Sanitize target for filesystem
        safe_target = target.replace(".", "_").replace("/", "_").replace(":", "_")
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = self.runs_dir / f"{safe_target}_{timestamp}"
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir


# Global settings instance
settings = BoxiSettings()


def get_settings() -> BoxiSettings:
    """Get the global settings instance."""
    return settings


def update_settings(**kwargs) -> None:
    """Update global settings."""
    global settings
    # Create new instance with updated values
    current_data = settings.model_dump()
    current_data.update(kwargs)
    settings = BoxiSettings(**current_data)
