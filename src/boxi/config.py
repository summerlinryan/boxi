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
        extra="allow",
    )

    workspace_root: Path = Field(
        default_factory=lambda: Path.home() / ".boxi",
        description="Root directory for boxi workspace",
    )

    tool_paths: Dict[str, Optional[str]] = Field(
        default_factory=dict, description="Override paths for external tools"
    )

    wordlist_paths: List[str] = Field(
        default_factory=lambda: [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/fasttrack.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
            str(Path.home() / "wordlists" / "rockyou.txt"),
        ],
        description="Paths to wordlist files",
    )

    # Concurrency limits
    max_concurrent_scans: int = Field(
        default=10, description="Max concurrent port scans"
    )
    max_concurrent_cracks: int = Field(
        default=4, description="Max concurrent hash cracks"
    )

    # Safety settings
    safe_mode: bool = Field(
        default=True, description="Enable safe mode (no destructive actions)"
    )
    require_confirmation: bool = Field(
        default=True, description="Require confirmation for risky actions"
    )

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: Optional[Path] = Field(None, description="Log file path")

    # Database
    database_url: str = Field(
        default="sqlite:///boxi.db", description="Database connection URL"
    )

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
        run_dir = self.workspace_root / "runs" / f"{safe_target}_{timestamp}"
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir
