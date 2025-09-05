"""
Logging configuration for boxi.

Provides structured logging with Rich console output and optional file logging.
Supports different log levels and formats for console vs file output.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.traceback import install


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    verbose: bool = False,
    quiet: bool = False,
) -> logging.Logger:
    """
    Set up logging configuration for boxi.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file to write logs to
        verbose: Enable verbose output (DEBUG level)
        quiet: Suppress non-critical output (WARNING+ only)
    
    Returns:
        Configured logger instance
    """
    # Install rich traceback handler
    install(show_locals=verbose)
    
    # Determine effective log level
    if verbose:
        effective_level = "DEBUG"
    elif quiet:
        effective_level = "WARNING"
    else:
        effective_level = level.upper()
    
    # Create root logger
    logger = logging.getLogger("boxi")
    logger.setLevel(getattr(logging, effective_level))
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Console handler with Rich formatting
    console = Console(stderr=True, force_terminal=not quiet)
    console_handler = RichHandler(
        console=console,
        show_time=verbose,
        show_path=verbose,
        rich_tracebacks=True,
        tracebacks_show_locals=verbose,
    )
    console_handler.setLevel(getattr(logging, effective_level))
    
    # Format for console (Rich handles most formatting)
    console_format = "%(message)s"
    console_handler.setFormatter(logging.Formatter(console_format))
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)  # Always debug level for files
        
        # More detailed format for file output
        file_format = (
            "%(asctime)s - %(name)s - %(levelname)s - "
            "%(funcName)s:%(lineno)d - %(message)s"
        )
        file_handler.setFormatter(logging.Formatter(file_format))
        logger.addHandler(file_handler)
    
    # Suppress noisy third-party loggers unless in debug mode
    if effective_level != "DEBUG":
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("paramiko").setLevel(logging.WARNING)
    
    return logger


def get_logger(name: str = "boxi") -> logging.Logger:
    """Get a logger instance."""
    return logging.getLogger(name)


class StageLogger:
    """
    Context manager for stage-specific logging.
    
    Provides consistent formatting and timing for pentest stages.
    """
    
    def __init__(self, stage_name: str, target: Optional[str] = None):
        self.stage_name = stage_name
        self.target = target
        self.logger = get_logger(f"boxi.stages.{stage_name}")
        self.start_time: Optional[float] = None
    
    def __enter__(self) -> "StageLogger":
        import time
        self.start_time = time.time()
        
        target_info = f" against {self.target}" if self.target else ""
        self.logger.info(f"Starting {self.stage_name}{target_info}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        import time
        if self.start_time:
            duration = time.time() - self.start_time
            
            if exc_type:
                self.logger.error(
                    f"{self.stage_name} failed after {duration:.2f}s: {exc_val}"
                )
            else:
                self.logger.info(f"{self.stage_name} completed in {duration:.2f}s")
    
    def info(self, message: str) -> None:
        """Log info message with stage context."""
        self.logger.info(f"[{self.stage_name}] {message}")
    
    def warning(self, message: str) -> None:
        """Log warning message with stage context.""" 
        self.logger.warning(f"[{self.stage_name}] {message}")
    
    def error(self, message: str) -> None:
        """Log error message with stage context."""
        self.logger.error(f"[{self.stage_name}] {message}")
    
    def debug(self, message: str) -> None:
        """Log debug message with stage context."""
        self.logger.debug(f"[{self.stage_name}] {message}")


def log_command(cmd: list[str], timeout: Optional[int] = None) -> None:
    """Log a command being executed."""
    logger = get_logger("boxi.command")
    cmd_str = " ".join(cmd)
    timeout_info = f" (timeout: {timeout}s)" if timeout else ""
    logger.debug(f"Executing: {cmd_str}{timeout_info}")


def log_command_result(
    cmd: list[str], 
    returncode: int, 
    stdout: str, 
    stderr: str, 
    duration: float
) -> None:
    """Log the result of a command execution."""
    logger = get_logger("boxi.command")
    cmd_str = " ".join(cmd[:2])  # Just show first two parts for brevity
    
    if returncode == 0:
        logger.debug(f"Command '{cmd_str}' completed in {duration:.2f}s")
    else:
        logger.warning(
            f"Command '{cmd_str}' failed (exit {returncode}) in {duration:.2f}s"
        )
        if stderr:
            logger.debug(f"stderr: {stderr[:200]}...")


def log_artifact_found(artifact_type: str, details: str) -> None:
    """Log when an artifact is discovered."""
    logger = get_logger("boxi.artifacts")
    logger.info(f"Found {artifact_type}: {details}")


def log_stage_skip(stage_name: str, reason: str) -> None:
    """Log when a stage is skipped."""
    logger = get_logger("boxi.orchestrator")
    logger.info(f"Skipping {stage_name}: {reason}")


def log_tool_missing(tool_name: str, stage_name: str) -> None:
    """Log when a required tool is missing."""
    logger = get_logger("boxi.tools")
    logger.warning(f"Tool '{tool_name}' not found, skipping {stage_name}")


def log_user_injection(injection_type: str, data: str) -> None:
    """Log when user injects data into the run."""
    logger = get_logger("boxi.inject")
    logger.info(f"User injected {injection_type}: {data}")


# Initialize default logging for imports
_default_logger = setup_logging()
