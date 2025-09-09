"""
Logging configuration and utilities for boxi.

Provides structured logging with Rich console output and optional file logging.
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
