"""
boxi - Interactive penetration testing CLI

A modular penetration testing tool that combines smart automation with operator oversight.
Designed for CTF competitions and authorized penetration testing, it provides an intelligent
pipeline that can be paused, guided, and resumed at any time.

Core Architecture:
- Evidence-driven decision making
- Methodical penetration testing phases  
- Operational security awareness
- Complete audit trails
"""

__version__ = "0.1.0"
__author__ = "boxi contributors"
__license__ = "MIT"

# Core components
from boxi.core.architecture import (
    Evidence, Target, Technique, Orchestrator,
    PentestPhase, ThreatLevel
)
from boxi.core.logging import setup_logging, get_logger
from boxi.core.database import Database

__all__ = [
    "Evidence",
    "Target", 
    "Technique",
    "Orchestrator",
    "PentestPhase",
    "ThreatLevel",
    "setup_logging",
    "get_logger",
    "Database",
]