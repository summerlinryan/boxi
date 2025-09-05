"""
boxi - Human-in-the-loop CTF/pentest CLI

A modular penetration testing tool that combines automation with human oversight
for authorized security testing scenarios like CTF competitions.
"""

__version__ = "0.1.0"
__author__ = "boxi contributors"
__license__ = "MIT"

from boxi.artifacts import Credential, FileArtifact, Flag, HashArtifact, Service, Target

__all__ = [
    "Target",
    "Service", 
    "Credential",
    "FileArtifact",
    "HashArtifact",
    "Flag",
]
