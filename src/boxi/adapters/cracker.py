"""
Hash cracking adapter for password recovery.

Uses hashcat when available, falls back to simple dictionary attacks.
"""

import hashlib
from pathlib import Path
from typing import List, Optional

from boxi.artifacts import HashArtifact, HashAlgorithm
from boxi.config import get_settings
from boxi.logging_config import get_logger, log_tool_missing
from boxi.utils.fs import read_file_lines
from boxi.utils.process import ProcessError, ProcessTimeout, run

logger = get_logger(__name__)


class CrackerAdapter:
    """Adapter for password hash cracking."""
    
    def __init__(self):
        self.settings = get_settings()
        self.hashcat_path = self.settings.get_tool_path("hashcat")
        self.john_path = self.settings.get_tool_path("john")
        self.timeout = self.settings.crack_timeout
    
    def is_hashcat_available(self) -> bool:
        """Check if hashcat is available."""
        return self.hashcat_path is not None
    
    def is_john_available(self) -> bool:
        """Check if John the Ripper is available."""
        return self.john_path is not None
    
    def crack_hash(self, hash_artifact: HashArtifact, wordlist_path: Optional[str] = None) -> bool:
        """
        Attempt to crack a hash.
        
        Args:
            hash_artifact: Hash to crack
            wordlist_path: Path to wordlist file (uses default if None)
            
        Returns:
            True if hash was cracked
        """
        if wordlist_path is None:
            wordlist_path = self.settings.get_wordlist()
        
        if not wordlist_path or not Path(wordlist_path).exists():
            logger.warning("No wordlist available for hash cracking")
            return self._crack_hash_simple(hash_artifact)
        
        # Try hashcat first (faster), then John, then simple
        if self.is_hashcat_available():
            success = self._crack_with_hashcat(hash_artifact, wordlist_path)
            if success:
                return True
        
        if self.is_john_available():
            success = self._crack_with_john(hash_artifact, wordlist_path)
            if success:
                return True
        
        # Fall back to simple dictionary attack
        return self._crack_hash_simple(hash_artifact, wordlist_path)
    
    def crack_multiple_hashes(self, hash_artifacts: List[HashArtifact], 
                            wordlist_path: Optional[str] = None) -> int:
        """
        Crack multiple hashes.
        
        Args:
            hash_artifacts: List of hashes to crack
            wordlist_path: Path to wordlist file
            
        Returns:
            Number of hashes cracked
        """
        cracked_count = 0
        
        for hash_artifact in hash_artifacts:
            if hash_artifact.cracked_password:
                continue  # Skip already cracked
            
            logger.debug(f"Attempting to crack hash for {hash_artifact.username}")
            
            if self.crack_hash(hash_artifact, wordlist_path):
                cracked_count += 1
                logger.info(f"Cracked password for {hash_artifact.username}")
        
        logger.info(f"Cracked {cracked_count}/{len(hash_artifacts)} hashes")
        return cracked_count
    
    def _crack_with_hashcat(self, hash_artifact: HashArtifact, wordlist_path: str) -> bool:
        """Crack hash using hashcat."""
        # Map our hash types to hashcat modes
        hashcat_modes = {
            HashAlgorithm.MD5: "0",
            HashAlgorithm.SHA1: "100",
            HashAlgorithm.SHA256: "1400",
            HashAlgorithm.SHA512: "1700",
            HashAlgorithm.NTLM: "1000",
            HashAlgorithm.LM: "3000",
        }
        
        if hash_artifact.algorithm not in hashcat_modes:
            logger.debug(f"Unsupported hash type for hashcat: {hash_artifact.algorithm}")
            return False
        
        mode = hashcat_modes[hash_artifact.algorithm]
        
        # Create temporary hash file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False) as f:
            f.write(hash_artifact.hash_value)
            hash_file = f.name
        
        try:
            cmd = [
                self.hashcat_path,
                "-m", mode,
                "-a", "0",  # Dictionary attack
                "--quiet",
                "--potfile-disable",  # Don't use potfile
                "--outfile-format", "2",  # Plain passwords only
                hash_file,
                wordlist_path
            ]
            
            logger.debug(f"Running hashcat for {hash_artifact.username}")
            result = run(cmd, timeout=self.timeout)
            
            if result.returncode == 0 and result.stdout:
                # Hashcat outputs the cracked password
                password = result.stdout.strip()
                if password:
                    hash_artifact.cracked_password = password
                    hash_artifact.cracked_at = hash_artifact.discovered_at
                    return True
            
        except (ProcessError, ProcessTimeout) as e:
            logger.debug(f"Hashcat failed for {hash_artifact.username}: {e}")
        finally:
            # Clean up temp file
            Path(hash_file).unlink(missing_ok=True)
        
        return False
    
    def _crack_with_john(self, hash_artifact: HashArtifact, wordlist_path: str) -> bool:
        """Crack hash using John the Ripper."""
        # Map our hash types to john formats
        john_formats = {
            HashAlgorithm.MD5: "raw-md5",
            HashAlgorithm.SHA1: "raw-sha1", 
            HashAlgorithm.SHA256: "raw-sha256",
            HashAlgorithm.SHA512: "raw-sha512",
            HashAlgorithm.NTLM: "nt",
            HashAlgorithm.LM: "lm",
        }
        
        if hash_artifact.algorithm not in john_formats:
            logger.debug(f"Unsupported hash type for john: {hash_artifact.algorithm}")
            return False
        
        format_name = john_formats[hash_artifact.algorithm]
        
        # Create hash file in john format
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False) as f:
            f.write(f"{hash_artifact.username}:{hash_artifact.hash_value}")
            hash_file = f.name
        
        try:
            cmd = [
                self.john_path,
                "--format=" + format_name,
                "--wordlist=" + wordlist_path,
                hash_file
            ]
            
            logger.debug(f"Running john for {hash_artifact.username}")
            result = run(cmd, timeout=self.timeout)
            
            # John's output format varies, try to get the password
            if result.returncode == 0:
                # Run john --show to get cracked passwords
                show_cmd = [self.john_path, "--show", "--format=" + format_name, hash_file]
                show_result = run(show_cmd, timeout=10)
                
                if show_result.stdout:
                    # Parse output: username:password
                    for line in show_result.stdout.split('\n'):
                        if ':' in line and hash_artifact.username in line:
                            parts = line.split(':', 1)
                            if len(parts) == 2:
                                password = parts[1].strip()
                                if password:
                                    hash_artifact.cracked_password = password
                                    hash_artifact.cracked_at = hash_artifact.discovered_at
                                    return True
            
        except (ProcessError, ProcessTimeout) as e:
            logger.debug(f"John failed for {hash_artifact.username}: {e}")
        finally:
            # Clean up temp file
            Path(hash_file).unlink(missing_ok=True)
        
        return False
    
    def _crack_hash_simple(self, hash_artifact: HashArtifact, 
                          wordlist_path: Optional[str] = None) -> bool:
        """Simple dictionary attack using Python (fallback method)."""
        if hash_artifact.algorithm == HashAlgorithm.UNKNOWN:
            logger.debug(f"Cannot crack unknown hash type for {hash_artifact.username}")
            return False
        
        # Get wordlist
        if wordlist_path and Path(wordlist_path).exists():
            passwords = read_file_lines(wordlist_path, max_lines=10000)  # Limit for performance
        else:
            # Use common passwords as fallback
            passwords = self._get_common_passwords()
        
        logger.debug(f"Trying {len(passwords)} passwords for {hash_artifact.username}")
        
        # Hash each password and compare
        for password in passwords:
            if not password.strip():
                continue
            
            password = password.strip()
            computed_hash = self._compute_hash(password, hash_artifact.algorithm)
            
            if computed_hash and computed_hash.lower() == hash_artifact.hash_value.lower():
                hash_artifact.cracked_password = password
                hash_artifact.cracked_at = hash_artifact.discovered_at
                logger.info(f"Cracked {hash_artifact.username} with simple attack")
                return True
        
        return False
    
    def _compute_hash(self, password: str, algorithm: HashAlgorithm) -> Optional[str]:
        """Compute hash of password using specified algorithm."""
        try:
            password_bytes = password.encode('utf-8')
            
            if algorithm == HashAlgorithm.MD5:
                return hashlib.md5(password_bytes).hexdigest()
            elif algorithm == HashAlgorithm.SHA1:
                return hashlib.sha1(password_bytes).hexdigest()
            elif algorithm == HashAlgorithm.SHA256:
                return hashlib.sha256(password_bytes).hexdigest()
            elif algorithm == HashAlgorithm.SHA512:
                return hashlib.sha512(password_bytes).hexdigest()
            elif algorithm == HashAlgorithm.NTLM:
                # NTLM hash (simplified - real NTLM has more complexity)
                import codecs
                return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
            else:
                return None
                
        except Exception:
            return None
    
    def _get_common_passwords(self) -> List[str]:
        """Get list of common passwords for fallback cracking."""
        return [
            "password", "123456", "password123", "admin", "letmein",
            "welcome", "monkey", "1234567890", "qwerty", "abc123",
            "Password1", "password1", "root", "toor", "pass",
            "guest", "user", "test", "demo", "login", "default",
            "", "admin123", "administrator", "manager", "service",
            "summer", "winter", "spring", "autumn", "january",
            "february", "march", "april", "may", "june", "july",
            "august", "september", "october", "november", "december"
        ]


def create_adapter() -> CrackerAdapter:
    """Create a cracker adapter instance."""
    return CrackerAdapter()
