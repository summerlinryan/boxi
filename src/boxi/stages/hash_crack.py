"""
Hash cracking stage for password recovery.

Attempts to crack password hashes using various methods and wordlists.
"""

from typing import List

from boxi.adapters.cracker import create_adapter as create_cracker_adapter
from boxi.artifacts import Credential, HashArtifact
from boxi.logging_config import StageLogger, log_artifact_found, log_stage_skip
from boxi.runtime import require_context


def run_hash_cracking() -> List[Credential]:
    """
    Attempt to crack discovered password hashes.
    
    Returns:
        List of credentials from cracked hashes
    """
    context = require_context()
    
    with StageLogger("hash_crack") as stage_log:
        # Get hash artifacts to crack
        hash_artifacts = context.get_artifacts_by_type(HashArtifact)
        
        if not hash_artifacts:
            log_stage_skip("hash_crack", "No hashes found to crack")
            return []
        
        # Filter out already cracked hashes
        uncracked_hashes = [h for h in hash_artifacts if not h.cracked_password]
        
        if not uncracked_hashes:
            log_stage_skip("hash_crack", "All hashes already cracked")
            return []
        
        stage_log.info(f"Attempting to crack {len(uncracked_hashes)} hashes")
        
        cracker = create_cracker_adapter()
        new_credentials = []
        
        # Try to crack each hash
        for hash_artifact in uncracked_hashes:
            stage_log.debug(f"Attempting to crack hash for {hash_artifact.username}")
            
            success = cracker.crack_hash(hash_artifact)
            
            if success and hash_artifact.cracked_password:
                stage_log.info(f"Cracked password for {hash_artifact.username}")
                
                # Create credential from cracked hash
                credential = hash_artifact.to_credential()
                
                if credential:
                    new_credentials.append(credential)
                    context.add_credential(credential)
                    log_artifact_found("credential", f"{credential.username}:{credential.secret}")
                
                # Update the hash artifact in context (it's modified in place)
                log_artifact_found("cracked_hash", f"{hash_artifact.username}")
            else:
                stage_log.debug(f"Failed to crack hash for {hash_artifact.username}")
        
        stage_log.info(f"Hash cracking completed, cracked {len(new_credentials)} passwords")
        return new_credentials


def crack_specific_hashes(hash_artifacts: List[HashArtifact], 
                         wordlist_path: str = None) -> List[Credential]:
    """
    Crack specific hash artifacts with custom wordlist.
    
    Args:
        hash_artifacts: List of hashes to crack
        wordlist_path: Path to wordlist file
        
    Returns:
        List of credentials from cracked hashes
    """
    context = require_context()
    
    with StageLogger("hash_crack_specific") as stage_log:
        if not hash_artifacts:
            return []
        
        stage_log.info(f"Attempting to crack {len(hash_artifacts)} specific hashes")
        
        cracker = create_cracker_adapter()
        new_credentials = []
        
        # Try to crack each hash
        for hash_artifact in hash_artifacts:
            if hash_artifact.cracked_password:
                continue  # Skip already cracked
            
            stage_log.debug(f"Cracking hash for {hash_artifact.username}")
            
            success = cracker.crack_hash(hash_artifact, wordlist_path)
            
            if success and hash_artifact.cracked_password:
                stage_log.info(f"Cracked password for {hash_artifact.username}")
                
                # Create credential from cracked hash
                credential = hash_artifact.to_credential()
                
                if credential:
                    new_credentials.append(credential)
                    context.add_credential(credential)
                    log_artifact_found("credential", f"{credential.username}:{credential.secret}")
                
                log_artifact_found("cracked_hash", f"{hash_artifact.username}")
        
        stage_log.info(f"Cracked {len(new_credentials)} passwords from specific hashes")
        return new_credentials


def run_fast_hash_crack() -> List[Credential]:
    """
    Run fast hash cracking with common passwords only.
    
    Returns:
        List of credentials from cracked hashes
    """
    context = require_context()
    
    with StageLogger("fast_hash_crack") as stage_log:
        hash_artifacts = context.get_artifacts_by_type(HashArtifact)
        uncracked_hashes = [h for h in hash_artifacts if not h.cracked_password]
        
        if not uncracked_hashes:
            log_stage_skip("fast_hash_crack", "No hashes to crack")
            return []
        
        stage_log.info(f"Fast cracking {len(uncracked_hashes)} hashes")
        
        cracker = create_cracker_adapter()
        new_credentials = []
        
        # Use simple cracking method (faster, common passwords only)
        for hash_artifact in uncracked_hashes:
            stage_log.debug(f"Fast crack attempt for {hash_artifact.username}")
            
            # Use the simple method which uses common passwords
            success = cracker._crack_hash_simple(hash_artifact)
            
            if success and hash_artifact.cracked_password:
                stage_log.info(f"Fast cracked password for {hash_artifact.username}")
                
                credential = hash_artifact.to_credential()
                
                if credential:
                    new_credentials.append(credential)
                    context.add_credential(credential)
                    log_artifact_found("credential", f"{credential.username}:{credential.secret}")
                
                log_artifact_found("cracked_hash", f"{hash_artifact.username}")
        
        stage_log.info(f"Fast hash cracking completed, cracked {len(new_credentials)} passwords")
        return new_credentials


def run_batch_hash_crack(hash_artifacts: List[HashArtifact]) -> int:
    """
    Crack multiple hashes in batch (more efficient).
    
    Args:
        hash_artifacts: List of hashes to crack
        
    Returns:
        Number of hashes cracked
    """
    context = require_context()
    
    with StageLogger("batch_hash_crack") as stage_log:
        if not hash_artifacts:
            return 0
        
        uncracked_hashes = [h for h in hash_artifacts if not h.cracked_password]
        
        if not uncracked_hashes:
            return 0
        
        stage_log.info(f"Batch cracking {len(uncracked_hashes)} hashes")
        
        cracker = create_cracker_adapter()
        
        # Use batch cracking method
        cracked_count = cracker.crack_multiple_hashes(uncracked_hashes)
        
        # Convert cracked hashes to credentials
        for hash_artifact in uncracked_hashes:
            if hash_artifact.cracked_password:
                credential = hash_artifact.to_credential()
                
                if credential:
                    context.add_credential(credential)
                    log_artifact_found("credential", f"{credential.username}:{credential.secret}")
                
                log_artifact_found("cracked_hash", f"{hash_artifact.username}")
        
        stage_log.info(f"Batch cracking completed, cracked {cracked_count} passwords")
        return cracked_count


def get_crackable_hashes() -> List[HashArtifact]:
    """
    Get list of hashes that can potentially be cracked.
    
    Returns:
        List of hash artifacts suitable for cracking
    """
    context = require_context()
    hash_artifacts = context.get_artifacts_by_type(HashArtifact)
    
    # Filter to supported hash types and uncracked hashes
    cracker = create_cracker_adapter()
    
    crackable = []
    for hash_artifact in hash_artifacts:
        if hash_artifact.cracked_password:
            continue  # Already cracked
        
        # Check if hash type is supported
        if hash_artifact.algorithm.value in ['md5', 'sha1', 'sha256', 'sha512', 'ntlm', 'lm']:
            crackable.append(hash_artifact)
    
    return crackable


def prioritize_hashes(hash_artifacts: List[HashArtifact]) -> List[HashArtifact]:
    """
    Prioritize hashes for cracking based on various factors.
    
    Args:
        hash_artifacts: List of hash artifacts
        
    Returns:
        Sorted list with highest priority hashes first
    """
    def hash_priority(hash_artifact: HashArtifact) -> int:
        priority = 0
        
        # Prioritize by hash algorithm (easier first)
        if hash_artifact.algorithm.value == 'md5':
            priority += 100
        elif hash_artifact.algorithm.value == 'sha1':
            priority += 90
        elif hash_artifact.algorithm.value == 'ntlm':
            priority += 85
        elif hash_artifact.algorithm.value == 'lm':
            priority += 95  # LM is very weak
        elif hash_artifact.algorithm.value == 'sha256':
            priority += 70
        elif hash_artifact.algorithm.value == 'sha512':
            priority += 60
        
        # Prioritize usernames that suggest importance
        username_lower = hash_artifact.username.lower()
        important_users = ['admin', 'administrator', 'root', 'sa', 'service', 'system']
        
        if any(user in username_lower for user in important_users):
            priority += 50
        
        # Prioritize by source (some sources more reliable)
        if 'sqlite' in hash_artifact.source:
            priority += 20
        
        return priority
    
    # Sort by priority (highest first)
    return sorted(hash_artifacts, key=hash_priority, reverse=True)


def check_stage_requirements() -> bool:
    """Check if this stage can run."""
    # Basic cracking can always run (uses Python hashlib)
    return True


def get_stage_info() -> dict:
    """Get information about this stage."""
    return {
        "name": "hash_crack",
        "description": "Crack password hashes using various methods",
        "requirements": ["hashcat (optional)", "john (optional)"],
        "produces": ["Credential"],
        "consumes": ["HashArtifact"],
        "safe": True,
    }
