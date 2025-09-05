"""
SMB credential spraying and enumeration stage.

Tests credentials against SMB services and enumerates accessible shares.
"""

from typing import List, Tuple

from boxi.adapters.smb import create_adapter as create_smb_adapter
from boxi.artifacts import Credential, Service
from boxi.logging_config import StageLogger, log_artifact_found, log_stage_skip
from boxi.runtime import require_context


def run_smb_credential_spray(target: str) -> List[Credential]:
    """
    Spray credentials against SMB services.
    
    Args:
        target: Target IP or hostname
        
    Returns:
        List of valid credentials
    """
    context = require_context()
    
    with StageLogger("smb_spray", target) as stage_log:
        # Find SMB services
        smb_services = _find_smb_services(context)
        
        if not smb_services:
            log_stage_skip("smb_spray", "No SMB services found")
            return []
        
        # Get credentials to test
        credentials = context.get_valid_credentials()
        
        if not credentials:
            log_stage_skip("smb_spray", "No credentials available to test")
            return []
        
        stage_log.info(f"Testing {len(credentials)} credentials against {len(smb_services)} SMB services")
        
        smb = create_smb_adapter()
        
        if not smb.is_available():
            log_stage_skip("smb_spray", "SMB tools not available")
            return []
        
        valid_credentials = []
        
        for service in smb_services:
            stage_log.info(f"Testing SMB on {service.target_host}:{service.port}")
            
            # Test each credential
            for cred in credentials:
                stage_log.debug(f"Testing {cred.username} against {service.target_host}")
                
                # Get shares to test access
                shares = smb.list_shares(service.target_host, cred)
                
                if shares:
                    stage_log.info(f"Valid SMB credential: {cred.username}")
                    
                    # Create new credential with SMB source
                    smb_cred = Credential(
                        username=cred.username,
                        secret=cred.secret,
                        credential_type=cred.credential_type,
                        source=f"smb_valid:{service.target_host}",
                        score=min(cred.score + 0.1, 1.0),  # Boost confidence
                        domain=cred.domain
                    )
                    
                    valid_credentials.append(smb_cred)
                    context.add_credential(smb_cred)
                    log_artifact_found("credential", f"SMB {cred.username} on {service.target_host}")
                    
                    # Test share access
                    _test_share_access(smb, service.target_host, shares, cred, stage_log)
        
        stage_log.info(f"SMB credential spray completed, found {len(valid_credentials)} valid credentials")
        return valid_credentials


def run_smb_enumeration(target: str) -> List[str]:
    """
    Enumerate SMB shares and test access.
    
    Args:
        target: Target IP or hostname
        
    Returns:
        List of accessible share names
    """
    context = require_context()
    
    with StageLogger("smb_enum", target) as stage_log:
        smb_services = _find_smb_services(context)
        
        if not smb_services:
            log_stage_skip("smb_enum", "No SMB services found")
            return []
        
        smb = create_smb_adapter()
        
        if not smb.is_available():
            log_stage_skip("smb_enum", "SMB tools not available")
            return []
        
        accessible_shares = []
        
        for service in smb_services:
            stage_log.info(f"Enumerating SMB shares on {service.target_host}")
            
            # Try anonymous access first
            shares = smb.list_shares(service.target_host)
            
            if shares:
                stage_log.info(f"Found {len(shares)} shares via anonymous access")
                accessible_shares.extend(shares)
                
                # Test anonymous read access
                for share in shares:
                    can_read, can_write = smb.test_share_access(service.target_host, share)
                    
                    if can_read:
                        stage_log.info(f"Anonymous read access to {share}")
                        log_artifact_found("share_access", f"{service.target_host}\\{share} (read)")
                    
                    if can_write:
                        stage_log.info(f"Anonymous write access to {share}")
                        log_artifact_found("share_access", f"{service.target_host}\\{share} (write)")
            
            # Try with valid credentials
            valid_creds = [c for c in context.get_valid_credentials() 
                          if "smb" in c.source.lower()]
            
            for cred in valid_creds:
                stage_log.debug(f"Enumerating with credential {cred.username}")
                
                shares = smb.list_shares(service.target_host, cred)
                
                if shares:
                    for share in shares:
                        if share not in accessible_shares:
                            accessible_shares.append(share)
                        
                        # Test access with credentials
                        can_read, can_write = smb.test_share_access(
                            service.target_host, share, cred
                        )
                        
                        if can_read:
                            stage_log.info(f"Read access to {share} with {cred.username}")
                        
                        if can_write:
                            stage_log.info(f"Write access to {share} with {cred.username}")
        
        stage_log.info(f"SMB enumeration completed, found {len(accessible_shares)} accessible shares")
        return accessible_shares


def _find_smb_services(context) -> List[Service]:
    """Find SMB services in discovered services."""
    smb_services = []
    
    # Look for explicit SMB services
    services = context.get_open_services("smb")
    smb_services.extend(services)
    
    # Also check common SMB ports
    all_services = context.get_open_services()
    smb_ports = [139, 445]
    
    for service in all_services:
        if service.port in smb_ports and service not in smb_services:
            smb_services.append(service)
    
    return smb_services


def _test_share_access(smb_adapter, host: str, shares: List[str], 
                      credential: Credential, stage_log: StageLogger) -> None:
    """Test access to discovered shares."""
    for share in shares:
        try:
            can_read, can_write = smb_adapter.test_share_access(host, share, credential)
            
            access_info = []
            if can_read:
                access_info.append("read")
            if can_write:
                access_info.append("write")
            
            if access_info:
                access_str = "/".join(access_info)
                stage_log.info(f"Share access: {host}\\{share} ({access_str}) with {credential.username}")
                log_artifact_found("share_access", f"{host}\\{share} ({access_str})")
        
        except Exception as e:
            stage_log.debug(f"Error testing share {share}: {e}")


def test_null_sessions(target: str) -> bool:
    """
    Test for null session access to SMB.
    
    Args:
        target: Target IP or hostname
        
    Returns:
        True if null sessions are allowed
    """
    context = require_context()
    
    with StageLogger("smb_null_test", target) as stage_log:
        smb_services = _find_smb_services(context)
        
        if not smb_services:
            return False
        
        smb = create_smb_adapter()
        
        if not smb.is_available():
            return False
        
        for service in smb_services:
            stage_log.debug(f"Testing null session on {service.target_host}")
            
            # Try to list shares without credentials
            shares = smb.list_shares(service.target_host)
            
            if shares:
                stage_log.info(f"Null session allowed on {service.target_host}")
                log_artifact_found("vulnerability", f"SMB null session on {service.target_host}")
                return True
        
        return False


def check_stage_requirements() -> bool:
    """Check if this stage can run."""
    smb = create_smb_adapter()
    return smb.is_available()


def get_stage_info() -> dict:
    """Get information about this stage."""
    return {
        "name": "smb_spray",
        "description": "Test credentials against SMB services and enumerate shares",
        "requirements": ["smbclient or smbmap"],
        "produces": ["Credential"],
        "consumes": ["Service", "Credential"],
        "safe": True,
    }
