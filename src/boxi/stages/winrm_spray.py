"""
WinRM credential spraying and foothold stage.

Tests credentials against WinRM services and establishes foothold access.
"""

from typing import Dict, List, Optional

from boxi.adapters.winrm import create_adapter as create_winrm_adapter
from boxi.artifacts import Credential, Flag, Service
from boxi.logging_config import StageLogger, log_artifact_found, log_stage_skip
from boxi.runtime import require_context


def run_winrm_credential_spray(target: str) -> List[Credential]:
    """
    Spray credentials against WinRM services.
    
    Args:
        target: Target IP or hostname
        
    Returns:
        List of valid WinRM credentials
    """
    context = require_context()
    
    with StageLogger("winrm_spray", target) as stage_log:
        # Find WinRM services
        winrm_services = _find_winrm_services(context)
        
        if not winrm_services:
            log_stage_skip("winrm_spray", "No WinRM services found")
            return []
        
        # Get credentials to test
        credentials = context.get_valid_credentials()
        
        if not credentials:
            log_stage_skip("winrm_spray", "No credentials available to test")
            return []
        
        stage_log.info(f"Testing {len(credentials)} credentials against {len(winrm_services)} WinRM services")
        
        winrm = create_winrm_adapter()
        
        if not winrm.is_available():
            log_stage_skip("winrm_spray", "WinRM tools not available")
            return []
        
        valid_credentials = []
        
        for service in winrm_services:
            stage_log.info(f"Testing WinRM on {service.target_host}:{service.port}")
            
            # Test credentials against this service
            service_creds = winrm.test_multiple_credentials(
                service.target_host, credentials, service.port
            )
            
            for cred in service_creds:
                # Create new credential with WinRM source
                winrm_cred = Credential(
                    username=cred.username,
                    secret=cred.secret,
                    credential_type=cred.credential_type,
                    source=f"winrm_valid:{service.target_host}",
                    score=min(cred.score + 0.2, 1.0),  # Boost confidence significantly
                    domain=cred.domain
                )
                
                valid_credentials.append(winrm_cred)
                context.add_credential(winrm_cred)
                log_artifact_found("credential", f"WinRM {cred.username} on {service.target_host}")
                
                # Test for admin access
                if winrm.check_admin_access(service.target_host, cred, service.port):
                    stage_log.info(f"Admin access confirmed for {cred.username}")
                    log_artifact_found("admin_access", f"{cred.username}@{service.target_host}")
        
        stage_log.info(f"WinRM credential spray completed, found {len(valid_credentials)} valid credentials")
        return valid_credentials


def establish_winrm_foothold(target: str) -> Optional[Dict[str, str]]:
    """
    Establish foothold via WinRM with valid credentials.
    
    Args:
        target: Target IP or hostname
        
    Returns:
        Dictionary with foothold information if successful
    """
    context = require_context()
    
    with StageLogger("winrm_foothold", target) as stage_log:
        # Find WinRM services
        winrm_services = _find_winrm_services(context)
        
        if not winrm_services:
            log_stage_skip("winrm_foothold", "No WinRM services found")
            return None
        
        # Get valid WinRM credentials
        valid_creds = [c for c in context.get_valid_credentials() 
                      if "winrm" in c.source.lower()]
        
        if not valid_creds:
            log_stage_skip("winrm_foothold", "No valid WinRM credentials available")
            return None
        
        winrm = create_winrm_adapter()
        
        if not winrm.is_available():
            log_stage_skip("winrm_foothold", "WinRM tools not available")
            return None
        
        for service in winrm_services:
            for cred in valid_creds:
                stage_log.info(f"Establishing foothold on {service.target_host} with {cred.username}")
                
                # Get system information
                system_info = winrm.get_system_info(service.target_host, cred, service.port)
                
                if system_info:
                    stage_log.info(f"Foothold established on {service.target_host}")
                    
                    # Create foothold flag
                    foothold_flag = Flag(
                        path=f"winrm://{service.target_host}",
                        value=f"foothold_{cred.username}",
                        source=f"winrm_foothold:{service.target_host}",
                        metadata={
                            'username': cred.username,
                            'host': service.target_host,
                            'port': service.port,
                            'system_info': system_info
                        }
                    )
                    
                    context.add_flag(foothold_flag)
                    log_artifact_found("foothold", f"WinRM {cred.username}@{service.target_host}")
                    
                    # Return foothold info
                    return {
                        'host': service.target_host,
                        'port': str(service.port),
                        'username': cred.username,
                        'access_level': 'admin' if winrm.check_admin_access(
                            service.target_host, cred, service.port
                        ) else 'user',
                        'system_info': system_info
                    }
        
        stage_log.warning("Failed to establish WinRM foothold")
        return None


def run_winrm_enumeration(target: str) -> Dict[str, List[str]]:
    """
    Enumerate system information via WinRM.
    
    Args:
        target: Target IP or hostname
        
    Returns:
        Dictionary with enumeration results
    """
    context = require_context()
    
    with StageLogger("winrm_enum", target) as stage_log:
        # Find WinRM services and valid credentials
        winrm_services = _find_winrm_services(context)
        valid_creds = [c for c in context.get_valid_credentials() 
                      if "winrm" in c.source.lower()]
        
        if not winrm_services or not valid_creds:
            log_stage_skip("winrm_enum", "No WinRM services or credentials available")
            return {}
        
        winrm = create_winrm_adapter()
        
        if not winrm.is_available():
            log_stage_skip("winrm_enum", "WinRM tools not available")
            return {}
        
        enum_results = {}
        
        for service in winrm_services:
            for cred in valid_creds:
                stage_log.info(f"Enumerating {service.target_host} with {cred.username}")
                
                # Get system information
                system_info = winrm.get_system_info(service.target_host, cred, service.port)
                
                if system_info:
                    enum_results[f"{service.target_host}_{cred.username}"] = system_info
                    
                    # Log interesting findings
                    if 'hostname' in system_info:
                        log_artifact_found("hostname", system_info['hostname'])
                    
                    if 'domain_info' in system_info:
                        log_artifact_found("domain", system_info['domain_info'])
                
                # Enumerate shares
                shares = winrm.enumerate_shares(service.target_host, cred, service.port)
                
                if shares:
                    enum_results[f"{service.target_host}_{cred.username}_shares"] = shares
                    stage_log.info(f"Found {len(shares)} shares on {service.target_host}")
                    
                    for share in shares:
                        log_artifact_found("share", f"{service.target_host}\\{share}")
        
        stage_log.info(f"WinRM enumeration completed, gathered info for {len(enum_results)} sessions")
        return enum_results


def execute_winrm_commands(target: str, commands: List[str], 
                          force_exec: bool = False) -> Dict[str, str]:
    """
    Execute commands via WinRM.
    
    Args:
        target: Target IP or hostname
        commands: List of commands to execute
        force_exec: Override safe mode restrictions
        
    Returns:
        Dictionary mapping commands to their output
    """
    context = require_context()
    
    with StageLogger("winrm_exec", target) as stage_log:
        # Safety check
        from boxi.config import get_settings
        settings = get_settings()
        
        if settings.safe_mode and not force_exec:
            stage_log.warning("Command execution blocked by safe mode")
            return {}
        
        # Find WinRM services and credentials
        winrm_services = _find_winrm_services(context)
        valid_creds = [c for c in context.get_valid_credentials() 
                      if "winrm" in c.source.lower()]
        
        if not winrm_services or not valid_creds:
            return {}
        
        winrm = create_winrm_adapter()
        
        if not winrm.is_available():
            return {}
        
        results = {}
        
        # Use first valid credential for execution
        service = winrm_services[0]
        cred = valid_creds[0]
        
        stage_log.info(f"Executing {len(commands)} commands on {service.target_host}")
        
        for command in commands:
            stage_log.debug(f"Executing: {command}")
            
            output = winrm.execute_command(
                service.target_host, cred, command, 
                service.port, force_exec=force_exec
            )
            
            if output:
                results[command] = output
                stage_log.debug(f"Command output: {output[:100]}...")
            else:
                results[command] = ""
                stage_log.warning(f"Command failed: {command}")
        
        return results


def _find_winrm_services(context) -> List[Service]:
    """Find WinRM services in discovered services."""
    winrm_services = []
    
    # Look for explicit WinRM services
    services = context.get_open_services("winrm")
    winrm_services.extend(services)
    
    # Also check common WinRM ports
    all_services = context.get_open_services()
    winrm_ports = [5985, 5986]  # HTTP and HTTPS
    
    for service in all_services:
        if service.port in winrm_ports and service not in winrm_services:
            winrm_services.append(service)
    
    return winrm_services


def check_stage_requirements() -> bool:
    """Check if this stage can run."""
    winrm = create_winrm_adapter()
    return winrm.is_available()


def get_stage_info() -> dict:
    """Get information about this stage."""
    return {
        "name": "winrm_spray",
        "description": "Test credentials against WinRM and establish foothold",
        "requirements": ["evil-winrm"],
        "produces": ["Credential", "Flag"],
        "consumes": ["Service", "Credential"],
        "safe": True,  # Only tests auth by default
    }
