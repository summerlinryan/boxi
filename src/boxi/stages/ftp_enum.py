"""
FTP enumeration stage for anonymous access and file discovery.

Tests FTP services for anonymous access and downloads interesting files.
"""

from typing import List

from boxi.adapters.ftp import create_adapter as create_ftp_adapter
from boxi.artifacts import Credential, FileArtifact, Service, ServiceState
from boxi.logging_config import StageLogger, log_artifact_found, log_stage_skip
from boxi.runtime import require_context


def run_ftp_enumeration(target: str) -> List[FileArtifact]:
    """
    Enumerate FTP services and download interesting files.
    
    Args:
        target: Target IP or hostname
        
    Returns:
        List of downloaded file artifacts
    """
    context = require_context()
    
    with StageLogger("ftp_enum", target) as stage_log:
        # Find FTP services
        ftp_services = context.get_open_services("ftp")
        if not ftp_services:
            # Also check for services on port 21
            all_services = context.get_open_services()
            ftp_services = [s for s in all_services if s.port == 21]
        
        if not ftp_services:
            log_stage_skip("ftp_enum", "No FTP services found")
            return []
        
        stage_log.info(f"Found {len(ftp_services)} FTP services to enumerate")
        
        ftp = create_ftp_adapter()
        all_artifacts = []
        
        for service in ftp_services:
            stage_log.info(f"Enumerating FTP on {service.target_host}:{service.port}")
            
            # Test anonymous access
            if ftp.test_anonymous_login(service.target_host, service.port):
                stage_log.info("Anonymous FTP access available")
                
                # Create anonymous credential for tracking
                anon_cred = Credential(
                    username="anonymous",
                    secret="anonymous@example.com",
                    source="ftp_anonymous",
                    score=1.0
                )
                context.add_credential(anon_cred)
                
                # Download interesting files
                artifacts = _download_interesting_files(
                    ftp, service.target_host, service.port, stage_log
                )
                all_artifacts.extend(artifacts)
                
                # Add artifacts to context
                for artifact in artifacts:
                    context.add_file(artifact)
            else:
                stage_log.info("Anonymous FTP access not available")
                
                # Try known credentials if any
                credentials = context.get_valid_credentials()
                if credentials:
                    for cred in credentials:
                        if ftp.test_credential_login(service.target_host, cred, service.port):
                            stage_log.info(f"FTP access with {cred.username}")
                            
                            artifacts = _download_interesting_files(
                                ftp, service.target_host, service.port, stage_log, cred
                            )
                            all_artifacts.extend(artifacts)
                            
                            for artifact in artifacts:
                                context.add_file(artifact)
                            break
        
        stage_log.info(f"FTP enumeration completed, downloaded {len(all_artifacts)} files")
        return all_artifacts


def _download_interesting_files(ftp_adapter, host: str, port: int, stage_log: StageLogger,
                               credential=None) -> List[FileArtifact]:
    """Download interesting files from FTP server."""
    artifacts = []
    
    try:
        # List root directory
        files = ftp_adapter.list_directory(host, "/", port, credential)
        
        if not files:
            stage_log.info("No files found in FTP root directory")
            return artifacts
        
        stage_log.info(f"Found {len(files)} items in FTP root")
        
        # Define interesting file extensions
        interesting_extensions = ['.pdf', '.txt', '.doc', '.docx', '.xls', '.xlsx', 
                                '.zip', '.rar', '.7z', '.sql', '.db', '.sqlite', 
                                '.conf', '.config', '.log', '.xml', '.json']
        
        # Download files with interesting extensions
        for file_info in files:
            if file_info.get('type') == 'file':
                filename = file_info.get('name', '')
                
                # Check if file has interesting extension
                for ext in interesting_extensions:
                    if filename.lower().endswith(ext.lower()):
                        stage_log.info(f"Downloading interesting file: {filename}")
                        
                        artifact = ftp_adapter.download_file(
                            host, filename, port=port, credential=credential
                        )
                        
                        if artifact:
                            artifacts.append(artifact)
                            log_artifact_found("file", f"{filename} ({artifact.size} bytes)")
                        break
        
        # Also look for directories to explore
        directories = [f for f in files if f.get('type') == 'directory']
        for dir_info in directories:
            dirname = dir_info.get('name', '')
            
            # Skip system directories
            if dirname in ['.', '..', 'proc', 'sys', 'dev']:
                continue
            
            stage_log.debug(f"Exploring directory: {dirname}")
            
            # List directory contents
            dir_files = ftp_adapter.list_directory(host, dirname, port, credential)
            
            for file_info in dir_files:
                if file_info.get('type') == 'file':
                    filename = file_info.get('name', '')
                    
                    # Check for interesting files
                    for ext in interesting_extensions:
                        if filename.lower().endswith(ext.lower()):
                            remote_path = f"{dirname}/{filename}"
                            stage_log.info(f"Downloading: {remote_path}")
                            
                            artifact = ftp_adapter.download_file(
                                host, remote_path, port=port, credential=credential
                            )
                            
                            if artifact:
                                artifacts.append(artifact)
                                log_artifact_found("file", f"{remote_path} ({artifact.size} bytes)")
                            break
    
    except Exception as e:
        stage_log.error(f"Error downloading FTP files: {e}")
    
    return artifacts


def test_ftp_credentials(target: str, credentials: List[Credential]) -> List[Credential]:
    """
    Test a list of credentials against FTP services.
    
    Args:
        target: Target IP or hostname
        credentials: List of credentials to test
        
    Returns:
        List of valid credentials
    """
    context = require_context()
    
    with StageLogger("ftp_cred_test", target) as stage_log:
        # Find FTP services
        ftp_services = context.get_open_services("ftp")
        if not ftp_services:
            all_services = context.get_open_services()
            ftp_services = [s for s in all_services if s.port == 21]
        
        if not ftp_services:
            log_stage_skip("ftp_cred_test", "No FTP services found")
            return []
        
        ftp = create_ftp_adapter()
        valid_creds = []
        
        for service in ftp_services:
            stage_log.info(f"Testing credentials against FTP on {service.target_host}:{service.port}")
            
            for cred in credentials:
                if ftp.test_credential_login(service.target_host, cred, service.port):
                    stage_log.info(f"Valid FTP credential: {cred.username}")
                    valid_creds.append(cred)
                    log_artifact_found("credential", f"FTP {cred.username}:{cred.secret}")
        
        return valid_creds


def check_stage_requirements() -> bool:
    """Check if this stage can run."""
    # FTP adapter uses built-in Python ftplib, so always available
    return True


def get_stage_info() -> dict:
    """Get information about this stage."""
    return {
        "name": "ftp_enum",
        "description": "Enumerate FTP services and download interesting files",
        "requirements": [],
        "produces": ["FileArtifact", "Credential"],
        "consumes": ["Service"],
        "safe": True,
    }
