"""
WinRM adapter for Windows remote management operations.

Uses evil-winrm or other WinRM tools for remote command execution.
"""

from typing import List, Optional, Tuple

from boxi.artifacts import Credential
from boxi.config import get_settings
from boxi.logging_config import get_logger, log_tool_missing
from boxi.utils.process import ProcessError, ProcessTimeout, run

logger = get_logger(__name__)


class WinRMAdapter:
    """Adapter for WinRM operations."""
    
    def __init__(self):
        self.settings = get_settings()
        self.evil_winrm_path = self.settings.get_tool_path("evil-winrm")
        self.timeout = self.settings.winrm_timeout
    
    def is_available(self) -> bool:
        """Check if WinRM tools are available."""
        return self.evil_winrm_path is not None
    
    def test_credential(self, host: str, credential: Credential, port: int = 5985) -> bool:
        """
        Test WinRM authentication with credentials.
        
        Args:
            host: Target hostname/IP
            credential: Credential to test
            port: WinRM port (5985 for HTTP, 5986 for HTTPS)
            
        Returns:
            True if authentication succeeds
        """
        if not self.is_available():
            log_tool_missing("evil-winrm", "WinRM authentication")
            return False
        
        try:
            logger.debug(f"Testing WinRM auth to {host}:{port} with {credential.username}")
            
            cmd = [
                self.evil_winrm_path,
                "-i", host,
                "-P", str(port),
                "-u", credential.username,
                "-p", credential.secret,
                "-e", "whoami"  # Simple command to test auth
            ]
            
            result = run(cmd, timeout=self.timeout)
            
            # Check if authentication was successful
            # evil-winrm typically returns 0 on success
            if result.returncode == 0:
                logger.info(f"WinRM auth successful for {credential.username}@{host}")
                return True
            else:
                logger.debug(f"WinRM auth failed for {credential.username}@{host}")
                return False
                
        except (ProcessError, ProcessTimeout) as e:
            logger.debug(f"WinRM authentication test failed: {e}")
            return False
    
    def test_multiple_credentials(self, host: str, credentials: List[Credential],
                                port: int = 5985) -> List[Credential]:
        """
        Test multiple credentials against WinRM.
        
        Args:
            host: Target hostname/IP
            credentials: List of credentials to test
            port: WinRM port
            
        Returns:
            List of valid credentials
        """
        valid_creds = []
        
        for credential in credentials:
            if self.test_credential(host, credential, port):
                valid_creds.append(credential)
        
        logger.info(f"Found {len(valid_creds)} valid WinRM credentials for {host}")
        return valid_creds
    
    def execute_command(self, host: str, credential: Credential, command: str,
                       port: int = 5985, force_exec: bool = False) -> Optional[str]:
        """
        Execute a command via WinRM.
        
        Args:
            host: Target hostname/IP
            credential: Valid credential
            command: Command to execute
            port: WinRM port
            force_exec: Override safe mode for command execution
            
        Returns:
            Command output or None if failed
        """
        if not self.is_available():
            log_tool_missing("evil-winrm", "WinRM command execution")
            return None
        
        # Safety check - don't execute commands in safe mode unless forced
        if self.settings.safe_mode and not force_exec:
            logger.warning("Command execution blocked by safe mode")
            return None
        
        try:
            logger.debug(f"Executing WinRM command on {host}: {command}")
            
            cmd = [
                self.evil_winrm_path,
                "-i", host,
                "-P", str(port),
                "-u", credential.username,
                "-p", credential.secret,
                "-e", command
            ]
            
            result = run(cmd, timeout=self.timeout)
            
            if result.returncode == 0:
                logger.info(f"WinRM command executed successfully on {host}")
                return result.stdout
            else:
                logger.error(f"WinRM command failed on {host}")
                return None
                
        except (ProcessError, ProcessTimeout) as e:
            logger.error(f"WinRM command execution failed: {e}")
            return None
    
    def get_system_info(self, host: str, credential: Credential, port: int = 5985) -> dict:
        """
        Get basic system information via WinRM.
        
        Args:
            host: Target hostname/IP
            credential: Valid credential
            port: WinRM port
            
        Returns:
            Dictionary with system information
        """
        info = {}
        
        # Commands to gather system info (safe, read-only)
        commands = {
            'hostname': 'hostname',
            'whoami': 'whoami',
            'systeminfo': 'systeminfo',
            'os_version': 'ver',
            'domain_info': 'echo %USERDOMAIN%',
            'current_user': 'echo %USERNAME%',
        }
        
        for info_type, command in commands.items():
            try:
                output = self.execute_command(host, credential, command, port, force_exec=True)
                if output:
                    info[info_type] = output.strip()
            except Exception as e:
                logger.debug(f"Failed to get {info_type}: {e}")
                continue
        
        logger.info(f"Gathered system info from {host}")
        return info
    
    def check_admin_access(self, host: str, credential: Credential, port: int = 5985) -> bool:
        """
        Check if credentials have administrative access.
        
        Args:
            host: Target hostname/IP
            credential: Valid credential
            port: WinRM port
            
        Returns:
            True if user has admin access
        """
        try:
            # Try to access admin-only resource
            output = self.execute_command(
                host, credential, 
                'net session', 
                port, 
                force_exec=True
            )
            
            # If command succeeds, user likely has admin rights
            if output and 'access is denied' not in output.lower():
                logger.info(f"User {credential.username} has admin access on {host}")
                return True
            
        except Exception as e:
            logger.debug(f"Admin access check failed: {e}")
        
        return False
    
    def enumerate_shares(self, host: str, credential: Credential, port: int = 5985) -> List[str]:
        """
        Enumerate network shares via WinRM.
        
        Args:
            host: Target hostname/IP
            credential: Valid credential
            port: WinRM port
            
        Returns:
            List of share names
        """
        shares = []
        
        try:
            output = self.execute_command(
                host, credential,
                'net share',
                port,
                force_exec=True
            )
            
            if output:
                shares = self._parse_net_share_output(output)
                logger.info(f"Found {len(shares)} shares on {host}")
            
        except Exception as e:
            logger.debug(f"Share enumeration failed: {e}")
        
        return shares
    
    def download_file(self, host: str, credential: Credential, remote_path: str,
                     local_path: str, port: int = 5985) -> bool:
        """
        Download a file via WinRM.
        
        Args:
            host: Target hostname/IP
            credential: Valid credential
            remote_path: Path to file on remote system
            local_path: Local path to save file
            port: WinRM port
            
        Returns:
            True if download succeeds
        """
        if not self.is_available():
            return False
        
        # Safety check
        if self.settings.safe_mode:
            logger.warning("File download blocked by safe mode")
            return False
        
        try:
            logger.debug(f"Downloading {remote_path} from {host}")
            
            cmd = [
                self.evil_winrm_path,
                "-i", host,
                "-P", str(port),
                "-u", credential.username,
                "-p", credential.secret,
                "-d", remote_path,  # Download file
                "-l", local_path   # Local destination
            ]
            
            result = run(cmd, timeout=self.timeout)
            
            if result.returncode == 0:
                logger.info(f"Downloaded {remote_path} from {host}")
                return True
            
        except (ProcessError, ProcessTimeout) as e:
            logger.error(f"File download failed: {e}")
        
        return False
    
    def _parse_net_share_output(self, output: str) -> List[str]:
        """Parse 'net share' command output."""
        shares = []
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Skip header and empty lines
            if not line or 'Share name' in line or '---' in line:
                continue
            
            # Parse share line format: "ShareName    Type    Used as    Comment"
            parts = line.split()
            if len(parts) >= 2:
                share_name = parts[0]
                # Skip administrative shares in safe mode
                if self.settings.safe_mode and share_name.endswith('$'):
                    continue
                shares.append(share_name)
        
        return shares


def create_adapter() -> WinRMAdapter:
    """Create a WinRM adapter instance."""
    return WinRMAdapter()
