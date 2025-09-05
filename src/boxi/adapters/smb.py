"""
SMB adapter for SMB enumeration and file operations.

Uses smbclient or impacket tools for SMB operations.
"""

from pathlib import Path
from typing import List, Optional, Tuple

from boxi.artifacts import Credential, FileArtifact
from boxi.config import get_settings
from boxi.logging_config import get_logger, log_tool_missing
from boxi.utils.fs import get_loot_dir, sanitize_path_component
from boxi.utils.process import ProcessError, ProcessTimeout, run, sanitize_filename
from boxi.utils.text import parse_smb_shares

logger = get_logger(__name__)


class SMBAdapter:
    """Adapter for SMB operations."""
    
    def __init__(self):
        self.settings = get_settings()
        self.timeout = self.settings.smb_timeout
        
        # Prefer smbclient, fall back to impacket
        self.smbclient_path = self.settings.get_tool_path("smbclient")
        self.smbmap_path = self.settings.get_tool_path("smbmap")
    
    def is_available(self) -> bool:
        """Check if SMB tools are available."""
        return self.smbclient_path is not None or self.smbmap_path is not None
    
    def list_shares(self, host: str, credential: Optional[Credential] = None) -> List[str]:
        """
        List SMB shares on a host.
        
        Args:
            host: Target hostname/IP
            credential: Optional credential for authentication
            
        Returns:
            List of share names
        """
        if not self.is_available():
            log_tool_missing("smbclient/smbmap", "SMB enumeration")
            return []
        
        # Try smbclient first
        if self.smbclient_path:
            return self._list_shares_smbclient(host, credential)
        elif self.smbmap_path:
            return self._list_shares_smbmap(host, credential)
        
        return []
    
    def _list_shares_smbclient(self, host: str, credential: Optional[Credential] = None) -> List[str]:
        """List shares using smbclient."""
        cmd = [self.smbclient_path, "-L", host, "-N"]  # -N for no password
        
        if credential:
            cmd.extend(["-U", f"{credential.username}%{credential.secret}"])
        
        try:
            logger.debug(f"Listing SMB shares on {host}")
            result = run(cmd, timeout=self.timeout)
            
            shares = parse_smb_shares(result.stdout)
            logger.info(f"Found {len(shares)} SMB shares on {host}")
            return shares
            
        except (ProcessError, ProcessTimeout) as e:
            logger.error(f"SMB share enumeration failed: {e}")
            return []
    
    def _list_shares_smbmap(self, host: str, credential: Optional[Credential] = None) -> List[str]:
        """List shares using smbmap."""
        cmd = [self.smbmap_path, "-H", host]
        
        if credential:
            cmd.extend(["-u", credential.username, "-p", credential.secret])
        else:
            cmd.extend(["-u", "guest", "-p", ""])
        
        try:
            logger.debug(f"Listing SMB shares on {host} with smbmap")
            result = run(cmd, timeout=self.timeout)
            
            shares = self._parse_smbmap_output(result.stdout)
            logger.info(f"Found {len(shares)} SMB shares on {host}")
            return shares
            
        except (ProcessError, ProcessTimeout) as e:
            logger.error(f"SMB share enumeration with smbmap failed: {e}")
            return []
    
    def test_share_access(self, host: str, share: str, 
                         credential: Optional[Credential] = None) -> Tuple[bool, bool]:
        """
        Test read/write access to an SMB share.
        
        Args:
            host: Target hostname/IP
            share: Share name
            credential: Optional credential
            
        Returns:
            Tuple of (can_read, can_write)
        """
        if not self.smbclient_path:
            return (False, False)
        
        # Test read access
        can_read = self._test_share_read(host, share, credential)
        
        # Test write access (only if safe mode is disabled)
        can_write = False
        if not self.settings.safe_mode:
            can_write = self._test_share_write(host, share, credential)
        
        return (can_read, can_write)
    
    def _test_share_read(self, host: str, share: str, credential: Optional[Credential] = None) -> bool:
        """Test read access to a share."""
        cmd = [self.smbclient_path, f"//{host}/{share}", "-c", "ls"]
        
        if credential:
            cmd.extend(["-U", f"{credential.username}%{credential.secret}"])
        else:
            cmd.append("-N")
        
        try:
            logger.debug(f"Testing read access to {host}/{share}")
            result = run(cmd, timeout=self.timeout)
            
            # If ls command succeeds, we have read access
            return result.returncode == 0
            
        except (ProcessError, ProcessTimeout):
            return False
    
    def _test_share_write(self, host: str, share: str, credential: Optional[Credential] = None) -> bool:
        """Test write access to a share."""
        # Create a small test file
        import tempfile
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
            temp_file.write("boxi test file")
            temp_path = temp_file.name
        
        try:
            # Try to upload the test file
            cmd = [
                self.smbclient_path, f"//{host}/{share}",
                "-c", f"put {temp_path} boxi_test.txt; del boxi_test.txt"
            ]
            
            if credential:
                cmd.extend(["-U", f"{credential.username}%{credential.secret}"])
            else:
                cmd.append("-N")
            
            logger.debug(f"Testing write access to {host}/{share}")
            result = run(cmd, timeout=self.timeout)
            
            return result.returncode == 0
            
        except (ProcessError, ProcessTimeout):
            return False
        finally:
            # Clean up test file
            Path(temp_path).unlink(missing_ok=True)
    
    def list_share_contents(self, host: str, share: str, path: str = "",
                           credential: Optional[Credential] = None) -> List[dict]:
        """
        List contents of an SMB share directory.
        
        Args:
            host: Target hostname/IP
            share: Share name
            path: Directory path within share
            credential: Optional credential
            
        Returns:
            List of file/directory information
        """
        if not self.smbclient_path:
            return []
        
        # Build ls command
        ls_cmd = f"cd {path}; ls" if path else "ls"
        cmd = [self.smbclient_path, f"//{host}/{share}", "-c", ls_cmd]
        
        if credential:
            cmd.extend(["-U", f"{credential.username}%{credential.secret}"])
        else:
            cmd.append("-N")
        
        try:
            logger.debug(f"Listing contents of {host}/{share}/{path}")
            result = run(cmd, timeout=self.timeout)
            
            files = self._parse_smb_listing(result.stdout)
            logger.info(f"Found {len(files)} items in {host}/{share}/{path}")
            return files
            
        except (ProcessError, ProcessTimeout) as e:
            logger.error(f"SMB directory listing failed: {e}")
            return []
    
    def download_file(self, host: str, share: str, remote_path: str,
                     local_dir: Optional[Path] = None,
                     credential: Optional[Credential] = None) -> Optional[FileArtifact]:
        """
        Download a file from SMB share.
        
        Args:
            host: Target hostname/IP
            share: Share name
            remote_path: Path to file within share
            local_dir: Local directory to save file
            credential: Optional credential
            
        Returns:
            FileArtifact for downloaded file, or None if failed
        """
        if not self.smbclient_path:
            return None
        
        if local_dir is None:
            local_dir = get_loot_dir(host)
        
        # Sanitize filename
        filename = Path(remote_path).name
        safe_filename = sanitize_filename(filename)
        local_path = local_dir / safe_filename
        
        cmd = [
            self.smbclient_path, f"//{host}/{share}",
            "-c", f"get {remote_path} {local_path}"
        ]
        
        if credential:
            cmd.extend(["-U", f"{credential.username}%{credential.secret}"])
        else:
            cmd.append("-N")
        
        try:
            logger.debug(f"Downloading {remote_path} from {host}/{share}")
            result = run(cmd, timeout=self.timeout)
            
            if result.returncode == 0 and local_path.exists():
                file_size = local_path.stat().st_size
                
                artifact = FileArtifact(
                    path=f"//{host}/{share}/{remote_path}",
                    name=filename,
                    size=file_size,
                    source=f"smb://{host}/{share}",
                    local_path=local_path
                )
                
                logger.info(f"Downloaded {filename} ({file_size} bytes) from SMB")
                return artifact
            
        except (ProcessError, ProcessTimeout) as e:
            logger.error(f"SMB file download failed: {e}")
        
        return None
    
    def download_files_by_extension(self, host: str, share: str, extensions: List[str],
                                   credential: Optional[Credential] = None) -> List[FileArtifact]:
        """
        Download all files matching extensions from a share.
        
        Args:
            host: Target hostname/IP
            share: Share name
            extensions: File extensions to download
            credential: Optional credential
            
        Returns:
            List of downloaded FileArtifacts
        """
        artifacts = []
        
        # Get share contents
        files = self.list_share_contents(host, share, credential=credential)
        
        for file_info in files:
            if file_info.get('type') == 'file':
                filename = file_info.get('name', '')
                file_ext = Path(filename).suffix.lower()
                
                if file_ext in [ext.lower() for ext in extensions]:
                    artifact = self.download_file(host, share, filename, credential=credential)
                    if artifact:
                        artifacts.append(artifact)
        
        logger.info(f"Downloaded {len(artifacts)} files from SMB share")
        return artifacts
    
    def _parse_smbmap_output(self, output: str) -> List[str]:
        """Parse smbmap output for share names."""
        shares = []
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Look for share entries in smbmap output
            if '\\\\' in line and 'Disk' in line:
                parts = line.split()
                if len(parts) >= 2:
                    share_path = parts[0]
                    share_name = share_path.split('\\')[-1]
                    if share_name:
                        shares.append(share_name)
        
        return shares
    
    def _parse_smb_listing(self, output: str) -> List[dict]:
        """Parse SMB directory listing output."""
        files = []
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Skip empty lines and headers
            if not line or 'Domain=' in line or 'blocks available' in line:
                continue
            
            # Parse file entries
            # Format: filename    attributes    size    date
            parts = line.split()
            if len(parts) >= 4:
                filename = parts[0]
                
                # Skip . and .. entries
                if filename in ['.', '..']:
                    continue
                
                # Determine if it's a directory
                attributes = parts[1] if len(parts) > 1 else ''
                is_directory = 'D' in attributes
                
                # Try to extract size
                size = 0
                try:
                    size = int(parts[2]) if not is_directory else 0
                except (ValueError, IndexError):
                    pass
                
                files.append({
                    'name': filename,
                    'type': 'directory' if is_directory else 'file',
                    'size': str(size),
                })
        
        return files


def create_adapter() -> SMBAdapter:
    """Create an SMB adapter instance."""
    return SMBAdapter()
