"""
FTP adapter for anonymous login testing and file enumeration.

Provides simple FTP operations for pentesting scenarios.
"""

import ftplib
import socket
from pathlib import Path
from typing import List, Optional, Tuple

from boxi.artifacts import Credential, FileArtifact
from boxi.config import get_settings
from boxi.logging_config import get_logger
from boxi.utils.fs import get_loot_dir, sanitize_path_component
from boxi.utils.process import sanitize_filename
from boxi.utils.text import parse_ftp_listing

logger = get_logger(__name__)


class FTPAdapter:
    """Adapter for FTP operations."""
    
    def __init__(self):
        self.settings = get_settings()
        self.timeout = self.settings.ftp_timeout
    
    def test_anonymous_login(self, host: str, port: int = 21) -> bool:
        """
        Test anonymous FTP login.
        
        Args:
            host: FTP server hostname/IP
            port: FTP server port
            
        Returns:
            True if anonymous login succeeds
        """
        try:
            logger.debug(f"Testing anonymous FTP login to {host}:{port}")
            
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            
            # Try anonymous login
            ftp.login('anonymous', 'anonymous@example.com')
            
            # If we get here, login succeeded
            ftp.quit()
            logger.info(f"Anonymous FTP login successful to {host}:{port}")
            return True
            
        except (ftplib.Error, socket.error, OSError) as e:
            logger.debug(f"Anonymous FTP login failed to {host}:{port}: {e}")
            return False
    
    def test_credential_login(self, host: str, credential: Credential, port: int = 21) -> bool:
        """
        Test FTP login with specific credentials.
        
        Args:
            host: FTP server hostname/IP
            credential: Credential to test
            port: FTP server port
            
        Returns:
            True if login succeeds
        """
        try:
            logger.debug(f"Testing FTP login to {host}:{port} with {credential.username}")
            
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            ftp.login(credential.username, credential.secret)
            
            ftp.quit()
            logger.info(f"FTP login successful to {host}:{port} with {credential.username}")
            return True
            
        except (ftplib.Error, socket.error, OSError) as e:
            logger.debug(f"FTP login failed to {host}:{port} with {credential.username}: {e}")
            return False
    
    def list_directory(self, host: str, path: str = "/", port: int = 21, 
                      credential: Optional[Credential] = None) -> List[dict]:
        """
        List FTP directory contents.
        
        Args:
            host: FTP server hostname/IP
            path: Directory path to list
            port: FTP server port
            credential: Optional credential (uses anonymous if None)
            
        Returns:
            List of file/directory information
        """
        try:
            logger.debug(f"Listing FTP directory {path} on {host}:{port}")
            
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            
            # Login
            if credential:
                ftp.login(credential.username, credential.secret)
            else:
                ftp.login('anonymous', 'anonymous@example.com')
            
            # Change to directory
            if path != "/":
                ftp.cwd(path)
            
            # Get directory listing
            lines = []
            ftp.retrlines('LIST', lines.append)
            
            ftp.quit()
            
            # Parse listing
            listing_text = '\n'.join(lines)
            files = parse_ftp_listing(listing_text)
            
            logger.info(f"Found {len(files)} items in FTP directory {path}")
            return files
            
        except (ftplib.Error, socket.error, OSError) as e:
            logger.error(f"FTP directory listing failed: {e}")
            return []
    
    def download_file(self, host: str, remote_path: str, local_dir: Optional[Path] = None,
                     port: int = 21, credential: Optional[Credential] = None) -> Optional[FileArtifact]:
        """
        Download a file from FTP server.
        
        Args:
            host: FTP server hostname/IP
            remote_path: Path to file on FTP server
            local_dir: Local directory to save file (uses loot dir if None)
            port: FTP server port
            credential: Optional credential (uses anonymous if None)
            
        Returns:
            FileArtifact for downloaded file, or None if failed
        """
        try:
            if local_dir is None:
                local_dir = get_loot_dir(host)
            
            # Sanitize filename
            filename = Path(remote_path).name
            safe_filename = sanitize_filename(filename)
            local_path = local_dir / safe_filename
            
            logger.debug(f"Downloading {remote_path} from {host}:{port} to {local_path}")
            
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            
            # Login
            if credential:
                ftp.login(credential.username, credential.secret)
            else:
                ftp.login('anonymous', 'anonymous@example.com')
            
            # Download file
            with open(local_path, 'wb') as f:
                ftp.retrbinary(f'RETR {remote_path}', f.write)
            
            ftp.quit()
            
            # Get file info
            file_size = local_path.stat().st_size
            
            # Create artifact
            artifact = FileArtifact(
                path=remote_path,
                name=filename,
                size=file_size,
                source=f"ftp://{host}:{port}",
                local_path=local_path
            )
            
            logger.info(f"Downloaded {filename} ({file_size} bytes) from FTP")
            return artifact
            
        except (ftplib.Error, socket.error, OSError) as e:
            logger.error(f"FTP file download failed: {e}")
            return None
    
    def download_all_files(self, host: str, remote_dir: str = "/", 
                          extensions: Optional[List[str]] = None,
                          port: int = 21, credential: Optional[Credential] = None) -> List[FileArtifact]:
        """
        Download all files from FTP directory matching extensions.
        
        Args:
            host: FTP server hostname/IP
            remote_dir: Remote directory to download from
            extensions: File extensions to download (None for all)
            port: FTP server port
            credential: Optional credential
            
        Returns:
            List of downloaded FileArtifacts
        """
        artifacts = []
        
        # Get directory listing
        files = self.list_directory(host, remote_dir, port, credential)
        
        for file_info in files:
            if file_info.get('type') == 'file':
                filename = file_info.get('name', '')
                
                # Check extension filter
                if extensions:
                    file_ext = Path(filename).suffix.lower()
                    if file_ext not in [ext.lower() for ext in extensions]:
                        continue
                
                # Download file
                remote_path = f"{remote_dir.rstrip('/')}/{filename}"
                artifact = self.download_file(host, remote_path, port=port, credential=credential)
                
                if artifact:
                    artifacts.append(artifact)
        
        logger.info(f"Downloaded {len(artifacts)} files from FTP")
        return artifacts
    
    def upload_file(self, host: str, local_path: Path, remote_path: str,
                   port: int = 21, credential: Optional[Credential] = None) -> bool:
        """
        Upload a file to FTP server.
        
        Args:
            host: FTP server hostname/IP
            local_path: Local file to upload
            remote_path: Remote path to upload to
            port: FTP server port
            credential: Optional credential
            
        Returns:
            True if upload succeeds
        """
        try:
            logger.debug(f"Uploading {local_path} to {host}:{port}:{remote_path}")
            
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            
            # Login
            if credential:
                ftp.login(credential.username, credential.secret)
            else:
                ftp.login('anonymous', 'anonymous@example.com')
            
            # Upload file
            with open(local_path, 'rb') as f:
                ftp.storbinary(f'STOR {remote_path}', f)
            
            ftp.quit()
            
            logger.info(f"Uploaded {local_path.name} to FTP")
            return True
            
        except (ftplib.Error, socket.error, OSError) as e:
            logger.error(f"FTP file upload failed: {e}")
            return False
    
    def get_server_info(self, host: str, port: int = 21) -> Optional[str]:
        """
        Get FTP server banner/info.
        
        Args:
            host: FTP server hostname/IP
            port: FTP server port
            
        Returns:
            Server banner string or None
        """
        try:
            logger.debug(f"Getting FTP server info from {host}:{port}")
            
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            
            banner = ftp.getwelcome()
            ftp.quit()
            
            logger.debug(f"FTP server banner: {banner}")
            return banner
            
        except (ftplib.Error, socket.error, OSError) as e:
            logger.debug(f"Failed to get FTP server info: {e}")
            return None


def create_adapter() -> FTPAdapter:
    """Create an FTP adapter instance."""
    return FTPAdapter()
