"""
Filesystem utilities for boxi.

Handles workspace management, file operations, and path utilities
for storing artifacts and run data.
"""

import hashlib
import shutil
from pathlib import Path
from typing import List, Optional, Union

from boxi.config import get_settings


def ensure_dir(path: Union[str, Path]) -> Path:
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        path: Directory path to ensure
        
    Returns:
        Path object for the directory
    """
    path_obj = Path(path)
    path_obj.mkdir(parents=True, exist_ok=True)
    return path_obj


def get_workspace_dir() -> Path:
    """Get the main workspace directory."""
    settings = get_settings()
    return settings.workspace_root


def get_loot_dir(target: Optional[str] = None) -> Path:
    """
    Get the loot directory for storing downloaded files.
    
    Args:
        target: Optional target identifier for subdirectory
        
    Returns:
        Path to loot directory
    """
    settings = get_settings()
    loot_dir = settings.loot_dir
    
    if target:
        # Sanitize target for filesystem
        safe_target = sanitize_path_component(target)
        loot_dir = loot_dir / safe_target
    
    ensure_dir(loot_dir)
    return loot_dir


def get_run_dir(target: str) -> Path:
    """
    Get or create a run directory for the target.
    
    Args:
        target: Target identifier
        
    Returns:
        Path to run directory
    """
    settings = get_settings()
    return settings.create_run_dir(target)


def sanitize_path_component(component: str) -> str:
    """
    Sanitize a string to be safe as a path component.
    
    Args:
        component: String to sanitize
        
    Returns:
        Sanitized string safe for filesystem use
    """
    import re
    # Replace dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', component)
    # Remove control characters
    sanitized = ''.join(c for c in sanitized if ord(c) >= 32)
    # Replace multiple underscores with single
    sanitized = re.sub(r'_+', '_', sanitized)
    # Strip underscores from ends
    sanitized = sanitized.strip('_')
    # Ensure not empty
    if not sanitized:
        sanitized = "unnamed"
    # Limit length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    return sanitized


def calculate_file_hash(file_path: Union[str, Path], algorithm: str = "md5") -> str:
    """
    Calculate hash of a file.
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Hex digest of file hash
    """
    hash_obj = hashlib.new(algorithm.lower())
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_obj.update(chunk)
    
    return hash_obj.hexdigest()


def safe_copy_file(src: Union[str, Path], dst: Union[str, Path]) -> Path:
    """
    Safely copy a file, ensuring destination directory exists.
    
    Args:
        src: Source file path
        dst: Destination file path
        
    Returns:
        Path to copied file
    """
    src_path = Path(src)
    dst_path = Path(dst)
    
    # Ensure destination directory exists
    ensure_dir(dst_path.parent)
    
    # Copy file
    shutil.copy2(src_path, dst_path)
    
    return dst_path


def find_files_by_extension(
    directory: Union[str, Path], 
    extensions: List[str],
    recursive: bool = True
) -> List[Path]:
    """
    Find files by extension in a directory.
    
    Args:
        directory: Directory to search
        extensions: List of extensions (with or without leading dot)
        recursive: Whether to search recursively
        
    Returns:
        List of matching file paths
    """
    dir_path = Path(directory)
    
    # Normalize extensions
    normalized_exts = []
    for ext in extensions:
        if not ext.startswith('.'):
            ext = '.' + ext
        normalized_exts.append(ext.lower())
    
    files = []
    pattern = "**/*" if recursive else "*"
    
    for file_path in dir_path.glob(pattern):
        if file_path.is_file() and file_path.suffix.lower() in normalized_exts:
            files.append(file_path)
    
    return files


def get_file_size(file_path: Union[str, Path]) -> int:
    """
    Get file size in bytes.
    
    Args:
        file_path: Path to file
        
    Returns:
        File size in bytes
    """
    return Path(file_path).stat().st_size


def get_mime_type(file_path: Union[str, Path]) -> Optional[str]:
    """
    Get MIME type of a file.
    
    Args:
        file_path: Path to file
        
    Returns:
        MIME type string or None if detection fails
    """
    try:
        import mimetypes
        mime_type, _ = mimetypes.guess_type(str(file_path))
        return mime_type
    except Exception:
        return None


def create_temp_file(suffix: str = "", prefix: str = "boxi_") -> Path:
    """
    Create a temporary file in the workspace.
    
    Args:
        suffix: File suffix (extension)
        prefix: File prefix
        
    Returns:
        Path to temporary file
    """
    import tempfile
    
    temp_dir = get_workspace_dir() / "temp"
    ensure_dir(temp_dir)
    
    fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=temp_dir)
    # Close the file descriptor since we just want the path
    import os
    os.close(fd)
    
    return Path(temp_path)


def cleanup_old_files(directory: Union[str, Path], max_age_days: int = 30) -> int:
    """
    Clean up old files from a directory.
    
    Args:
        directory: Directory to clean
        max_age_days: Maximum age in days
        
    Returns:
        Number of files deleted
    """
    import time
    
    dir_path = Path(directory)
    if not dir_path.exists():
        return 0
    
    current_time = time.time()
    max_age_seconds = max_age_days * 24 * 60 * 60
    deleted_count = 0
    
    for file_path in dir_path.rglob("*"):
        if file_path.is_file():
            file_age = current_time - file_path.stat().st_mtime
            if file_age > max_age_seconds:
                try:
                    file_path.unlink()
                    deleted_count += 1
                except OSError:
                    # Skip files we can't delete
                    continue
    
    return deleted_count


def read_file_lines(file_path: Union[str, Path], max_lines: Optional[int] = None) -> List[str]:
    """
    Read lines from a file, with optional limit.
    
    Args:
        file_path: Path to file
        max_lines: Maximum number of lines to read
        
    Returns:
        List of lines (without newlines)
    """
    lines = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if max_lines and i >= max_lines:
                    break
                lines.append(line.rstrip('\n\r'))
    except Exception:
        # Return empty list if file can't be read
        pass
    
    return lines


def write_file_lines(file_path: Union[str, Path], lines: List[str]) -> None:
    """
    Write lines to a file.
    
    Args:
        file_path: Path to file
        lines: Lines to write
    """
    path_obj = Path(file_path)
    ensure_dir(path_obj.parent)
    
    with open(path_obj, 'w', encoding='utf-8') as f:
        for line in lines:
            f.write(line + '\n')


def is_text_file(file_path: Union[str, Path]) -> bool:
    """
    Check if a file appears to be a text file.
    
    Args:
        file_path: Path to file
        
    Returns:
        True if file appears to be text
    """
    try:
        with open(file_path, 'rb') as f:
            # Read first chunk
            chunk = f.read(8192)
            
        # Check for null bytes (common in binary files)
        if b'\x00' in chunk:
            return False
            
        # Try to decode as UTF-8
        try:
            chunk.decode('utf-8')
            return True
        except UnicodeDecodeError:
            return False
            
    except Exception:
        return False
