"""
Safe subprocess wrapper utilities.

Provides secure command execution with timeouts, logging, and proper error handling.
All external tool interactions should go through these functions.
"""

import asyncio
import subprocess
import time
from typing import List, Optional, Tuple, Union

from boxi.logging_config import log_command, log_command_result


class ProcessError(Exception):
    """Raised when a process execution fails."""
    
    def __init__(self, cmd: List[str], returncode: int, stdout: str, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(f"Command failed with exit code {returncode}: {' '.join(cmd)}")


class ProcessTimeout(Exception):
    """Raised when a process times out."""
    
    def __init__(self, cmd: List[str], timeout: int):
        self.cmd = cmd
        self.timeout = timeout
        super().__init__(f"Command timed out after {timeout}s: {' '.join(cmd)}")


def run(
    cmd: Union[str, List[str]],
    timeout: Optional[int] = 30,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    check: bool = False,
    capture_output: bool = True,
    text: bool = True,
    input_data: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """
    Run a command with safe defaults and logging.
    
    Args:
        cmd: Command to run (string or list)
        timeout: Timeout in seconds (None for no timeout)
        cwd: Working directory
        env: Environment variables
        check: Raise exception on non-zero exit
        capture_output: Capture stdout/stderr
        text: Return output as text (not bytes)
        input_data: Data to send to stdin
    
    Returns:
        CompletedProcess instance
        
    Raises:
        ProcessError: If check=True and command fails
        ProcessTimeout: If command times out
    """
    # Convert string command to list
    if isinstance(cmd, str):
        cmd = cmd.split()
    
    # Log the command
    log_command(cmd, timeout)
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            cmd,
            timeout=timeout,
            cwd=cwd,
            env=env,
            capture_output=capture_output,
            text=text,
            input=input_data,
        )
        
        duration = time.time() - start_time
        
        # Log the result
        log_command_result(
            cmd, result.returncode, 
            result.stdout if capture_output else "",
            result.stderr if capture_output else "",
            duration
        )
        
        # Raise exception if requested and command failed
        if check and result.returncode != 0:
            raise ProcessError(cmd, result.returncode, result.stdout, result.stderr)
        
        return result
        
    except subprocess.TimeoutExpired as e:
        duration = time.time() - start_time
        log_command_result(cmd, -1, "", "Process timed out", duration)
        raise ProcessTimeout(cmd, timeout or 0) from e


async def run_async(
    cmd: Union[str, List[str]],
    timeout: Optional[int] = 30,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    check: bool = False,
    input_data: Optional[str] = None,
) -> Tuple[int, str, str]:
    """
    Run a command asynchronously.
    
    Args:
        cmd: Command to run (string or list)
        timeout: Timeout in seconds
        cwd: Working directory  
        env: Environment variables
        check: Raise exception on non-zero exit
        input_data: Data to send to stdin
    
    Returns:
        Tuple of (returncode, stdout, stderr)
        
    Raises:
        ProcessError: If check=True and command fails
        ProcessTimeout: If command times out
    """
    # Convert string command to list
    if isinstance(cmd, str):
        cmd = cmd.split()
    
    log_command(cmd, timeout)
    start_time = time.time()
    
    try:
        # Create subprocess
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data else None,
            cwd=cwd,
            env=env,
        )
        
        # Wait for completion with timeout
        stdout_data, stderr_data = await asyncio.wait_for(
            process.communicate(input=input_data.encode() if input_data else None),
            timeout=timeout
        )
        
        duration = time.time() - start_time
        stdout = stdout_data.decode() if stdout_data else ""
        stderr = stderr_data.decode() if stderr_data else ""
        
        log_command_result(cmd, process.returncode or 0, stdout, stderr, duration)
        
        if check and process.returncode != 0:
            raise ProcessError(cmd, process.returncode or 0, stdout, stderr)
        
        return process.returncode or 0, stdout, stderr
        
    except asyncio.TimeoutError as e:
        duration = time.time() - start_time
        log_command_result(cmd, -1, "", "Process timed out", duration)
        raise ProcessTimeout(cmd, timeout or 0) from e


def check_tool_available(tool_name: str) -> bool:
    """
    Check if a tool is available in PATH.
    
    Args:
        tool_name: Name of the tool to check
        
    Returns:
        True if tool is available, False otherwise
    """
    try:
        result = run([tool_name, "--version"], timeout=5, check=False)
        return result.returncode == 0
    except (ProcessTimeout, FileNotFoundError):
        return False


def get_tool_version(tool_name: str) -> Optional[str]:
    """
    Get the version of a tool.
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        Version string if available, None otherwise
    """
    version_flags = ["--version", "-V", "-v", "version"]
    
    for flag in version_flags:
        try:
            result = run([tool_name, flag], timeout=5, check=False)
            if result.returncode == 0 and result.stdout:
                # Extract version from output (first line usually)
                first_line = result.stdout.split('\n')[0]
                return first_line.strip()
        except (ProcessTimeout, FileNotFoundError):
            continue
    
    return None


def escape_shell_arg(arg: str) -> str:
    """
    Escape a shell argument to prevent injection.
    
    Args:
        arg: Argument to escape
        
    Returns:
        Escaped argument safe for shell use
    """
    import shlex
    return shlex.quote(arg)


def validate_ip(ip: str) -> bool:
    """
    Validate an IP address.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid IP address
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: Union[str, int]) -> bool:
    """
    Validate a port number.
    
    Args:
        port: Port number to validate
        
    Returns:
        True if valid port (1-65535)
    """
    try:
        port_int = int(port)
        return 1 <= port_int <= 65535
    except (ValueError, TypeError):
        return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to be filesystem-safe.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    import re
    # Remove/replace dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove control characters
    sanitized = ''.join(c for c in sanitized if ord(c) >= 32)
    # Limit length
    if len(sanitized) > 200:
        sanitized = sanitized[:200]
    # Ensure not empty
    if not sanitized:
        sanitized = "unnamed"
    return sanitized
