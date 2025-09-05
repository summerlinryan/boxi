"""
Text parsing and processing utilities.

Provides small, unit-testable parsers for extracting information
from command output and files.
"""

import re
from typing import Dict, List, Optional, Set, Tuple


def extract_ip_addresses(text: str) -> Set[str]:
    """
    Extract IP addresses from text.
    
    Args:
        text: Text to search for IP addresses
        
    Returns:
        Set of unique IP addresses found
    """
    # IPv4 pattern
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    
    matches = re.findall(ipv4_pattern, text)
    
    # Validate IP addresses
    valid_ips = set()
    for ip in matches:
        parts = ip.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            valid_ips.add(ip)
    
    return valid_ips


def extract_hostnames(text: str) -> Set[str]:
    """
    Extract hostnames/FQDNs from text.
    
    Args:
        text: Text to search for hostnames
        
    Returns:
        Set of unique hostnames found
    """
    # Basic hostname pattern
    hostname_pattern = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b'
    
    matches = re.findall(hostname_pattern, text)
    
    # Filter out likely false positives
    hostnames = set()
    for match in matches:
        # Must contain at least one dot for FQDN
        if '.' in match and not match.replace('.', '').isdigit():
            hostnames.add(match.lower())
    
    return hostnames


def extract_credentials(text: str) -> List[Tuple[str, str]]:
    """
    Extract potential username:password pairs from text.
    
    Args:
        text: Text to search for credentials
        
    Returns:
        List of (username, password) tuples
    """
    credentials = []
    
    # Common credential patterns
    patterns = [
        r'([a-zA-Z0-9._-]+):([a-zA-Z0-9!@#$%^&*()_+={}|\\:";\'<>?,./`~-]+)',  # user:pass
        r'username[:\s=]+([a-zA-Z0-9._-]+).*password[:\s=]+([a-zA-Z0-9!@#$%^&*()_+={}|\\:";\'<>?,./`~-]+)',  # username: x password: y
        r'user[:\s=]+([a-zA-Z0-9._-]+).*pass[:\s=]+([a-zA-Z0-9!@#$%^&*()_+={}|\\:";\'<>?,./`~-]+)',  # user: x pass: y
    ]
    
    for pattern in patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            username = match.group(1).strip()
            password = match.group(2).strip()
            
            # Basic validation
            if len(username) > 0 and len(password) > 0 and len(username) < 100 and len(password) < 100:
                credentials.append((username, password))
    
    return credentials


def extract_hashes(text: str) -> List[Tuple[str, str, str]]:
    """
    Extract password hashes from text.
    
    Args:
        text: Text to search for hashes
        
    Returns:
        List of (username, hash_type, hash_value) tuples
    """
    hashes = []
    
    # Common hash patterns
    hash_patterns = {
        'md5': r'([a-zA-Z0-9._-]+)[:\s]+([a-f0-9]{32})',
        'sha1': r'([a-zA-Z0-9._-]+)[:\s]+([a-f0-9]{40})',
        'sha256': r'([a-zA-Z0-9._-]+)[:\s]+([a-f0-9]{64})',
        'ntlm': r'([a-zA-Z0-9._-]+)[:\s]+([a-fA-F0-9]{32})',  # NTLM hashes
        'lm': r'([a-zA-Z0-9._-]+)[:\s]+([a-fA-F0-9]{32})',  # LM hashes (same length as NTLM)
    }
    
    for hash_type, pattern in hash_patterns.items():
        matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            username = match.group(1).strip()
            hash_value = match.group(2).strip().lower()
            
            if username and hash_value:
                hashes.append((username, hash_type, hash_value))
    
    return hashes


def extract_file_paths(text: str) -> Set[str]:
    """
    Extract file paths from text.
    
    Args:
        text: Text to search for file paths
        
    Returns:
        Set of unique file paths found
    """
    paths = set()
    
    # Unix-style paths
    unix_pattern = r'(?:/[a-zA-Z0-9._-]+)+(?:\.[a-zA-Z0-9]+)?'
    
    # Windows-style paths  
    windows_pattern = r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*'
    
    for pattern in [unix_pattern, windows_pattern]:
        matches = re.findall(pattern, text)
        for match in matches:
            if len(match) > 3:  # Filter out very short matches
                paths.add(match)
    
    return paths


def extract_urls(text: str) -> Set[str]:
    """
    Extract URLs from text.
    
    Args:
        text: Text to search for URLs
        
    Returns:
        Set of unique URLs found
    """
    # URL pattern
    url_pattern = r'https?://(?:[-\w.])+(?::[0-9]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?'
    
    matches = re.findall(url_pattern, text, re.IGNORECASE)
    return set(matches)


def extract_email_addresses(text: str) -> Set[str]:
    """
    Extract email addresses from text.
    
    Args:
        text: Text to search for email addresses
        
    Returns:
        Set of unique email addresses found
    """
    # Email pattern
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    matches = re.findall(email_pattern, text)
    return set(match.lower() for match in matches)


def parse_nmap_output(output: str) -> List[Dict[str, str]]:
    """
    Parse nmap output for open ports.
    
    Args:
        output: Nmap command output
        
    Returns:
        List of port dictionaries with port, protocol, service, state
    """
    ports = []
    
    # Look for port lines like "22/tcp open ssh"
    port_pattern = r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s*(.+)?'
    
    for line in output.split('\n'):
        match = re.match(port_pattern, line.strip())
        if match:
            port_info = {
                'port': match.group(1),
                'protocol': match.group(2),
                'state': match.group(3),
                'service': match.group(4).strip() if match.group(4) else '',
            }
            ports.append(port_info)
    
    return ports


def parse_ftp_listing(output: str) -> List[Dict[str, str]]:
    """
    Parse FTP directory listing.
    
    Args:
        output: FTP LIST command output
        
    Returns:
        List of file dictionaries with name, size, type
    """
    files = []
    
    for line in output.split('\n'):
        line = line.strip()
        if not line:
            continue
            
        # Parse Unix-style listing
        # -rw-r--r-- 1 user group 1234 Jan 01 12:00 filename.txt
        unix_pattern = r'^([d-])[rwx-]{9}\s+\d+\s+\S+\s+\S+\s+(\d+)\s+.+\s+(.+)$'
        match = re.match(unix_pattern, line)
        
        if match:
            file_type = 'directory' if match.group(1) == 'd' else 'file'
            size = int(match.group(2)) if match.group(2) else 0
            name = match.group(3)
            
            files.append({
                'name': name,
                'size': str(size),
                'type': file_type,
            })
    
    return files


def parse_smb_shares(output: str) -> List[str]:
    """
    Parse SMB share listing output.
    
    Args:
        output: smbclient or similar tool output
        
    Returns:
        List of share names
    """
    shares = []
    
    # Look for share lines like "ADMIN$    Disk    Remote Admin"
    share_pattern = r'^\s*([A-Za-z0-9$_-]+)\s+Disk\s+'
    
    for line in output.split('\n'):
        match = re.match(share_pattern, line.strip())
        if match:
            share_name = match.group(1)
            shares.append(share_name)
    
    return shares


def clean_text(text: str) -> str:
    """
    Clean text by removing control characters and normalizing whitespace.
    
    Args:
        text: Text to clean
        
    Returns:
        Cleaned text
    """
    # Remove control characters except newline and tab
    cleaned = ''.join(c for c in text if ord(c) >= 32 or c in '\n\t')
    
    # Normalize whitespace
    cleaned = re.sub(r'\s+', ' ', cleaned)
    cleaned = cleaned.strip()
    
    return cleaned


def truncate_text(text: str, max_length: int = 1000) -> str:
    """
    Truncate text to maximum length with ellipsis.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        
    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - 3] + "..."


def extract_base64_strings(text: str, min_length: int = 20) -> Set[str]:
    """
    Extract potential base64 strings from text.
    
    Args:
        text: Text to search
        min_length: Minimum length for base64 strings
        
    Returns:
        Set of potential base64 strings
    """
    # Base64 pattern
    b64_pattern = r'[A-Za-z0-9+/]{' + str(min_length) + r',}={0,2}'
    
    matches = re.findall(b64_pattern, text)
    
    # Validate base64 format
    valid_b64 = set()
    for match in matches:
        # Check if length is multiple of 4 (with padding)
        if len(match) % 4 == 0:
            valid_b64.add(match)
    
    return valid_b64
