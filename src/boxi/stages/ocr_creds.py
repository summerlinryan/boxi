"""
OCR credential extraction stage.

Extracts text from images and PDFs to find potential credentials.
"""

from typing import List

from boxi.adapters.ocr import create_adapter as create_ocr_adapter
from boxi.artifacts import Credential, FileArtifact
from boxi.logging_config import StageLogger, log_artifact_found, log_stage_skip
from boxi.runtime import require_context
from boxi.utils.text import extract_credentials


def run_ocr_credential_extraction() -> List[Credential]:
    """
    Extract credentials from files using OCR.
    
    Returns:
        List of discovered credentials
    """
    context = require_context()
    
    with StageLogger("ocr_creds") as stage_log:
        # Get files that might contain text
        files = context.get_artifacts_by_type(FileArtifact)
        
        if not files:
            log_stage_skip("ocr_creds", "No files to analyze")
            return []
        
        # Filter to OCR-able files
        ocr_files = [f for f in files if _is_ocr_capable_file(f)]
        
        if not ocr_files:
            log_stage_skip("ocr_creds", "No OCR-capable files found")
            return []
        
        stage_log.info(f"Found {len(ocr_files)} files to analyze with OCR")
        
        ocr = create_ocr_adapter()
        
        if not ocr.is_available():
            stage_log.warning("OCR tools not available, trying text extraction only")
        
        all_credentials = []
        
        for file_artifact in ocr_files:
            stage_log.info(f"Analyzing file: {file_artifact.name}")
            
            # Extract text from file
            text = _extract_text_from_file(ocr, file_artifact, stage_log)
            
            if text:
                stage_log.debug(f"Extracted {len(text)} characters from {file_artifact.name}")
                
                # Look for credentials in the text
                credentials = _find_credentials_in_text(text, file_artifact.name)
                
                if credentials:
                    stage_log.info(f"Found {len(credentials)} potential credentials in {file_artifact.name}")
                    
                    # Add credentials to context
                    for cred in credentials:
                        context.add_credential(cred)
                        log_artifact_found("credential", f"{cred.username}:{cred.secret}")
                    
                    all_credentials.extend(credentials)
                else:
                    stage_log.debug(f"No credentials found in {file_artifact.name}")
            else:
                stage_log.warning(f"Could not extract text from {file_artifact.name}")
        
        stage_log.info(f"OCR credential extraction completed, found {len(all_credentials)} credentials")
        return all_credentials


def _is_ocr_capable_file(file_artifact: FileArtifact) -> bool:
    """Check if file can be processed with OCR."""
    if not file_artifact.local_path:
        return False
    
    # Check file extension
    name_lower = file_artifact.name.lower()
    
    # OCR-capable file types
    ocr_extensions = [
        '.pdf', '.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp', '.gif',
        '.txt', '.log', '.conf', '.config', '.xml', '.json'
    ]
    
    return any(name_lower.endswith(ext) for ext in ocr_extensions)


def _extract_text_from_file(ocr_adapter, file_artifact: FileArtifact, stage_log: StageLogger) -> str:
    """Extract text from a file artifact."""
    if not file_artifact.local_path:
        stage_log.warning(f"No local path for file: {file_artifact.name}")
        return ""
    
    try:
        # Try OCR extraction
        text = ocr_adapter.extract_text_from_file(file_artifact.local_path)
        
        if text:
            return text
        
        # If OCR fails, try reading as plain text
        name_lower = file_artifact.name.lower()
        if any(name_lower.endswith(ext) for ext in ['.txt', '.log', '.conf', '.config', '.xml', '.json']):
            try:
                text = file_artifact.local_path.read_text(encoding='utf-8', errors='ignore')
                return text
            except Exception as e:
                stage_log.debug(f"Failed to read {file_artifact.name} as text: {e}")
        
        return ""
        
    except Exception as e:
        stage_log.error(f"Text extraction failed for {file_artifact.name}: {e}")
        return ""


def _find_credentials_in_text(text: str, source_file: str) -> List[Credential]:
    """Find credentials in extracted text."""
    credentials = []
    
    # Use text utility to find credential patterns
    cred_pairs = extract_credentials(text)
    
    for username, password in cred_pairs:
        # Create credential artifact
        credential = Credential(
            username=username,
            secret=password,
            source=f"ocr:{source_file}",
            score=0.7  # Medium confidence for OCR-extracted creds
        )
        
        # Basic validation
        if _is_valid_credential(credential):
            credentials.append(credential)
    
    # Also look for common credential patterns manually
    lines = text.split('\n')
    for line in lines:
        line = line.strip()
        
        # Look for various credential formats
        creds_from_line = _extract_creds_from_line(line, source_file)
        credentials.extend(creds_from_line)
    
    # Remove duplicates
    unique_creds = []
    seen = set()
    
    for cred in credentials:
        key = (cred.username.lower(), cred.secret)
        if key not in seen:
            seen.add(key)
            unique_creds.append(cred)
    
    return unique_creds


def _extract_creds_from_line(line: str, source_file: str) -> List[Credential]:
    """Extract credentials from a single line of text."""
    credentials = []
    line_lower = line.lower()
    
    # Common credential patterns in documents
    patterns = [
        # "Username: admin Password: secret123"
        (r'username[:\s]+(\w+).*password[:\s]+(\S+)', 0.8),
        # "User: admin Pass: secret123"  
        (r'user[:\s]+(\w+).*pass[:\s]+(\S+)', 0.8),
        # "Login: admin / secret123"
        (r'login[:\s]+(\w+)[/\s]+(\S+)', 0.7),
        # "admin / secret123" (simple format)
        (r'^(\w+)\s*/\s*(\S+)$', 0.6),
        # "admin:secret123" at start of line
        (r'^(\w+):(\S+)$', 0.7),
    ]
    
    import re
    
    for pattern, confidence in patterns:
        matches = re.finditer(pattern, line, re.IGNORECASE)
        
        for match in matches:
            username = match.group(1).strip()
            password = match.group(2).strip()
            
            if username and password and len(username) > 0 and len(password) > 0:
                credential = Credential(
                    username=username,
                    secret=password,
                    source=f"ocr_line:{source_file}",
                    score=confidence
                )
                
                if _is_valid_credential(credential):
                    credentials.append(credential)
    
    return credentials


def _is_valid_credential(credential: Credential) -> bool:
    """Basic validation of extracted credentials."""
    # Check lengths
    if len(credential.username) < 2 or len(credential.username) > 50:
        return False
    
    if len(credential.secret) < 1 or len(credential.secret) > 100:
        return False
    
    # Check for obvious false positives
    username_lower = credential.username.lower()
    password_lower = credential.secret.lower()
    
    # Skip obvious non-credentials
    skip_usernames = {
        'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had',
        'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his',
        'how', 'its', 'may', 'new', 'now', 'old', 'see', 'two', 'who', 'boy',
        'did', 'man', 'men', 'way', 'www', 'com', 'org', 'net', 'edu'
    }
    
    if username_lower in skip_usernames:
        return False
    
    # Skip very common/obvious test values
    if 'test' in username_lower and 'test' in password_lower:
        return False
    
    # Must contain some alphanumeric characters
    if not any(c.isalnum() for c in credential.username):
        return False
    
    if not any(c.isalnum() for c in credential.secret):
        return False
    
    return True


def check_stage_requirements() -> bool:
    """Check if this stage can run."""
    # Can always try text extraction, OCR is optional
    return True


def get_stage_info() -> dict:
    """Get information about this stage."""
    return {
        "name": "ocr_creds",
        "description": "Extract credentials from images and documents using OCR",
        "requirements": ["tesseract (optional)"],
        "produces": ["Credential"],
        "consumes": ["FileArtifact"],
        "safe": True,
    }
