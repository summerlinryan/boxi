"""
SQLite database parsing stage.

Analyzes SQLite databases to extract user data and password hashes.
"""

from typing import List, Tuple

from boxi.adapters.sqlitex import create_adapter as create_sqlite_adapter
from boxi.artifacts import Credential, FileArtifact, HashArtifact
from boxi.logging_config import StageLogger, log_artifact_found, log_stage_skip
from boxi.runtime import require_context


def run_sqlite_parsing() -> Tuple[List[Credential], List[HashArtifact]]:
    """
    Parse SQLite databases for credentials and hashes.
    
    Returns:
        Tuple of (credentials, hash_artifacts)
    """
    context = require_context()
    
    with StageLogger("sqlite_parse") as stage_log:
        # Find SQLite database files
        files = context.get_artifacts_by_type(FileArtifact)
        db_files = [f for f in files if _is_sqlite_file(f)]
        
        if not db_files:
            log_stage_skip("sqlite_parse", "No SQLite database files found")
            return [], []
        
        stage_log.info(f"Found {len(db_files)} SQLite database files to analyze")
        
        sqlite = create_sqlite_adapter()
        
        all_credentials = []
        all_hashes = []
        
        for db_file in db_files:
            if not db_file.local_path:
                stage_log.warning(f"No local path for database: {db_file.name}")
                continue
            
            stage_log.info(f"Analyzing database: {db_file.name}")
            
            try:
                # Analyze the database
                analysis = sqlite.analyze_database(db_file.local_path)
                
                if not analysis:
                    stage_log.warning(f"Failed to analyze database: {db_file.name}")
                    continue
                
                stage_log.info(f"Database {db_file.name} has {len(analysis.get('tables', []))} tables")
                
                # Extract credentials and hashes found during analysis
                creds_found = analysis.get('credentials_found', [])
                hashes_found = analysis.get('hashes_found', [])
                
                # Convert to proper artifacts
                for cred_str in creds_found:
                    if ':' in cred_str:
                        username, password = cred_str.split(':', 1)
                        credential = Credential(
                            username=username,
                            secret=password,
                            source=f"sqlite:{db_file.name}",
                            score=0.8
                        )
                        all_credentials.append(credential)
                        context.add_credential(credential)
                        log_artifact_found("credential", f"{username}:{password}")
                
                for hash_artifact in hashes_found:
                    all_hashes.append(hash_artifact)
                    context.add_hash(hash_artifact)
                    log_artifact_found("hash", f"{hash_artifact.username} ({hash_artifact.algorithm.value})")
                
                # Try to extract from specific tables
                interesting_tables = analysis.get('interesting_tables', [])
                
                for table_name in interesting_tables:
                    stage_log.debug(f"Extracting from table: {table_name}")
                    
                    # Extract users from this table
                    table_hashes = sqlite.extract_users_table(db_file.local_path, table_name)
                    
                    for hash_artifact in table_hashes:
                        if hash_artifact not in all_hashes:  # Avoid duplicates
                            all_hashes.append(hash_artifact)
                            context.add_hash(hash_artifact)
                            log_artifact_found("hash", f"{hash_artifact.username} ({hash_artifact.algorithm.value})")
                
                # Also do a comprehensive search
                stage_log.debug("Performing comprehensive credential search")
                
                text_creds, search_hashes = sqlite.search_for_credentials(db_file.local_path)
                
                # Add text credentials
                for cred_str in text_creds:
                    if ':' in cred_str:
                        username, password = cred_str.split(':', 1)
                        credential = Credential(
                            username=username,
                            secret=password,
                            source=f"sqlite_search:{db_file.name}",
                            score=0.7
                        )
                        
                        # Check for duplicates
                        if not any(c.username == username and c.secret == password 
                                 for c in all_credentials):
                            all_credentials.append(credential)
                            context.add_credential(credential)
                            log_artifact_found("credential", f"{username}:{password}")
                
                # Add search hashes
                for hash_artifact in search_hashes:
                    # Check for duplicates
                    if not any(h.username == hash_artifact.username and 
                             h.hash_value == hash_artifact.hash_value 
                             for h in all_hashes):
                        all_hashes.append(hash_artifact)
                        context.add_hash(hash_artifact)
                        log_artifact_found("hash", f"{hash_artifact.username} ({hash_artifact.algorithm.value})")
            
            except Exception as e:
                stage_log.error(f"Error analyzing database {db_file.name}: {e}")
                continue
        
        stage_log.info(f"SQLite parsing completed, found {len(all_credentials)} credentials and {len(all_hashes)} hashes")
        return all_credentials, all_hashes


def analyze_specific_database(db_path: str, table_name: str = "users") -> List[HashArtifact]:
    """
    Analyze a specific database table for user data.
    
    Args:
        db_path: Path to SQLite database
        table_name: Name of table to analyze
        
    Returns:
        List of hash artifacts
    """
    context = require_context()
    
    with StageLogger("sqlite_specific", f"{db_path}:{table_name}") as stage_log:
        sqlite = create_sqlite_adapter()
        
        from pathlib import Path
        db_file = Path(db_path)
        
        if not db_file.exists():
            stage_log.error(f"Database file not found: {db_path}")
            return []
        
        stage_log.info(f"Analyzing table '{table_name}' in {db_file.name}")
        
        try:
            hash_artifacts = sqlite.extract_users_table(db_file, table_name)
            
            # Add to context
            for hash_artifact in hash_artifacts:
                context.add_hash(hash_artifact)
                log_artifact_found("hash", f"{hash_artifact.username} ({hash_artifact.algorithm.value})")
            
            stage_log.info(f"Extracted {len(hash_artifacts)} hashes from {table_name}")
            return hash_artifacts
        
        except Exception as e:
            stage_log.error(f"Error analyzing table {table_name}: {e}")
            return []


def _is_sqlite_file(file_artifact: FileArtifact) -> bool:
    """Check if a file is likely a SQLite database."""
    if not file_artifact.local_path:
        return False
    
    name_lower = file_artifact.name.lower()
    
    # Check file extensions
    sqlite_extensions = ['.db', '.sqlite', '.sqlite3', '.s3db', '.sl3']
    
    if any(name_lower.endswith(ext) for ext in sqlite_extensions):
        return True
    
    # Check for SQLite keywords in filename
    sqlite_keywords = ['database', 'db', 'sqlite', 'user', 'account']
    
    if any(keyword in name_lower for keyword in sqlite_keywords):
        return True
    
    # Try to detect SQLite by reading file header
    try:
        with open(file_artifact.local_path, 'rb') as f:
            header = f.read(16)
            # SQLite files start with "SQLite format 3\000"
            if header.startswith(b'SQLite format 3'):
                return True
    except Exception:
        pass
    
    return False


def get_database_schema(db_path: str) -> dict:
    """
    Get the schema of a SQLite database.
    
    Args:
        db_path: Path to SQLite database
        
    Returns:
        Dictionary with schema information
    """
    sqlite = create_sqlite_adapter()
    
    from pathlib import Path
    db_file = Path(db_path)
    
    if not db_file.exists():
        return {}
    
    try:
        import sqlite3
        
        with sqlite3.connect(str(db_file)) as conn:
            cursor = conn.cursor()
            
            # Get table list
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            schema = {'tables': {}}
            
            # Get schema for each table
            for table in tables:
                cursor.execute(f"PRAGMA table_info({table})")
                columns = cursor.fetchall()
                
                schema['tables'][table] = {
                    'columns': [{'name': col[1], 'type': col[2], 'notnull': col[3], 
                               'default': col[4], 'pk': col[5]} for col in columns]
                }
                
                # Get row count
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                row_count = cursor.fetchone()[0]
                schema['tables'][table]['row_count'] = row_count
            
            return schema
    
    except Exception as e:
        return {'error': str(e)}


def check_stage_requirements() -> bool:
    """Check if this stage can run."""
    # SQLite is built into Python, so always available
    return True


def get_stage_info() -> dict:
    """Get information about this stage."""
    return {
        "name": "sqlite_parse",
        "description": "Parse SQLite databases to extract credentials and hashes",
        "requirements": [],
        "produces": ["Credential", "HashArtifact"],
        "consumes": ["FileArtifact"],
        "safe": True,
    }
