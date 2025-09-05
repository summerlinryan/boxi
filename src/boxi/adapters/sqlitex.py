"""
SQLite adapter for database parsing and data extraction.

Provides utilities for analyzing SQLite databases found during pentesting.
"""

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from boxi.artifacts import HashArtifact, HashAlgorithm
from boxi.logging_config import get_logger
from boxi.utils.text import extract_credentials, extract_hashes

logger = get_logger(__name__)


class SQLiteAdapter:
    """Adapter for SQLite database operations."""
    
    def __init__(self):
        pass
    
    def is_available(self) -> bool:
        """SQLite is built into Python, so always available."""
        return True
    
    def analyze_database(self, db_path: Path) -> Dict[str, Any]:
        """
        Analyze a SQLite database and extract useful information.
        
        Args:
            db_path: Path to SQLite database file
            
        Returns:
            Dictionary with database analysis results
        """
        if not db_path.exists():
            logger.error(f"Database file not found: {db_path}")
            return {}
        
        try:
            logger.debug(f"Analyzing SQLite database: {db_path}")
            
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                # Get database info
                info = {
                    'file_path': str(db_path),
                    'file_size': db_path.stat().st_size,
                    'tables': [],
                    'interesting_tables': [],
                    'row_counts': {},
                    'credentials_found': [],
                    'hashes_found': [],
                }
                
                # Get table list
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                info['tables'] = tables
                
                # Analyze each table
                for table in tables:
                    try:
                        # Get row count
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        row_count = cursor.fetchone()[0]
                        info['row_counts'][table] = row_count
                        
                        # Check if table might contain interesting data
                        if self._is_interesting_table(table):
                            info['interesting_tables'].append(table)
                            
                            # Extract sample data
                            table_data = self._extract_table_data(cursor, table)
                            
                            # Look for credentials and hashes
                            creds, hashes = self._find_credentials_in_data(table_data, table)
                            info['credentials_found'].extend(creds)
                            info['hashes_found'].extend(hashes)
                    
                    except sqlite3.Error as e:
                        logger.warning(f"Error analyzing table {table}: {e}")
                        continue
                
                logger.info(f"Analyzed database with {len(tables)} tables, "
                           f"found {len(info['credentials_found'])} credentials, "
                           f"{len(info['hashes_found'])} hashes")
                
                return info
                
        except sqlite3.Error as e:
            logger.error(f"Failed to analyze SQLite database {db_path}: {e}")
            return {}
    
    def extract_users_table(self, db_path: Path, table_name: str = "users") -> List[HashArtifact]:
        """
        Extract user data from a specific table.
        
        Args:
            db_path: Path to SQLite database
            table_name: Name of users table
            
        Returns:
            List of HashArtifact objects for found hashes
        """
        hash_artifacts = []
        
        try:
            logger.debug(f"Extracting users from table '{table_name}' in {db_path}")
            
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                # Check if table exists
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (table_name,)
                )
                
                if not cursor.fetchone():
                    logger.warning(f"Table '{table_name}' not found in database")
                    return []
                
                # Get table schema
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [row[1] for row in cursor.fetchall()]
                
                # Find relevant columns
                username_col = self._find_column(columns, ['user', 'username', 'login', 'name'])
                password_col = self._find_column(columns, ['pass', 'password', 'hash', 'passwd'])
                
                if not username_col or not password_col:
                    logger.warning(f"Could not identify username/password columns in {table_name}")
                    return []
                
                # Extract user data
                cursor.execute(f"SELECT {username_col}, {password_col} FROM {table_name}")
                rows = cursor.fetchall()
                
                for username, password_hash in rows:
                    if username and password_hash:
                        # Determine hash type
                        hash_algo = self._detect_hash_algorithm(password_hash)
                        
                        hash_artifact = HashArtifact(
                            username=str(username),
                            algorithm=hash_algo,
                            hash_value=str(password_hash),
                            source=f"sqlite:{db_path.name}:{table_name}"
                        )
                        
                        hash_artifacts.append(hash_artifact)
                
                logger.info(f"Extracted {len(hash_artifacts)} hashes from {table_name}")
                
        except sqlite3.Error as e:
            logger.error(f"Failed to extract users from {table_name}: {e}")
        
        return hash_artifacts
    
    def search_for_credentials(self, db_path: Path) -> Tuple[List[str], List[HashArtifact]]:
        """
        Search entire database for potential credentials.
        
        Args:
            db_path: Path to SQLite database
            
        Returns:
            Tuple of (plaintext_credentials, hash_artifacts)
        """
        credentials = []
        hash_artifacts = []
        
        try:
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                # Get all tables
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                
                for table in tables:
                    try:
                        # Get all text data from table
                        cursor.execute(f"SELECT * FROM {table}")
                        rows = cursor.fetchall()
                        
                        # Convert all data to text for searching
                        text_data = []
                        for row in rows:
                            row_text = ' '.join(str(cell) for cell in row if cell is not None)
                            text_data.append(row_text)
                        
                        all_text = '\n'.join(text_data)
                        
                        # Search for credentials
                        found_creds = extract_credentials(all_text)
                        credentials.extend([f"{u}:{p}" for u, p in found_creds])
                        
                        # Search for hashes
                        found_hashes = extract_hashes(all_text)
                        for username, hash_type, hash_value in found_hashes:
                            hash_algo = HashAlgorithm(hash_type) if hash_type in HashAlgorithm else HashAlgorithm.UNKNOWN
                            
                            hash_artifact = HashArtifact(
                                username=username,
                                algorithm=hash_algo,
                                hash_value=hash_value,
                                source=f"sqlite:{db_path.name}:{table}"
                            )
                            hash_artifacts.append(hash_artifact)
                    
                    except sqlite3.Error as e:
                        logger.warning(f"Error searching table {table}: {e}")
                        continue
        
        except sqlite3.Error as e:
            logger.error(f"Failed to search database for credentials: {e}")
        
        logger.info(f"Found {len(credentials)} plaintext credentials and "
                   f"{len(hash_artifacts)} hashes in database")
        
        return credentials, hash_artifacts
    
    def _is_interesting_table(self, table_name: str) -> bool:
        """Check if a table name suggests it might contain interesting data."""
        interesting_keywords = [
            'user', 'admin', 'account', 'login', 'auth', 'pass', 'cred',
            'employee', 'member', 'customer', 'client', 'person'
        ]
        
        table_lower = table_name.lower()
        return any(keyword in table_lower for keyword in interesting_keywords)
    
    def _extract_table_data(self, cursor: sqlite3.Cursor, table: str, limit: int = 100) -> List[tuple]:
        """Extract sample data from a table."""
        try:
            cursor.execute(f"SELECT * FROM {table} LIMIT {limit}")
            return cursor.fetchall()
        except sqlite3.Error:
            return []
    
    def _find_credentials_in_data(self, data: List[tuple], table_name: str) -> Tuple[List[str], List[HashArtifact]]:
        """Look for credentials in table data."""
        credentials = []
        hash_artifacts = []
        
        # Convert data to text for pattern matching
        text_data = []
        for row in data:
            row_text = ' '.join(str(cell) for cell in row if cell is not None)
            text_data.append(row_text)
        
        all_text = '\n'.join(text_data)
        
        # Extract credentials
        found_creds = extract_credentials(all_text)
        credentials.extend([f"{u}:{p}" for u, p in found_creds])
        
        # Extract hashes
        found_hashes = extract_hashes(all_text)
        for username, hash_type, hash_value in found_hashes:
            hash_algo = HashAlgorithm(hash_type) if hash_type in HashAlgorithm else HashAlgorithm.UNKNOWN
            
            hash_artifact = HashArtifact(
                username=username,
                algorithm=hash_algo,
                hash_value=hash_value,
                source=f"sqlite_table:{table_name}"
            )
            hash_artifacts.append(hash_artifact)
        
        return credentials, hash_artifacts
    
    def _find_column(self, columns: List[str], keywords: List[str]) -> Optional[str]:
        """Find a column name containing any of the keywords."""
        for col in columns:
            col_lower = col.lower()
            for keyword in keywords:
                if keyword in col_lower:
                    return col
        return None
    
    def _detect_hash_algorithm(self, hash_value: str) -> HashAlgorithm:
        """Detect hash algorithm based on hash format."""
        if not hash_value:
            return HashAlgorithm.UNKNOWN
        
        hash_str = str(hash_value).strip()
        
        # Check hash length and format
        if len(hash_str) == 32 and hash_str.isalnum():
            # Could be MD5 or NTLM
            if hash_str.islower():
                return HashAlgorithm.MD5
            else:
                return HashAlgorithm.NTLM
        elif len(hash_str) == 40 and hash_str.isalnum():
            return HashAlgorithm.SHA1
        elif len(hash_str) == 64 and hash_str.isalnum():
            return HashAlgorithm.SHA256
        elif len(hash_str) == 128 and hash_str.isalnum():
            return HashAlgorithm.SHA512
        elif hash_str.startswith('$2'):
            return HashAlgorithm.BCRYPT
        elif hash_str.startswith('$7$'):
            return HashAlgorithm.SCRYPT
        else:
            return HashAlgorithm.UNKNOWN


def create_adapter() -> SQLiteAdapter:
    """Create a SQLite adapter instance."""
    return SQLiteAdapter()
