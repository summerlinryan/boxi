"""
Database management for boxi using SQLite.

Handles data persistence, schema management, and provides a clean interface
for storing and retrieving pentest artifacts and run state.
"""

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from contextlib import contextmanager

from boxi.core.logging import get_logger

logger = get_logger(__name__)


class Database:
    """SQLite database manager for boxi."""
    
    def __init__(self, db_path: Union[str, Path]):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        logger.debug(f"Database initialized at {self.db_path}")
    
    def _init_schema(self) -> None:
        """Initialize database schema."""
        with self.get_connection() as conn:
            # Runs table - tracks individual pentest runs
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    status TEXT DEFAULT 'running',
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP NULL,
                    metadata TEXT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Artifacts table - stores discovered items
            conn.execute("""
                CREATE TABLE IF NOT EXISTS artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    artifact_type TEXT NOT NULL,
                    artifact_data TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence REAL DEFAULT 1.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (run_id) REFERENCES runs (id) ON DELETE CASCADE
                )
            """)
            
            # Events table - tracks actions and decisions
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    event_data TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (run_id) REFERENCES runs (id) ON DELETE CASCADE
                )
            """)
            
            # Create indexes for better performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_artifacts_run_type ON artifacts(run_id, artifact_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_run_type ON events(run_id, event_type)")
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access to rows
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def create_run(self, target: str, metadata: Optional[Dict[str, Any]] = None) -> int:
        """
        Create a new pentest run.
        
        Args:
            target: Target identifier (IP, hostname, etc.)
            metadata: Optional metadata dictionary
            
        Returns:
            Run ID
        """
        import json
        
        metadata_json = json.dumps(metadata) if metadata else None
        
        with self.get_connection() as conn:
            cursor = conn.execute(
                "INSERT INTO runs (target, metadata) VALUES (?, ?)",
                (target, metadata_json)
            )
            run_id = cursor.lastrowid
            conn.commit()
            
        logger.info(f"Created new run {run_id} for target {target}")
        return run_id
    
    def get_run(self, run_id: int) -> Optional[Dict[str, Any]]:
        """
        Get run information by ID.
        
        Args:
            run_id: Run identifier
            
        Returns:
            Run data dictionary or None if not found
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM runs WHERE id = ?",
                (run_id,)
            )
            row = cursor.fetchone()
            
        if row:
            return dict(row)
        return None
    
    def get_latest_run(self, target: str) -> Optional[Dict[str, Any]]:
        """
        Get the most recent run for a target.
        
        Args:
            target: Target identifier
            
        Returns:
            Run data dictionary or None if not found
        """
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM runs WHERE target = ? ORDER BY created_at DESC LIMIT 1",
                (target,)
            )
            row = cursor.fetchone()
            
        if row:
            return dict(row)
        return None
    
    def update_run_status(self, run_id: int, status: str) -> None:
        """
        Update run status.
        
        Args:
            run_id: Run identifier
            status: New status
        """
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE runs SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status, run_id)
            )
            conn.commit()
            
        logger.debug(f"Updated run {run_id} status to {status}")
    
    def add_artifact(
        self, 
        run_id: int, 
        artifact_type: str, 
        artifact_data: Dict[str, Any],
        source: str,
        confidence: float = 1.0
    ) -> int:
        """
        Add an artifact to the database.
        
        Args:
            run_id: Run identifier
            artifact_type: Type of artifact (service, credential, file, etc.)
            artifact_data: Artifact data dictionary
            source: Source that discovered this artifact
            confidence: Confidence score (0.0 to 1.0)
            
        Returns:
            Artifact ID
        """
        import json
        
        data_json = json.dumps(artifact_data)
        
        with self.get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO artifacts (run_id, artifact_type, artifact_data, source, confidence) 
                   VALUES (?, ?, ?, ?, ?)""",
                (run_id, artifact_type, data_json, source, confidence)
            )
            artifact_id = cursor.lastrowid
            conn.commit()
            
        logger.debug(f"Added {artifact_type} artifact {artifact_id} from {source}")
        return artifact_id
    
    def get_artifacts(
        self, 
        run_id: int, 
        artifact_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get artifacts for a run.
        
        Args:
            run_id: Run identifier
            artifact_type: Optional filter by artifact type
            
        Returns:
            List of artifact dictionaries
        """
        import json
        
        if artifact_type:
            query = "SELECT * FROM artifacts WHERE run_id = ? AND artifact_type = ? ORDER BY created_at"
            params = (run_id, artifact_type)
        else:
            query = "SELECT * FROM artifacts WHERE run_id = ? ORDER BY created_at"
            params = (run_id,)
        
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
        
        artifacts = []
        for row in rows:
            artifact = dict(row)
            artifact['artifact_data'] = json.loads(artifact['artifact_data'])
            artifacts.append(artifact)
        
        return artifacts
    
    def log_event(
        self, 
        run_id: int, 
        event_type: str, 
        event_data: Dict[str, Any]
    ) -> int:
        """
        Log an event.
        
        Args:
            run_id: Run identifier
            event_type: Type of event
            event_data: Event data dictionary
            
        Returns:
            Event ID
        """
        import json
        
        data_json = json.dumps(event_data)
        
        with self.get_connection() as conn:
            cursor = conn.execute(
                "INSERT INTO events (run_id, event_type, event_data) VALUES (?, ?, ?)",
                (run_id, event_type, data_json)
            )
            event_id = cursor.lastrowid
            conn.commit()
            
        logger.debug(f"Logged {event_type} event {event_id}")
        return event_id
    
    def get_events(
        self, 
        run_id: int, 
        event_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get events for a run.
        
        Args:
            run_id: Run identifier
            event_type: Optional filter by event type
            limit: Maximum number of events to return
            
        Returns:
            List of event dictionaries
        """
        import json
        
        if event_type:
            query = """SELECT * FROM events 
                      WHERE run_id = ? AND event_type = ? 
                      ORDER BY timestamp DESC LIMIT ?"""
            params = (run_id, event_type, limit)
        else:
            query = "SELECT * FROM events WHERE run_id = ? ORDER BY timestamp DESC LIMIT ?"
            params = (run_id, limit)
        
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
        
        events = []
        for row in rows:
            event = dict(row)
            event['event_data'] = json.loads(event['event_data'])
            events.append(event)
        
        return events
