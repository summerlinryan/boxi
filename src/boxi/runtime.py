"""
Runtime context and event system for boxi.

Provides state management, event bus for inter-stage communication,
and run context tracking for the orchestrator.
"""

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Type, TypeVar, Union

from pydantic import BaseModel

from boxi.artifacts import (
    Credential, FileArtifact, Flag, HashArtifact, RunState, Service, Target
)
from boxi.config import get_settings
from boxi.logging_config import get_logger
from boxi.utils.fs import ensure_dir

logger = get_logger(__name__)

T = TypeVar('T', bound=BaseModel)


class BoxiEvent(BaseModel):
    """Base class for all boxi events."""
    event_type: str
    timestamp: datetime = datetime.now()
    data: Dict[str, Any] = {}


class ArtifactFoundEvent(BoxiEvent):
    """Event fired when a new artifact is discovered."""
    event_type: str = "artifact_found"
    artifact_type: str
    artifact: Dict[str, Any]


class StageCompleteEvent(BoxiEvent):
    """Event fired when a stage completes."""
    event_type: str = "stage_complete"
    stage_name: str
    success: bool
    artifacts_count: int = 0


class UserInjectEvent(BoxiEvent):
    """Event fired when user injects data."""
    event_type: str = "user_inject"
    injection_type: str  # 'creds', 'ignore', 'hint'
    injection_data: str


class StageStartEvent(BoxiEvent):
    """Event fired when a stage starts."""
    event_type: str = "stage_start"
    stage_name: str
    target: Optional[str] = None


EventHandler = Callable[[BoxiEvent], None]


class EventBus:
    """Simple in-process event bus for stage coordination."""
    
    def __init__(self):
        self._handlers: Dict[str, List[EventHandler]] = {}
        self._lock = threading.RLock()
    
    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Subscribe a handler to an event type."""
        with self._lock:
            if event_type not in self._handlers:
                self._handlers[event_type] = []
            self._handlers[event_type].append(handler)
            logger.debug(f"Subscribed handler to {event_type}")
    
    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        """Unsubscribe a handler from an event type."""
        with self._lock:
            if event_type in self._handlers:
                try:
                    self._handlers[event_type].remove(handler)
                    logger.debug(f"Unsubscribed handler from {event_type}")
                except ValueError:
                    pass
    
    def emit(self, event: BoxiEvent) -> None:
        """Emit an event to all subscribers."""
        with self._lock:
            handlers = self._handlers.get(event.event_type, [])
            logger.debug(f"Emitting {event.event_type} to {len(handlers)} handlers")
            
            for handler in handlers:
                try:
                    handler(event)
                except Exception as e:
                    logger.error(f"Error in event handler: {e}")


class StateStore:
    """Persistent state storage using SQLite."""
    
    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        ensure_dir(self.db_path.parent)
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize the database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS run_state (
                    id INTEGER PRIMARY KEY,
                    target TEXT NOT NULL,
                    state_json TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    event_data TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create index for faster lookups
            conn.execute("CREATE INDEX IF NOT EXISTS idx_target ON run_state(target)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type)")
    
    def save_state(self, target: str, state: RunState) -> None:
        """Save run state to database."""
        state_json = state.model_dump_json()
        
        with sqlite3.connect(self.db_path) as conn:
            # Update or insert
            conn.execute("""
                INSERT OR REPLACE INTO run_state (target, state_json, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            """, (target, state_json))
            
        logger.debug(f"Saved state for target {target}")
    
    def load_state(self, target: str) -> Optional[RunState]:
        """Load run state from database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT state_json FROM run_state WHERE target = ? ORDER BY updated_at DESC LIMIT 1",
                (target,)
            )
            row = cursor.fetchone()
            
        if row:
            try:
                state_data = json.loads(row[0])
                return RunState(**state_data)
            except Exception as e:
                logger.error(f"Failed to load state for {target}: {e}")
                return None
        
        return None
    
    def log_event(self, event: BoxiEvent) -> None:
        """Log an event to the database."""
        event_json = event.model_dump_json()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO events (event_type, event_data) VALUES (?, ?)",
                (event.event_type, event_json)
            )
    
    def get_events(self, event_type: Optional[str] = None, limit: int = 100) -> List[BoxiEvent]:
        """Get recent events from the database."""
        with sqlite3.connect(self.db_path) as conn:
            if event_type:
                cursor = conn.execute(
                    "SELECT event_data FROM events WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
                    (event_type, limit)
                )
            else:
                cursor = conn.execute(
                    "SELECT event_data FROM events ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                )
            
            events = []
            for row in cursor.fetchall():
                try:
                    event_data = json.loads(row[0])
                    event = BoxiEvent(**event_data)
                    events.append(event)
                except Exception as e:
                    logger.error(f"Failed to deserialize event: {e}")
            
            return events


class RunContext:
    """
    Context for a single boxi run.
    
    Manages state, events, and provides convenience methods for stage coordination.
    """
    
    def __init__(self, target: str, workspace_dir: Optional[Path] = None):
        self.target = target
        self.workspace_dir = workspace_dir or get_settings().workspace_root
        
        # Initialize state
        self.state = RunState(target=target)
        
        # Initialize event bus and state store
        self.event_bus = EventBus()
        self.state_store = StateStore(self.workspace_dir / "state.db")
        
        # Load existing state if available
        existing_state = self.state_store.load_state(target)
        if existing_state:
            self.state = existing_state
            logger.info(f"Loaded existing state for {target}")
        
        # Set up event logging
        self.event_bus.subscribe("*", self._log_event)
        
        # Track running stages
        self._running_stages: Set[str] = set()
        self._lock = threading.RLock()
    
    def _log_event(self, event: BoxiEvent) -> None:
        """Log events to persistent storage."""
        self.state_store.log_event(event)
    
    def save_state(self) -> None:
        """Save current state to persistent storage."""
        self.state_store.save_state(self.target, self.state)
    
    def add_target(self, target: Target) -> None:
        """Add a target to the run state."""
        self.state.targets.append(target)
        self.emit_artifact_found("target", target)
        self.save_state()
    
    def add_service(self, service: Service) -> None:
        """Add a service to the run state."""
        self.state.add_service(service)
        self.emit_artifact_found("service", service)
        self.save_state()
    
    def add_credential(self, credential: Credential) -> None:
        """Add a credential to the run state."""
        self.state.add_credential(credential)
        self.emit_artifact_found("credential", credential)
        self.save_state()
    
    def add_file(self, file_artifact: FileArtifact) -> None:
        """Add a file artifact to the run state."""
        self.state.files.append(file_artifact)
        self.emit_artifact_found("file", file_artifact)
        self.save_state()
    
    def add_hash(self, hash_artifact: HashArtifact) -> None:
        """Add a hash artifact to the run state."""
        self.state.hashes.append(hash_artifact)
        self.emit_artifact_found("hash", hash_artifact)
        
        # If hash is cracked, also add as credential
        if hash_artifact.cracked_password:
            cred = hash_artifact.to_credential()
            if cred:
                self.add_credential(cred)
        
        self.save_state()
    
    def add_flag(self, flag: Flag) -> None:
        """Add a flag to the run state."""
        self.state.flags.append(flag)
        self.emit_artifact_found("flag", flag)
        self.save_state()
    
    def emit_artifact_found(self, artifact_type: str, artifact: BaseModel) -> None:
        """Emit an artifact found event."""
        event = ArtifactFoundEvent(
            artifact_type=artifact_type,
            artifact=artifact.model_dump()
        )
        self.event_bus.emit(event)
    
    def emit_stage_start(self, stage_name: str) -> None:
        """Emit a stage start event."""
        with self._lock:
            self._running_stages.add(stage_name)
        
        event = StageStartEvent(stage_name=stage_name, target=self.target)
        self.event_bus.emit(event)
    
    def emit_stage_complete(self, stage_name: str, success: bool, artifacts_count: int = 0) -> None:
        """Emit a stage complete event."""
        with self._lock:
            self._running_stages.discard(stage_name)
            
            if success:
                if stage_name not in self.state.completed_stages:
                    self.state.completed_stages.append(stage_name)
            else:
                if stage_name not in self.state.failed_stages:
                    self.state.failed_stages.append(stage_name)
        
        event = StageCompleteEvent(
            stage_name=stage_name,
            success=success,
            artifacts_count=artifacts_count
        )
        self.event_bus.emit(event)
        self.save_state()
    
    def emit_user_inject(self, injection_type: str, data: str) -> None:
        """Emit a user injection event."""
        event = UserInjectEvent(injection_type=injection_type, injection_data=data)
        self.event_bus.emit(event)
    
    def is_stage_completed(self, stage_name: str) -> bool:
        """Check if a stage has been completed."""
        return stage_name in self.state.completed_stages
    
    def is_stage_failed(self, stage_name: str) -> bool:
        """Check if a stage has failed."""
        return stage_name in self.state.failed_stages
    
    def is_stage_running(self, stage_name: str) -> bool:
        """Check if a stage is currently running."""
        with self._lock:
            return stage_name in self._running_stages
    
    def get_artifacts_by_type(self, artifact_type: Type[T]) -> List[T]:
        """Get all artifacts of a specific type."""
        if artifact_type == Target:
            return self.state.targets
        elif artifact_type == Service:
            return self.state.services
        elif artifact_type == Credential:
            return self.state.credentials
        elif artifact_type == FileArtifact:
            return self.state.files
        elif artifact_type == HashArtifact:
            return self.state.hashes
        elif artifact_type == Flag:
            return self.state.flags
        else:
            return []
    
    def inject_credentials(self, username: str, password: str, source: str = "user_input") -> None:
        """Inject credentials from user input."""
        credential = Credential(
            username=username,
            secret=password,
            source=source,
            score=1.0  # User-provided creds get max score
        )
        self.add_credential(credential)
        self.emit_user_inject("creds", f"{username}:{password}")
    
    def inject_ignore_pattern(self, pattern: str) -> None:
        """Inject an ignore pattern from user input."""
        if pattern not in self.state.ignore_patterns:
            self.state.ignore_patterns.append(pattern)
            self.save_state()
            self.emit_user_inject("ignore", pattern)
    
    def inject_hint(self, hint: str) -> None:
        """Inject a hint from user input."""
        self.state.hints.append(hint)
        self.save_state()
        self.emit_user_inject("hint", hint)
    
    def get_loot_dir(self) -> Path:
        """Get the loot directory for this run."""
        from boxi.utils.fs import get_loot_dir
        return get_loot_dir(self.target)
    
    def get_run_dir(self) -> Path:
        """Get the run directory for this run."""
        from boxi.utils.fs import get_run_dir
        return get_run_dir(self.target)


# Global run context (set by CLI)
_current_context: Optional[RunContext] = None
_context_lock = threading.RLock()


def set_current_context(context: RunContext) -> None:
    """Set the current run context."""
    global _current_context
    with _context_lock:
        _current_context = context


def get_current_context() -> Optional[RunContext]:
    """Get the current run context."""
    with _context_lock:
        return _current_context


def require_context() -> RunContext:
    """Get the current context, raising an error if not set."""
    context = get_current_context()
    if context is None:
        raise RuntimeError("No active run context")
    return context
