"""
Orchestrator for coordinating boxi pipeline stages.

Implements rule-based stage scheduling with event-driven coordination
and support for human-in-the-loop intervention.
"""

import time
from typing import Dict, List, Optional, Set

from boxi.artifacts import Credential, FileArtifact, HashArtifact, Service
from boxi.logging_config import get_logger, log_stage_skip
from boxi.runtime import (
    ArtifactFoundEvent, BoxiEvent, RunContext, StageCompleteEvent,
    StageStartEvent, UserInjectEvent
)

# Import all stages
from boxi.stages import (
    ftp_enum, hash_crack, ocr_creds, port_scan, smb_loot, smb_spray,
    sqlite_parse, winrm_spray
)

logger = get_logger(__name__)


class StageRule:
    """Rule for determining when a stage should run."""
    
    def __init__(self, 
                 name: str,
                 stage_function,
                 requires_artifacts: List[str] = None,
                 requires_completed: List[str] = None,
                 prevents_stages: List[str] = None,
                 priority: int = 50,
                 max_runs: int = 1):
        self.name = name
        self.stage_function = stage_function
        self.requires_artifacts = requires_artifacts or []
        self.requires_completed = requires_completed or []
        self.prevents_stages = prevents_stages or []
        self.priority = priority
        self.max_runs = max_runs
        self.run_count = 0
    
    def can_run(self, context: RunContext) -> bool:
        """Check if this stage can run given the current context."""
        # Check if already completed
        if context.is_stage_completed(self.name):
            return False
        
        # Check if failed too many times
        if context.is_stage_failed(self.name):
            return False
        
        # Check if already running
        if context.is_stage_running(self.name):
            return False
        
        # Check max runs
        if self.run_count >= self.max_runs:
            return False
        
        # Check required completed stages
        for required_stage in self.requires_completed:
            if not context.is_stage_completed(required_stage):
                return False
        
        # Check required artifacts
        for artifact_type in self.requires_artifacts:
            if artifact_type == "Service":
                if not context.get_artifacts_by_type(Service):
                    return False
            elif artifact_type == "Credential":
                if not context.get_artifacts_by_type(Credential):
                    return False
            elif artifact_type == "FileArtifact":
                if not context.get_artifacts_by_type(FileArtifact):
                    return False
            elif artifact_type == "HashArtifact":
                if not context.get_artifacts_by_type(HashArtifact):
                    return False
        
        return True
    
    def should_prevent(self, other_stage: str, context: RunContext) -> bool:
        """Check if this stage should prevent another stage from running."""
        return other_stage in self.prevents_stages


class Orchestrator:
    """Main orchestrator for coordinating pentest stages."""
    
    def __init__(self, context: RunContext):
        self.context = context
        self.rules: List[StageRule] = []
        self.running = False
        self.paused = False
        
        # Set up event handlers
        self.context.event_bus.subscribe("artifact_found", self._on_artifact_found)
        self.context.event_bus.subscribe("stage_complete", self._on_stage_complete)
        self.context.event_bus.subscribe("user_inject", self._on_user_inject)
        
        # Initialize stage rules
        self._setup_stage_rules()
        
        logger.info("Orchestrator initialized")
    
    def _setup_stage_rules(self) -> None:
        """Set up rules for all stages."""
        self.rules = [
            # Port scanning - entry point
            StageRule(
                name="port_scan",
                stage_function=lambda: port_scan.run_port_scan(self.context.target),
                priority=100,  # Highest priority - run first
            ),
            
            # FTP enumeration - requires FTP services
            StageRule(
                name="ftp_enum",
                stage_function=lambda: ftp_enum.run_ftp_enumeration(self.context.target),
                requires_completed=["port_scan"],
                priority=90,
            ),
            
            # OCR credential extraction - requires files
            StageRule(
                name="ocr_creds",
                stage_function=ocr_creds.run_ocr_credential_extraction,
                requires_artifacts=["FileArtifact"],
                priority=80,
            ),
            
            # SMB credential spraying - requires credentials
            StageRule(
                name="smb_spray",
                stage_function=lambda: smb_spray.run_smb_credential_spray(self.context.target),
                requires_artifacts=["Credential"],
                requires_completed=["port_scan"],
                priority=70,
            ),
            
            # SMB file looting - requires SMB access
            StageRule(
                name="smb_loot",
                stage_function=lambda: smb_loot.run_smb_file_looting(self.context.target),
                requires_completed=["smb_spray"],
                priority=65,
            ),
            
            # SQLite parsing - requires database files
            StageRule(
                name="sqlite_parse",
                stage_function=sqlite_parse.run_sqlite_parsing,
                requires_artifacts=["FileArtifact"],
                priority=60,
            ),
            
            # Hash cracking - requires hashes
            StageRule(
                name="hash_crack",
                stage_function=hash_crack.run_hash_cracking,
                requires_artifacts=["HashArtifact"],
                priority=50,
            ),
            
            # WinRM spraying - requires credentials
            StageRule(
                name="winrm_spray",
                stage_function=lambda: winrm_spray.run_winrm_credential_spray(self.context.target),
                requires_artifacts=["Credential"],
                requires_completed=["port_scan"],
                priority=40,
            ),
            
            # WinRM foothold - requires valid WinRM creds
            StageRule(
                name="winrm_foothold",
                stage_function=lambda: winrm_spray.establish_winrm_foothold(self.context.target),
                requires_completed=["winrm_spray"],
                priority=30,
            ),
        ]
        
        logger.debug(f"Set up {len(self.rules)} stage rules")
    
    def run_pipeline(self, max_iterations: int = 20, dry_run: bool = False) -> Dict[str, any]:
        """
        Run the automated pipeline.
        
        Args:
            max_iterations: Maximum number of planning iterations
            dry_run: If True, only show what would be executed
            
        Returns:
            Dictionary with run results
        """
        logger.info(f"Starting pipeline {'(dry run)' if dry_run else ''}")
        
        if dry_run:
            return self._plan_execution()
        
        self.running = True
        start_time = time.time()
        
        try:
            iteration = 0
            stages_run = []
            
            while iteration < max_iterations and self.running and not self.paused:
                iteration += 1
                logger.debug(f"Pipeline iteration {iteration}")
                
                # Get next stage to run
                next_stage = self._get_next_stage()
                
                if not next_stage:
                    logger.info("No more stages to run, pipeline complete")
                    break
                
                logger.info(f"Running stage: {next_stage.name}")
                
                # Execute the stage
                success = self._execute_stage(next_stage)
                
                if success:
                    stages_run.append(next_stage.name)
                    next_stage.run_count += 1
                else:
                    logger.warning(f"Stage {next_stage.name} failed")
                
                # Small delay between stages
                if self.running:
                    time.sleep(1)
            
            end_time = time.time()
            duration = end_time - start_time
            
            result = {
                'success': True,
                'duration': duration,
                'iterations': iteration,
                'stages_run': stages_run,
                'artifacts_found': {
                    'services': len(self.context.get_artifacts_by_type(Service)),
                    'credentials': len(self.context.get_artifacts_by_type(Credential)),
                    'files': len(self.context.get_artifacts_by_type(FileArtifact)),
                    'hashes': len(self.context.get_artifacts_by_type(HashArtifact)),
                }
            }
            
            logger.info(f"Pipeline completed in {duration:.2f}s, ran {len(stages_run)} stages")
            return result
            
        except Exception as e:
            logger.error(f"Pipeline execution failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'stages_run': stages_run if 'stages_run' in locals() else []
            }
        finally:
            self.running = False
    
    def _plan_execution(self) -> Dict[str, any]:
        """Plan what stages would be executed."""
        plan = {
            'planned_stages': [],
            'blocked_stages': [],
            'available_artifacts': {
                'services': len(self.context.get_artifacts_by_type(Service)),
                'credentials': len(self.context.get_artifacts_by_type(Credential)),
                'files': len(self.context.get_artifacts_by_type(FileArtifact)),
                'hashes': len(self.context.get_artifacts_by_type(HashArtifact)),
            }
        }
        
        # Check each stage
        for rule in sorted(self.rules, key=lambda r: r.priority, reverse=True):
            if rule.can_run(self.context):
                plan['planned_stages'].append({
                    'name': rule.name,
                    'priority': rule.priority,
                    'requires_artifacts': rule.requires_artifacts,
                    'requires_completed': rule.requires_completed
                })
            else:
                # Determine why it's blocked
                reasons = []
                
                if self.context.is_stage_completed(rule.name):
                    reasons.append("already completed")
                
                if self.context.is_stage_failed(rule.name):
                    reasons.append("previously failed")
                
                for req_stage in rule.requires_completed:
                    if not self.context.is_stage_completed(req_stage):
                        reasons.append(f"requires {req_stage}")
                
                for artifact_type in rule.requires_artifacts:
                    if not self._has_artifact_type(artifact_type):
                        reasons.append(f"requires {artifact_type}")
                
                plan['blocked_stages'].append({
                    'name': rule.name,
                    'reasons': reasons
                })
        
        return plan
    
    def _get_next_stage(self) -> Optional[StageRule]:
        """Get the next stage that should be executed."""
        runnable_stages = [rule for rule in self.rules if rule.can_run(self.context)]
        
        if not runnable_stages:
            return None
        
        # Sort by priority (highest first)
        runnable_stages.sort(key=lambda r: r.priority, reverse=True)
        
        return runnable_stages[0]
    
    def _execute_stage(self, rule: StageRule) -> bool:
        """Execute a stage and handle the results."""
        try:
            # Emit stage start event
            self.context.emit_stage_start(rule.name)
            
            # Execute the stage function
            result = rule.stage_function()
            
            # Count artifacts produced
            artifacts_count = 0
            if isinstance(result, list):
                artifacts_count = len(result)
            elif result is not None:
                artifacts_count = 1
            
            # Emit stage complete event
            self.context.emit_stage_complete(rule.name, True, artifacts_count)
            
            logger.info(f"Stage {rule.name} completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Stage {rule.name} failed: {e}")
            
            # Emit stage complete event (failed)
            self.context.emit_stage_complete(rule.name, False, 0)
            
            return False
    
    def _has_artifact_type(self, artifact_type: str) -> bool:
        """Check if we have any artifacts of the given type."""
        if artifact_type == "Service":
            return len(self.context.get_artifacts_by_type(Service)) > 0
        elif artifact_type == "Credential":
            return len(self.context.get_artifacts_by_type(Credential)) > 0
        elif artifact_type == "FileArtifact":
            return len(self.context.get_artifacts_by_type(FileArtifact)) > 0
        elif artifact_type == "HashArtifact":
            return len(self.context.get_artifacts_by_type(HashArtifact)) > 0
        
        return False
    
    def pause(self) -> None:
        """Pause the orchestrator."""
        self.paused = True
        logger.info("Orchestrator paused")
    
    def resume(self) -> None:
        """Resume the orchestrator."""
        self.paused = False
        logger.info("Orchestrator resumed")
    
    def stop(self) -> None:
        """Stop the orchestrator."""
        self.running = False
        self.paused = False
        logger.info("Orchestrator stopped")
    
    def get_status(self) -> Dict[str, any]:
        """Get current orchestrator status."""
        return {
            'running': self.running,
            'paused': self.paused,
            'completed_stages': self.context.state.completed_stages,
            'failed_stages': self.context.state.failed_stages,
            'artifacts': {
                'services': len(self.context.get_artifacts_by_type(Service)),
                'credentials': len(self.context.get_artifacts_by_type(Credential)),
                'files': len(self.context.get_artifacts_by_type(FileArtifact)),
                'hashes': len(self.context.get_artifacts_by_type(HashArtifact)),
            }
        }
    
    def force_run_stage(self, stage_name: str) -> bool:
        """Force run a specific stage regardless of rules."""
        for rule in self.rules:
            if rule.name == stage_name:
                logger.info(f"Force running stage: {stage_name}")
                return self._execute_stage(rule)
        
        logger.error(f"Stage not found: {stage_name}")
        return False
    
    def _on_artifact_found(self, event: ArtifactFoundEvent) -> None:
        """Handle artifact found events."""
        logger.debug(f"Artifact found: {event.artifact_type}")
        
        # Trigger re-planning when new artifacts are found
        if self.running and not self.paused:
            # New artifacts might enable new stages
            pass
    
    def _on_stage_complete(self, event: StageCompleteEvent) -> None:
        """Handle stage completion events."""
        if event.success:
            logger.info(f"Stage {event.stage_name} completed with {event.artifacts_count} artifacts")
        else:
            logger.warning(f"Stage {event.stage_name} failed")
    
    def _on_user_inject(self, event: UserInjectEvent) -> None:
        """Handle user injection events."""
        logger.info(f"User injected {event.injection_type}: {event.injection_data}")
        
        # User injections might enable new stages, trigger re-planning
        if event.injection_type == "creds":
            logger.debug("New credentials injected, may enable spray stages")
        elif event.injection_type == "hint":
            logger.debug("Hint injected, may influence stage selection")


def create_orchestrator(context: RunContext) -> Orchestrator:
    """Create an orchestrator instance."""
    return Orchestrator(context)
