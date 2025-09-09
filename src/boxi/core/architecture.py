"""
Core architecture patterns and base classes for boxi.

Defines the fundamental building blocks that implement the pentester mindset:
- Methodical reconnaissance and enumeration
- Intelligent decision-making and prioritization  
- Evidence preservation and audit trails
- Adaptive techniques based on discovered information
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from datetime import datetime

from boxi.core.logging import get_logger

logger = get_logger(__name__)


class ThreatLevel(Enum):
    """Threat levels for operational security awareness."""
    LOW = "low"
    MEDIUM = "medium"  
    HIGH = "high"
    CRITICAL = "critical"


class PentestPhase(Enum):
    """Standard penetration testing methodology phases."""
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


@dataclass
class Evidence:
    """
    Represents a piece of evidence discovered during testing.
    
    Following the pentester mindset of documenting everything:
    - What was found
    - How it was found  
    - When it was found
    - Confidence level
    - Chain of discovery
    """
    evidence_type: str
    data: Dict[str, Any]
    source: str
    confidence: float  # 0.0 to 1.0
    discovered_at: datetime
    metadata: Dict[str, Any]
    
    def __post_init__(self):
        """Validate evidence after creation."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")
        
        if not self.evidence_type:
            raise ValueError("Evidence type cannot be empty")


@dataclass  
class Target:
    """
    Represents a target in the pentesting scope.
    
    Implements the broad-to-narrow reconnaissance approach:
    - Start with basic identification
    - Build detailed profile over time
    - Track what's been tested
    """
    identifier: str  # IP, hostname, etc.
    target_type: str = "host"
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    metadata: Dict[str, Any] = None
    tested_techniques: Set[str] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.tested_techniques is None:
            self.tested_techniques = set()


class Technique(ABC):
    """
    Base class for penetration testing techniques.
    
    Implements the pentester mindset:
    - Each technique has prerequisites and success criteria
    - Tracks what was attempted and results
    - Provides decision-making input for next steps
    - Maintains operational security awareness
    """
    
    def __init__(self, name: str, phase: PentestPhase):
        self.name = name
        self.phase = phase
        self.evidence_gathered: List[Evidence] = []
        self.execution_log: List[Dict[str, Any]] = []
    
    @abstractmethod
    def can_execute(self, target: Target, context: Dict[str, Any]) -> bool:
        """
        Determine if this technique can be executed against the target.
        
        Implements intelligent decision-making based on:
        - Target characteristics
        - Previously gathered evidence  
        - Current context and constraints
        """
        pass
    
    @abstractmethod
    def get_priority(self, target: Target, context: Dict[str, Any]) -> float:
        """
        Calculate priority for executing this technique.
        
        Returns priority score (0.0 to 1.0) based on:
        - Likelihood of success
        - Potential impact
        - Risk vs reward
        - Operational security considerations
        """
        pass
    
    @abstractmethod
    def execute(self, target: Target, context: Dict[str, Any]) -> List[Evidence]:
        """
        Execute the technique against the target.
        
        Returns:
            List of evidence gathered during execution
        """
        pass
    
    def log_execution(self, action: str, result: str, metadata: Dict[str, Any] = None) -> None:
        """Log an execution step for audit trail."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "result": result,
            "metadata": metadata or {}
        }
        self.execution_log.append(log_entry)
        logger.debug(f"[{self.name}] {action}: {result}")
    
    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence gathered by this technique."""
        self.evidence_gathered.append(evidence)
        logger.info(f"[{self.name}] Gathered {evidence.evidence_type} evidence")


class Orchestrator:
    """
    Core orchestration engine that thinks like a top-tier pentester.
    
    Implements the methodical approach:
    - Maintains current understanding of targets
    - Prioritizes techniques based on gathered intelligence
    - Adapts strategy based on discoveries
    - Preserves complete audit trail
    """
    
    def __init__(self):
        self.targets: Dict[str, Target] = {}
        self.techniques: List[Technique] = []
        self.global_evidence: List[Evidence] = []
        self.current_phase = PentestPhase.RECONNAISSANCE
        self.execution_history: List[Dict[str, Any]] = []
    
    def add_target(self, target: Target) -> None:
        """Add a target to the scope."""
        self.targets[target.identifier] = target
        logger.info(f"Added target: {target.identifier}")
    
    def register_technique(self, technique: Technique) -> None:
        """Register a technique with the orchestrator."""
        self.techniques.append(technique)
        logger.debug(f"Registered technique: {technique.name}")
    
    def get_next_actions(self, target_id: str) -> List[Technique]:
        """
        Determine next actions for a target using pentester decision-making.
        
        Implements intelligent prioritization:
        - Start broad, narrow focus based on discoveries
        - Chain discoveries to inform next steps  
        - Consider operational security
        - Avoid rabbit holes with time management
        """
        target = self.targets.get(target_id)
        if not target:
            return []
        
        # Build context from all gathered evidence
        context = self._build_context(target)
        
        # Get executable techniques for current phase
        available_techniques = [
            t for t in self.techniques 
            if t.phase == self.current_phase and t.can_execute(target, context)
        ]
        
        # Sort by priority (pentester decision-making)
        prioritized = sorted(
            available_techniques,
            key=lambda t: t.get_priority(target, context),
            reverse=True
        )
        
        logger.debug(f"Identified {len(prioritized)} prioritized techniques for {target_id}")
        return prioritized
    
    def execute_technique(self, technique: Technique, target_id: str) -> List[Evidence]:
        """
        Execute a technique and process results.
        
        Maintains audit trail and updates global knowledge.
        """
        target = self.targets[target_id]
        context = self._build_context(target)
        
        logger.info(f"Executing {technique.name} against {target_id}")
        
        # Execute technique
        evidence = technique.execute(target, context)
        
        # Process results
        for item in evidence:
            self.global_evidence.append(item)
            target.metadata.setdefault('discoveries', []).append({
                'evidence_type': item.evidence_type,
                'source': item.source,
                'timestamp': item.discovered_at.isoformat()
            })
        
        # Mark technique as tested
        target.tested_techniques.add(technique.name)
        
        # Log execution
        self.execution_history.append({
            'timestamp': datetime.now().isoformat(),
            'technique': technique.name,
            'target': target_id,
            'evidence_count': len(evidence),
            'phase': self.current_phase.value
        })
        
        logger.info(f"Completed {technique.name}: gathered {len(evidence)} evidence items")
        return evidence
    
    def advance_phase(self, new_phase: PentestPhase) -> None:
        """Advance to the next phase of testing."""
        logger.info(f"Advancing from {self.current_phase.value} to {new_phase.value}")
        self.current_phase = new_phase
    
    def _build_context(self, target: Target) -> Dict[str, Any]:
        """
        Build context for decision-making.
        
        Aggregates all relevant information for intelligent technique selection.
        """
        # Get evidence relevant to this target
        target_evidence = [
            e for e in self.global_evidence 
            if target.identifier in str(e.data) or e.source == target.identifier
        ]
        
        return {
            'target': target,
            'evidence_count': len(target_evidence),
            'tested_techniques': target.tested_techniques,
            'current_phase': self.current_phase,
            'threat_level': target.threat_level,
            'recent_evidence': target_evidence[-10:],  # Last 10 pieces of evidence
        }


class ReconTechnique(Technique):
    """Base class for reconnaissance techniques."""
    
    def __init__(self, name: str):
        super().__init__(name, PentestPhase.RECONNAISSANCE)


class EnumerationTechnique(Technique):
    """Base class for enumeration techniques."""
    
    def __init__(self, name: str):
        super().__init__(name, PentestPhase.ENUMERATION)


class ExploitationTechnique(Technique):
    """Base class for exploitation techniques."""
    
    def __init__(self, name: str):
        super().__init__(name, PentestPhase.EXPLOITATION)


class PostExploitationTechnique(Technique):
    """Base class for post-exploitation techniques."""
    
    def __init__(self, name: str):
        super().__init__(name, PentestPhase.POST_EXPLOITATION)
