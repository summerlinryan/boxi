"""Tests for core boxi components."""

import pytest
from datetime import datetime
from pathlib import Path
import tempfile

from boxi.core.architecture import (
    Evidence, Target, Technique, Orchestrator,
    PentestPhase, ThreatLevel, ReconTechnique
)
from boxi.core.database import Database


class TestEvidence:
    """Test Evidence class."""
    
    def test_basic_evidence(self):
        evidence = Evidence(
            evidence_type="service",
            data={"port": 80, "service": "http"},
            source="nmap",
            confidence=0.9,
            discovered_at=datetime.now(),
            metadata={"scan_type": "tcp"}
        )
        
        assert evidence.evidence_type == "service"
        assert evidence.confidence == 0.9
        assert evidence.data["port"] == 80
    
    def test_confidence_validation(self):
        with pytest.raises(ValueError):
            Evidence(
                evidence_type="test",
                data={},
                source="test",
                confidence=1.5,  # Invalid confidence
                discovered_at=datetime.now(),
                metadata={}
            )


class TestTarget:
    """Test Target class."""
    
    def test_basic_target(self):
        target = Target(identifier="10.10.10.10")
        
        assert target.identifier == "10.10.10.10"
        assert target.target_type == "host"
        assert target.threat_level == ThreatLevel.MEDIUM
        assert isinstance(target.metadata, dict)
        assert isinstance(target.tested_techniques, set)
    
    def test_target_with_custom_values(self):
        target = Target(
            identifier="critical-server.example.com",
            target_type="server",
            threat_level=ThreatLevel.HIGH
        )
        
        assert target.threat_level == ThreatLevel.HIGH
        assert target.target_type == "server"


class MockReconTechnique(ReconTechnique):
    """Mock reconnaissance technique for testing."""
    
    def __init__(self):
        super().__init__("mock_recon")
    
    def can_execute(self, target: Target, context: dict) -> bool:
        return True
    
    def get_priority(self, target: Target, context: dict) -> float:
        return 0.8
    
    def execute(self, target: Target, context: dict) -> list[Evidence]:
        evidence = Evidence(
            evidence_type="service",
            data={"port": 22, "service": "ssh"},
            source=self.name,
            confidence=0.9,
            discovered_at=datetime.now(),
            metadata={}
        )
        self.add_evidence(evidence)
        return [evidence]


class TestTechnique:
    """Test Technique base class functionality."""
    
    def test_technique_execution_logging(self):
        technique = MockReconTechnique()
        
        technique.log_execution("scan", "port 22 open", {"method": "tcp"})
        
        assert len(technique.execution_log) == 1
        assert technique.execution_log[0]["action"] == "scan"
        assert technique.execution_log[0]["result"] == "port 22 open"
    
    def test_evidence_gathering(self):
        technique = MockReconTechnique()
        target = Target("10.10.10.10")
        
        evidence = technique.execute(target, {})
        
        assert len(evidence) == 1
        assert evidence[0].evidence_type == "service"
        assert len(technique.evidence_gathered) == 1


class TestOrchestrator:
    """Test Orchestrator functionality."""
    
    def test_orchestrator_creation(self):
        orchestrator = Orchestrator()
        
        assert len(orchestrator.targets) == 0
        assert len(orchestrator.techniques) == 0
        assert orchestrator.current_phase == PentestPhase.RECONNAISSANCE
    
    def test_target_management(self):
        orchestrator = Orchestrator()
        target = Target("192.168.1.1")
        
        orchestrator.add_target(target)
        
        assert len(orchestrator.targets) == 1
        assert "192.168.1.1" in orchestrator.targets
    
    def test_technique_registration(self):
        orchestrator = Orchestrator()
        technique = MockReconTechnique()
        
        orchestrator.register_technique(technique)
        
        assert len(orchestrator.techniques) == 1
        assert orchestrator.techniques[0].name == "mock_recon"
    
    def test_next_actions_selection(self):
        orchestrator = Orchestrator()
        target = Target("test-target")
        technique = MockReconTechnique()
        
        orchestrator.add_target(target)
        orchestrator.register_technique(technique)
        
        actions = orchestrator.get_next_actions("test-target")
        
        assert len(actions) == 1
        assert actions[0].name == "mock_recon"
    
    def test_technique_execution(self):
        orchestrator = Orchestrator()
        target = Target("test-target")
        technique = MockReconTechnique()
        
        orchestrator.add_target(target)
        orchestrator.register_technique(technique)
        
        evidence = orchestrator.execute_technique(technique, "test-target")
        
        assert len(evidence) == 1
        assert len(orchestrator.global_evidence) == 1
        assert "mock_recon" in target.tested_techniques
    
    def test_phase_advancement(self):
        orchestrator = Orchestrator()
        
        orchestrator.advance_phase(PentestPhase.ENUMERATION)
        
        assert orchestrator.current_phase == PentestPhase.ENUMERATION


class TestDatabase:
    """Test Database functionality."""
    
    def test_database_creation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            db = Database(db_path)
            
            assert db_path.exists()
    
    def test_run_creation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            db = Database(db_path)
            
            run_id = db.create_run("10.10.10.10", {"test": True})
            
            assert isinstance(run_id, int)
            assert run_id > 0
    
    def test_run_retrieval(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            db = Database(db_path)
            
            run_id = db.create_run("10.10.10.10")
            run_data = db.get_run(run_id)
            
            assert run_data is not None
            assert run_data["target"] == "10.10.10.10"
            assert run_data["status"] == "running"
    
    def test_artifact_storage(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            db = Database(db_path)
            
            run_id = db.create_run("test-target")
            artifact_id = db.add_artifact(
                run_id=run_id,
                artifact_type="service",
                artifact_data={"port": 80, "service": "http"},
                source="nmap",
                confidence=0.9
            )
            
            artifacts = db.get_artifacts(run_id)
            
            assert len(artifacts) == 1
            assert artifacts[0]["artifact_type"] == "service"
            assert artifacts[0]["artifact_data"]["port"] == 80
    
    def test_event_logging(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            db = Database(db_path)
            
            run_id = db.create_run("test-target")
            event_id = db.log_event(
                run_id=run_id,
                event_type="technique_executed",
                event_data={"technique": "port_scan", "result": "success"}
            )
            
            events = db.get_events(run_id)
            
            assert len(events) == 1
            assert events[0]["event_type"] == "technique_executed"
            assert events[0]["event_data"]["technique"] == "port_scan"
