"""Tests for orchestrator functionality."""

import pytest
from unittest.mock import Mock, patch

from boxi.artifacts import Credential, Service, ServiceState
from boxi.orchestrator import Orchestrator, StageRule
from boxi.runtime import RunContext


class TestStageRule:
    """Test StageRule logic."""
    
    def test_basic_rule(self):
        mock_function = Mock(return_value=[])
        
        rule = StageRule(
            name="test_stage",
            stage_function=mock_function,
            priority=50
        )
        
        assert rule.name == "test_stage"
        assert rule.priority == 50
        assert rule.max_runs == 1
        assert rule.run_count == 0
    
    def test_rule_can_run_basic(self):
        mock_function = Mock()
        
        rule = StageRule(
            name="test_stage",
            stage_function=mock_function
        )
        
        # Mock context
        context = Mock()
        context.is_stage_completed.return_value = False
        context.is_stage_failed.return_value = False
        context.is_stage_running.return_value = False
        
        assert rule.can_run(context) is True
    
    def test_rule_cannot_run_if_completed(self):
        mock_function = Mock()
        
        rule = StageRule(
            name="test_stage",
            stage_function=mock_function
        )
        
        # Mock context with completed stage
        context = Mock()
        context.is_stage_completed.return_value = True
        context.is_stage_failed.return_value = False
        context.is_stage_running.return_value = False
        
        assert rule.can_run(context) is False
    
    def test_rule_cannot_run_if_failed(self):
        mock_function = Mock()
        
        rule = StageRule(
            name="test_stage",
            stage_function=mock_function
        )
        
        # Mock context with failed stage
        context = Mock()
        context.is_stage_completed.return_value = False
        context.is_stage_failed.return_value = True
        context.is_stage_running.return_value = False
        
        assert rule.can_run(context) is False
    
    def test_rule_requires_artifacts(self):
        mock_function = Mock()
        
        rule = StageRule(
            name="test_stage",
            stage_function=mock_function,
            requires_artifacts=["Service"]
        )
        
        # Mock context without required artifacts
        context = Mock()
        context.is_stage_completed.return_value = False
        context.is_stage_failed.return_value = False
        context.is_stage_running.return_value = False
        context.get_artifacts_by_type.return_value = []  # No services
        
        assert rule.can_run(context) is False
        
        # Mock context with required artifacts
        mock_service = Service(target_host="test", port=80, protocol="tcp")
        context.get_artifacts_by_type.return_value = [mock_service]
        
        assert rule.can_run(context) is True
    
    def test_rule_requires_completed_stages(self):
        mock_function = Mock()
        
        rule = StageRule(
            name="test_stage",
            stage_function=mock_function,
            requires_completed=["port_scan"]
        )
        
        # Mock context without required completed stages
        context = Mock()
        context.is_stage_completed.side_effect = lambda stage: stage != "port_scan"
        context.is_stage_failed.return_value = False
        context.is_stage_running.return_value = False
        
        assert rule.can_run(context) is False
        
        # Mock context with required completed stages
        context.is_stage_completed.side_effect = lambda stage: True
        
        assert rule.can_run(context) is True
    
    def test_rule_max_runs(self):
        mock_function = Mock()
        
        rule = StageRule(
            name="test_stage",
            stage_function=mock_function,
            max_runs=2
        )
        
        context = Mock()
        context.is_stage_completed.return_value = False
        context.is_stage_failed.return_value = False
        context.is_stage_running.return_value = False
        
        # First run should be allowed
        assert rule.can_run(context) is True
        rule.run_count = 1
        
        # Second run should be allowed
        assert rule.can_run(context) is True
        rule.run_count = 2
        
        # Third run should not be allowed
        assert rule.can_run(context) is False


class TestOrchestrator:
    """Test Orchestrator functionality."""
    
    @pytest.fixture
    def mock_context(self):
        """Create a mock context for testing."""
        context = Mock(spec=RunContext)
        context.target = "10.10.10.10"
        context.event_bus = Mock()
        
        # Default stage states
        context.is_stage_completed.return_value = False
        context.is_stage_failed.return_value = False
        context.is_stage_running.return_value = False
        
        # Default artifacts
        context.get_artifacts_by_type.return_value = []
        
        return context
    
    def test_orchestrator_creation(self, mock_context):
        orchestrator = Orchestrator(mock_context)
        
        assert orchestrator.context == mock_context
        assert orchestrator.running is False
        assert orchestrator.paused is False
        assert len(orchestrator.rules) > 0
        
        # Should subscribe to events
        assert mock_context.event_bus.subscribe.call_count >= 3
    
    def test_get_next_stage(self, mock_context):
        orchestrator = Orchestrator(mock_context)
        
        # Mock some runnable stages
        for rule in orchestrator.rules[:3]:
            rule.can_run = Mock(return_value=True)
        
        for rule in orchestrator.rules[3:]:
            rule.can_run = Mock(return_value=False)
        
        next_stage = orchestrator._get_next_stage()
        
        assert next_stage is not None
        assert next_stage in orchestrator.rules[:3]
        
        # Should return highest priority stage
        priorities = [rule.priority for rule in orchestrator.rules[:3]]
        assert next_stage.priority == max(priorities)
    
    def test_get_next_stage_none_runnable(self, mock_context):
        orchestrator = Orchestrator(mock_context)
        
        # Mock no runnable stages
        for rule in orchestrator.rules:
            rule.can_run = Mock(return_value=False)
        
        next_stage = orchestrator._get_next_stage()
        assert next_stage is None
    
    def test_execute_stage_success(self, mock_context):
        orchestrator = Orchestrator(mock_context)
        
        # Create a mock stage that succeeds
        mock_stage_function = Mock(return_value=["result1", "result2"])
        rule = StageRule("test_stage", mock_stage_function)
        
        result = orchestrator._execute_stage(rule)
        
        assert result is True
        mock_stage_function.assert_called_once()
        
        # Should emit events
        mock_context.emit_stage_start.assert_called_once_with("test_stage")
        mock_context.emit_stage_complete.assert_called_once_with("test_stage", True, 2)
    
    def test_execute_stage_failure(self, mock_context):
        orchestrator = Orchestrator(mock_context)
        
        # Create a mock stage that fails
        mock_stage_function = Mock(side_effect=Exception("Stage failed"))
        rule = StageRule("test_stage", mock_stage_function)
        
        result = orchestrator._execute_stage(rule)
        
        assert result is False
        mock_stage_function.assert_called_once()
        
        # Should emit failure event
        mock_context.emit_stage_complete.assert_called_once_with("test_stage", False, 0)
    
    def test_pause_resume_stop(self, mock_context):
        orchestrator = Orchestrator(mock_context)
        
        # Test pause
        orchestrator.pause()
        assert orchestrator.paused is True
        
        # Test resume
        orchestrator.resume()
        assert orchestrator.paused is False
        
        # Test stop
        orchestrator.stop()
        assert orchestrator.running is False
        assert orchestrator.paused is False
    
    def test_get_status(self, mock_context):
        # Mock some state
        mock_context.state.completed_stages = ["port_scan", "ftp_enum"]
        mock_context.state.failed_stages = ["smb_spray"]
        
        # Mock artifacts
        mock_context.get_artifacts_by_type.side_effect = lambda t: {
            Service: [Mock(), Mock()],  # 2 services
            Credential: [Mock()],       # 1 credential
        }.get(t, [])
        
        orchestrator = Orchestrator(mock_context)
        status = orchestrator.get_status()
        
        assert status['running'] is False
        assert status['paused'] is False
        assert status['completed_stages'] == ["port_scan", "ftp_enum"]
        assert status['failed_stages'] == ["smb_spray"]
        assert status['artifacts']['services'] == 2
        assert status['artifacts']['credentials'] == 1
    
    def test_force_run_stage(self, mock_context):
        orchestrator = Orchestrator(mock_context)
        
        # Mock a stage function
        for rule in orchestrator.rules:
            if rule.name == "port_scan":
                rule.stage_function = Mock(return_value=[])
                break
        
        result = orchestrator.force_run_stage("port_scan")
        assert result is True
        
        # Test non-existent stage
        result = orchestrator.force_run_stage("nonexistent_stage")
        assert result is False
    
    def test_plan_execution(self, mock_context):
        orchestrator = Orchestrator(mock_context)
        
        # Mock some runnable and some blocked stages
        runnable_stages = orchestrator.rules[:2]
        blocked_stages = orchestrator.rules[2:4]
        
        for rule in runnable_stages:
            rule.can_run = Mock(return_value=True)
        
        for rule in blocked_stages:
            rule.can_run = Mock(return_value=False)
        
        plan = orchestrator._plan_execution()
        
        assert 'planned_stages' in plan
        assert 'blocked_stages' in plan
        assert 'available_artifacts' in plan
        
        assert len(plan['planned_stages']) == len(runnable_stages)
        assert len(plan['blocked_stages']) == len(blocked_stages)
    
    def test_has_artifact_type(self, mock_context):
        orchestrator = Orchestrator(mock_context)
        
        # Mock empty artifacts
        mock_context.get_artifacts_by_type.return_value = []
        assert orchestrator._has_artifact_type("Service") is False
        
        # Mock with artifacts
        mock_context.get_artifacts_by_type.return_value = [Mock()]
        assert orchestrator._has_artifact_type("Service") is True
    
    @patch('time.sleep')  # Speed up test
    def test_pipeline_execution_dry_run(self, mock_sleep, mock_context):
        orchestrator = Orchestrator(mock_context)
        
        # Mock plan execution
        expected_plan = {'planned_stages': [], 'blocked_stages': []}
        orchestrator._plan_execution = Mock(return_value=expected_plan)
        
        result = orchestrator.run_pipeline(dry_run=True)
        
        assert result == expected_plan
        orchestrator._plan_execution.assert_called_once()
    
    @patch('time.sleep')  # Speed up test
    def test_pipeline_execution_no_stages(self, mock_sleep, mock_context):
        orchestrator = Orchestrator(mock_context)
        
        # Mock no runnable stages
        orchestrator._get_next_stage = Mock(return_value=None)
        
        result = orchestrator.run_pipeline(max_iterations=5)
        
        assert result['success'] is True
        assert result['iterations'] == 1
        assert result['stages_run'] == []
    
    @patch('time.sleep')  # Speed up test  
    def test_pipeline_execution_with_stages(self, mock_sleep, mock_context):
        orchestrator = Orchestrator(mock_context)
        
        # Create mock stages
        stage1 = Mock()
        stage1.name = "stage1"
        stage1.run_count = 0
        
        stage2 = Mock()
        stage2.name = "stage2"  
        stage2.run_count = 0
        
        # Mock stage execution order
        call_count = [0]
        def get_next_stage():
            if call_count[0] == 0:
                call_count[0] += 1
                return stage1
            elif call_count[0] == 1:
                call_count[0] += 1
                return stage2
            else:
                return None
        
        orchestrator._get_next_stage = get_next_stage
        orchestrator._execute_stage = Mock(return_value=True)
        
        result = orchestrator.run_pipeline(max_iterations=5)
        
        assert result['success'] is True
        assert result['stages_run'] == ["stage1", "stage2"]
        assert orchestrator._execute_stage.call_count == 2


class TestOrchestratorIntegration:
    """Test orchestrator integration with real context."""
    
    def test_real_context_integration(self):
        """Test orchestrator with a real context object."""
        context = RunContext("10.10.10.10")
        orchestrator = Orchestrator(context)
        
        # Should create orchestrator successfully
        assert orchestrator.context == context
        assert len(orchestrator.rules) > 0
        
        # Test initial planning
        plan = orchestrator._plan_execution()
        
        assert 'planned_stages' in plan
        assert 'blocked_stages' in plan
        
        # port_scan should be runnable initially (no requirements)
        port_scan_planned = any(
            stage['name'] == 'port_scan' 
            for stage in plan['planned_stages']
        )
        assert port_scan_planned
    
    def test_stage_dependencies(self):
        """Test that stage dependencies work correctly."""
        context = RunContext("10.10.10.10")
        orchestrator = Orchestrator(context)
        
        # Initially only port_scan should be runnable
        next_stage = orchestrator._get_next_stage()
        assert next_stage.name == "port_scan"
        
        # After completing port_scan, mark it complete
        context.emit_stage_complete("port_scan", True, 0)
        
        # Add some services to enable other stages
        service = Service(
            target_host="10.10.10.10",
            port=21,
            protocol="tcp",
            service_name="ftp",
            state=ServiceState.OPEN
        )
        context.add_service(service)
        
        # Now ftp_enum should be runnable
        plan = orchestrator._plan_execution()
        ftp_enum_planned = any(
            stage['name'] == 'ftp_enum'
            for stage in plan['planned_stages']
        )
        assert ftp_enum_planned
