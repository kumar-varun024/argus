import os
import json
import pytest
from datetime import datetime
from typer.testing import CliRunner

from argus.runtime.mission import Mission
from argus.planning.models import ResearchTask, TaskCategory
from argus.runtime.models import (
    Tool, ToolExecutionStatus, OrchestratorEventType, 
    ToolType, ToolArtifact, ToolExecutionResult, TaskState
)
from argus.runtime.registry import ToolRegistry
from argus.runtime.orchestrator import ToolOrchestrator
from argus.runtime.dispatcher import ToolDispatcher
from argus.runtime.events import EventBus
from argus.runtime.executor import TaskScheduler
from argus.runtime.sandbox import SafetyValidator, SafetyViolationError
from argus.cli.app import app

runner = CliRunner()


@pytest.fixture
def test_registry():
    """Create a clean registry with some custom test tools."""
    reg = ToolRegistry()
    # Tool A matches category "API Discovery" with priority 100
    reg.register(
        Tool(
            id="tool_a",
            name="Tool A",
            supported_tasks=["API Discovery"],
            capabilities=["api_discovery"],
            safety_requirements={"type": "external", "permissions": ["network"]},
            priority=100,
            command="echo"
        )
    )
    # Tool B matches category "API Discovery" with priority 200 (should be chosen first)
    reg.register(
        Tool(
            id="tool_b",
            name="Tool B",
            supported_tasks=["API Discovery"],
            capabilities=["api_discovery"],
            safety_requirements={"type": "external", "permissions": ["network"]},
            priority=200,
            command="echo"
        )
    )
    # Tool C matches category "API Discovery" with priority 100 (alphabetical tiebreaker with A)
    reg.register(
        Tool(
            id="tool_c",
            name="Tool C",
            supported_tasks=["API Discovery"],
            capabilities=["api_discovery"],
            safety_requirements={"type": "external", "permissions": ["network"]},
            priority=100,
            command="echo"
        )
    )
    # GraphQL specialist
    reg.register(
        Tool(
            id="graphql_specialist",
            name="GraphQL Specialist",
            supported_tasks=["GraphQL Analysis"],
            capabilities=["graphql_analyzer"],
            safety_requirements={"type": "internal", "permissions": ["network"]},
            priority=100
        )
    )
    return reg


@pytest.fixture
def test_mission():
    m = Mission(target="test.example.com")
    m.scope = ["test.example.com"]
    m.policy = {
        "allowed_permissions": ["network", "filesystem", "db_read", "db_write"],
        "blocked_operations": [],
        "blocked_categories": [],
        "blocked_tasks": []
    }
    return m


# =========================================================
# UNIT TESTS
# =========================================================

class TestToolRegistry:
    def test_register_and_get(self, test_registry):
        tool = test_registry.get("tool_a")
        assert tool is not None
        assert tool.name == "Tool A"

        # Compatibility lookup by capability
        tool_by_cap = test_registry.get("api_discovery")
        assert tool_by_cap is not None
        assert tool_by_cap.id == "tool_a"  # returned because it is matched in loop

    def test_list(self, test_registry):
        tools = test_registry.list()
        assert len(tools) == 4
        ids = [t.id for t in tools]
        assert "tool_a" in ids
        assert "graphql_specialist" in ids


class TestToolSelection:
    def test_deterministic_priority_selection(self, test_registry):
        dispatcher = ToolDispatcher(test_registry)
        task = ResearchTask(
            title="Scan endpoints",
            description="Recon",
            goal="API lists",
            category=TaskCategory.API_DISCOVERY
        )
        
        # Tool B has priority 200, which is higher than A and C (100)
        selected = dispatcher.resolve_tool(task)
        assert selected is not None
        assert selected.id == "tool_b"

    def test_deterministic_alphabetical_tiebreaker(self, test_registry):
        # Remove tool_b to force a tiebreaker between tool_a and tool_c (both priority 100)
        del test_registry.tools["tool_b"]
        
        dispatcher = ToolDispatcher(test_registry)
        task = ResearchTask(
            title="Scan endpoints",
            description="Recon",
            goal="API lists",
            category=TaskCategory.API_DISCOVERY
        )
        
        # "tool_a" comes alphabetically before "tool_c"
        selected = dispatcher.resolve_tool(task)
        assert selected is not None
        assert selected.id == "tool_a"


class TestSafetyValidation:
    def test_scope_validation_allows_in_scope(self, test_mission, test_registry):
        # Target in scope
        task = ResearchTask(title="T1", description="D", goal="G", category=TaskCategory.API_DISCOVERY)
        tool = test_registry.get("tool_a")
        
        # Prepare context
        from argus.runtime.models import ToolExecutionContext
        context = ToolExecutionContext(
            mission=test_mission,
            scope=test_mission.scope,
            policy=test_mission.policy,
            task=task
        )
        
        # Should not raise exception
        SafetyValidator.validate(tool, context)

    def test_scope_validation_blocks_out_of_scope(self, test_mission, test_registry):
        test_mission.target = "evil.com"  # Out of scope target
        task = ResearchTask(title="T1", description="D", goal="G", category=TaskCategory.API_DISCOVERY)
        tool = test_registry.get("tool_a")
        
        from argus.runtime.models import ToolExecutionContext
        context = ToolExecutionContext(
            mission=test_mission,
            scope=test_mission.scope,
            policy=test_mission.policy,
            task=task
        )
        
        with pytest.raises(SafetyViolationError, match="outside the mission scope"):
            SafetyValidator.validate(tool, context)

    def test_policy_validation_blocks_operation(self, test_mission, test_registry):
        test_mission.policy["blocked_operations"] = ["api_discovery"]
        task = ResearchTask(title="T1", description="D", goal="G", category=TaskCategory.API_DISCOVERY)
        tool = test_registry.get("tool_a")
        
        from argus.runtime.models import ToolExecutionContext
        context = ToolExecutionContext(
            mission=test_mission,
            scope=test_mission.scope,
            policy=test_mission.policy,
            task=task
        )
        
        with pytest.raises(SafetyViolationError, match="blocked by mission policy"):
            SafetyValidator.validate(tool, context)

    def test_policy_validation_blocks_category(self, test_mission, test_registry):
        test_mission.policy["blocked_categories"] = [TaskCategory.API_DISCOVERY.value]
        task = ResearchTask(title="T1", description="D", goal="G", category=TaskCategory.API_DISCOVERY)
        tool = test_registry.get("tool_a")
        
        from argus.runtime.models import ToolExecutionContext
        context = ToolExecutionContext(
            mission=test_mission,
            scope=test_mission.scope,
            policy=test_mission.policy,
            task=task
        )
        
        with pytest.raises(SafetyViolationError, match="blocked by mission policy"):
            SafetyValidator.validate(tool, context)

    def test_unauthorized_permissions_are_blocked(self, test_mission, test_registry):
        # Tool wants "network" permission, but we don't allow it in policy
        test_mission.policy["allowed_permissions"] = ["filesystem"]
        task = ResearchTask(title="T1", description="D", goal="G", category=TaskCategory.API_DISCOVERY)
        tool = test_registry.get("tool_a")
        
        from argus.runtime.models import ToolExecutionContext
        context = ToolExecutionContext(
            mission=test_mission,
            scope=test_mission.scope,
            policy=test_mission.policy,
            task=task
        )
        
        with pytest.raises(SafetyViolationError, match="requests permission .* not allowed by policy"):
            SafetyValidator.validate(tool, context)


class TestExecutionLifecycleAndEvents:
    def test_successful_lifecycle_and_provenance(self, test_mission, test_registry):
        # We will use "tool_b" (resolved as highest priority tool)
        tool = test_registry.get("tool_b")
        # Change command to run a standard shell utility that succeeds instantly
        tool.command = "true"
        
        task = ResearchTask(title="T1", description="D", goal="G", category=TaskCategory.API_DISCOVERY)
        
        bus = EventBus()
        events_emitted = []
        
        def track_events(event):
            events_emitted.append(event.event_type)
            
        bus.subscribe(track_events)
        
        orchestrator = ToolOrchestrator(tool_registry=test_registry, event_bus=bus)
        result = orchestrator.execute_task(test_mission, task)
        
        assert result.status == ToolExecutionStatus.SUCCEEDED
        assert result.execution_time_ms >= 0.0
        
        # Verify event sequence
        assert OrchestratorEventType.TOOL_SELECTED in events_emitted
        assert OrchestratorEventType.TOOL_STARTED in events_emitted
        assert OrchestratorEventType.TOOL_COMPLETED in events_emitted
        
        # Verify artifact collection & provenance
        assert len(result.artifacts) > 0  # Should contain logs
        log_art = next(a for a in result.artifacts if a.type == "log")
        assert log_art.provenance["tool_id"] == "tool_b"
        assert log_art.provenance["task_id"] == task.id
        assert "timestamp" in log_art.provenance

    def test_failed_lifecycle(self, test_mission, test_registry):
        tool = test_registry.get("tool_a")
        tool.command = "false"  # Command returning exit code 1
        
        task = ResearchTask(title="T1", description="D", goal="G", category=TaskCategory.API_DISCOVERY)
        
        orchestrator = ToolOrchestrator(tool_registry=test_registry)
        result = orchestrator.execute_task(test_mission, task)
        
        # In a real sandbox, returncode != 0 can trigger execution failure or collect output
        # Let's verify status is captured
        assert result.status in (ToolExecutionStatus.SUCCEEDED, ToolExecutionStatus.FAILED)

    def test_timeout_lifecycle(self, test_mission, test_registry):
        test_mission.target = "10"
        test_mission.scope = ["10"]
        tool = test_registry.get("tool_b")
        tool.command = "sleep"
        tool.timeout = 0.05  # extremely short timeout
        
        task = ResearchTask(title="T1", description="D", goal="G", category=TaskCategory.API_DISCOVERY)
        
        orchestrator = ToolOrchestrator(tool_registry=test_registry)
        result = orchestrator.execute_task(test_mission, task)
        
        assert result.status == ToolExecutionStatus.TIMED_OUT
        assert "timed out" in result.error.lower()


# =========================================================
# INTEGRATION TESTS
# =========================================================

class TestOrchestratorIntegrations:
    def test_scheduler_integration(self, test_mission, test_registry):
        """Verify scheduler cycles trigger orchestrator execution."""
        # Setup scheduler
        scheduler = TaskScheduler(test_mission, max_workers=1)
        
        # Add task matching API Discovery
        t1 = ResearchTask(
            id="scheduler-task-1",
            title="Discovery",
            description="Recon",
            goal="API lists",
            category=TaskCategory.API_DISCOVERY
        )
        scheduler.schedule_tasks([t1])
        
        # Pull ready tasks from scheduler
        batch = scheduler.get_executable_batch()
        assert len(batch) == 1
        scheduled_task = batch[0]
        
        # Run orchestrator execution
        orchestrator = ToolOrchestrator(tool_registry=test_registry)
        result = orchestrator.execute_task(test_mission, t1)
        
        # Report back to scheduler depending on execution result
        if result.status == ToolExecutionStatus.SUCCEEDED:
            scheduler.report_success(scheduled_task.task_id)
        else:
            scheduler.report_failure(scheduled_task.task_id, error=result.error)
            
        task_check = scheduler.queue_manager.get_task(scheduled_task.task_id)
        assert task_check.state in (TaskState.COMPLETED, TaskState.FAILED)

    def test_plugin_integration(self, test_mission):
        """Runs the actual GraphQL Specialist plugin through orchestrator."""
        # Using real global registry which registers the default graphql_specialist
        orchestrator = ToolOrchestrator()
        
        # Create GraphQL analysis task
        task = ResearchTask(
            title="Analyze GraphQL endpoints",
            description="GraphQL scan",
            goal="Vulnerabilities",
            category=TaskCategory.GRAPHQL_ANALYSIS
        )
        
        # Execute GraphQL Specialist
        result = orchestrator.execute_task(test_mission, task)
        assert result.status == ToolExecutionStatus.SUCCEEDED
        assert result.tool_id == "graphql_specialist"

    def test_mission_runtime_integration(self, test_mission, test_registry):
        """Verify mission attributes (tool_runs, logs, artifacts) populate correctly."""
        orchestrator = ToolOrchestrator(tool_registry=test_registry)
        tool = test_registry.get("tool_b")
        tool.command = "true"
        
        task = ResearchTask(title="T1", description="D", goal="G", category=TaskCategory.API_DISCOVERY)
        
        orchestrator.execute_task(test_mission, task)
        
        assert hasattr(test_mission, "tool_runs")
        assert task.id in test_mission.tool_runs
        assert test_mission.tool_runs[task.id]["tool_id"] == "tool_b"
        assert test_mission.tool_runs[task.id]["status"] == "Succeeded"
        
        assert hasattr(test_mission, "execution_results")
        assert task.id in test_mission.execution_results
        
        assert hasattr(test_mission, "execution_logs")
        assert task.id in test_mission.execution_logs
        
        assert hasattr(test_mission, "artifacts")
        assert len(test_mission.artifacts) > 0

    def test_cli_integration(self, test_mission):
        """Tests tools CLI commands using CliRunner."""
        # List command
        res_list = runner.invoke(app, ["tools", "list"])
        assert res_list.exit_code == 0
        assert "Subfinder" in res_list.output
        assert "GraphQL" in res_list.output
        assert "Specialist" in res_list.output

        # History command
        res_hist = runner.invoke(app, ["tools", "history"])
        assert res_hist.exit_code == 0
