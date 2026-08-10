import pytest
from argus.orchestration.models import ResearchStep, ResearchStepType, ResearchStepState, ToolExecution
from argus.orchestration.orchestrator import ResearchWorkflowOrchestrator
from argus.runtime.manager import mission_manager
from argus.runtime.mission import Mission
from argus.runtime.models import Tool
from argus.runtime.registry import registry

@pytest.fixture
def orchestrator():
    return ResearchWorkflowOrchestrator()

@pytest.fixture
def setup_mission():
    mission = Mission(name="Workflow Test Mission", target="example.com")
    mission.scope = ["example.com"]
    mission_manager._active_missions[mission.id] = mission
    
    # Register a dummy tool
    if not registry.get("dummy_scanner"):
        registry.register(
            Tool(
                id="dummy_scanner",
                name="Dummy Scanner",
                capability="scanner",
                command="dummy",
                description="Dummy",
                supported_tasks=["Testing"],
                required_inputs=[],
                produced_outputs=["data"],
                capabilities=["scanner"],
                safety_requirements={"type": "internal", "permissions": []},
                timeout=10.0,
                priority=100
            )
        )
    return mission

def test_workflow_creation(orchestrator, setup_mission):
    wf = orchestrator.create_workflow("inv_123", setup_mission.id)
    assert wf.investigation_id == "inv_123"
    assert len(wf.events) == 1
    assert wf.events[0].event_type == "WORKFLOW_CREATED"

def test_plan_step(orchestrator, setup_mission):
    wf = orchestrator.create_workflow("inv_123", setup_mission.id)
    step = ResearchStep(title="Test Step", description="Desc", step_type=ResearchStepType.ANALYZE)
    planned = orchestrator.plan_next_step(wf.id, step)
    
    assert planned.state == ResearchStepState.PLANNING
    assert wf.steps[0].id == planned.id
    assert wf.events[-1].event_type == "STEP_PLANNED"

def test_execute_tool_step_out_of_scope(orchestrator, setup_mission):
    wf = orchestrator.create_workflow("inv_123", setup_mission.id)
    step = ResearchStep(
        title="Test Tool", 
        description="Desc", 
        step_type=ResearchStepType.TOOL_EXECUTION,
        tool_execution=ToolExecution(tool_id="dummy_scanner", target="hacker.com")
    )
    orchestrator.plan_next_step(wf.id, step)
    
    result_step = orchestrator.execute_step(wf.id, step.id)
    assert result_step.state == ResearchStepState.BLOCKED
    assert result_step.tool_execution.status == "BLOCKED_BY_POLICY"
    assert wf.events[-1].event_type == "STEP_BLOCKED"

def test_execute_tool_step_in_scope(orchestrator, setup_mission):
    wf = orchestrator.create_workflow("inv_123", setup_mission.id)
    step = ResearchStep(
        title="Test Tool", 
        description="Desc", 
        step_type=ResearchStepType.TOOL_EXECUTION,
        tool_execution=ToolExecution(tool_id="dummy_scanner", target="example.com")
    )
    orchestrator.plan_next_step(wf.id, step)
    
    result_step = orchestrator.execute_step(wf.id, step.id)
    assert result_step.state == ResearchStepState.COMPLETED
    assert result_step.tool_execution.status == "COMPLETED"
    assert wf.events[-1].event_type == "EVIDENCE_CREATED"
    assert len(result_step.produced_evidence_ids) == 1
