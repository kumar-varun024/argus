import pytest
from argus.runtime.mission import Mission
from argus.methodology.models import Playbook, PlaybookStep
from argus.methodology.registry import PlaybookRegistry
from argus.methodology.executor import PlaybookExecutor
from argus.methodology.engine import MethodologyEngine
from argus.methodology.step import StepEvaluator
from argus.workflows.models import Workflow

def test_playbook_registry():
    registry = PlaybookRegistry()
    assert len(registry.get_all()) > 0
    assert registry.get("pb_authz_review") is not None
    
    custom = Playbook(id="custom", name="Custom", category="Custom", description="Custom")
    registry.register(custom)
    assert registry.get("custom") == custom
    
    with pytest.raises(ValueError):
        registry.register(custom)

def test_step_evaluator():
    evaluator = StepEvaluator()
    mission = Mission("test.local")
    
    step = PlaybookStep(
        id="test_step",
        title="Test",
        description="Test",
        required_workflows=["Admin Functions"]
    )
    
    # Mission has no workflows, should fail
    assert not evaluator.evaluate_prerequisites(step, mission)
    
    # Add workflow
    mission.workflows.append(Workflow(id="wf1", name="Admin Functions", description=""))
    assert evaluator.evaluate_prerequisites(step, mission)

def test_playbook_executor():
    executor = PlaybookExecutor()
    mission = Mission("test.local")
    
    pb = Playbook(
        id="test_pb",
        name="Test",
        category="Test",
        description="Test",
        steps=[
            PlaybookStep(id="s1", title="S1", description="")
        ]
    )
    
    result = executor.execute(pb, mission)
    assert result.status == "completed"
    assert "s1" in result.completed_steps

def test_methodology_engine():
    registry = PlaybookRegistry()
    registry._playbooks = {} # clear defaults for test
    
    pb = Playbook(
        id="test_pb",
        name="Test",
        category="Test",
        description="Test",
        steps=[
            PlaybookStep(id="s1", title="S1", description="")
        ]
    )
    registry.register(pb)
    
    engine = MethodologyEngine(registry)
    mission = Mission("test.local")
    
    engine.run(mission, "test_pb")
    
    assert "test_pb" in mission.playbooks
    assert "test_pb" in mission.completed_playbooks
    assert "test_pb" not in mission.active_playbooks
    assert mission.playbook_results["test_pb"].status == "completed"
