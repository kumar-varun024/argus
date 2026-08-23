import pytest
from argus.runtime.mission import Mission, MissionState
from argus.runtime.state_machine import MissionStateMachine, TransitionError
from argus.runtime.checkpoint import MissionCheckpointer, CheckpointAction
from argus.runtime.mission_runtime import AutonomousMissionRuntime

# Mocking all the engines
class MockEngine:
    def __getattr__(self, name):
        if name in ("queue_manager",):
            return MockEngine()
        def _mock(*args, **kwargs):
            if name == "is_complete":
                return True
            return None
        return _mock

def test_state_machine_valid_transitions():
    mission = Mission(target="test_target")
    sm = MissionStateMachine(mission)
    
    assert mission.status == MissionState.CREATED
    sm.transition_to(MissionState.PLANNING)
    assert mission.status == MissionState.PLANNING
    sm.transition_to(MissionState.RESEARCHING)
    assert mission.status == MissionState.RESEARCHING

def test_state_machine_invalid_transition():
    mission = Mission(target="test_target")
    sm = MissionStateMachine(mission)
    
    with pytest.raises(TransitionError):
        sm.transition_to(MissionState.COMPLETED)

def test_mission_runtime_checkpoint_pause():
    mission = Mission(target="test_target")
    mission.status = MissionState.RESEARCHING
    sm = MissionStateMachine(mission)
    checkpointer = MissionCheckpointer()
    
    # Mocking checkpoint to pause
    checkpointer.register_hook("post_execution", lambda m, c: CheckpointAction.PAUSE)
    
    runtime = AutonomousMissionRuntime(
        mission=mission,
        state_machine=sm,
        checkpointer=checkpointer,
        mission_planner=MockEngine(),
        research_planner=MockEngine(),
        task_scheduler=MockEngine(),
        tool_orchestrator=MockEngine(),
        correlation_engine=MockEngine(),
        fusion_engine=MockEngine(),
        investigation_builder=MockEngine(),
        priority_engine=MockEngine(),
        hypothesis_engine=MockEngine(),
        learning_engine=MockEngine()
    )
    
    runtime.step()
    
    # It should have paused at post_execution
    assert mission.status == MissionState.WAITING_FOR_APPROVAL

def test_mission_runtime_completion():
    mission = Mission(target="test_target")
    mission.status = MissionState.GENERATING_HYPOTHESES
    sm = MissionStateMachine(mission)
    checkpointer = MissionCheckpointer()
    
    runtime = AutonomousMissionRuntime(
        mission=mission,
        state_machine=sm,
        checkpointer=checkpointer,
        mission_planner=MockEngine(),
        research_planner=MockEngine(),
        task_scheduler=MockEngine(),
        tool_orchestrator=MockEngine(),
        correlation_engine=MockEngine(),
        fusion_engine=MockEngine(),
        investigation_builder=MockEngine(),
        priority_engine=MockEngine(),
        hypothesis_engine=MockEngine(),
        learning_engine=MockEngine()
    )
    
    runtime.step()
    
    assert mission.status == MissionState.COMPLETED
