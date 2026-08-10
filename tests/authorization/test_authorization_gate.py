import pytest
from argus.authorization.gate import AuthorizationGate
from argus.authorization.scope import ScopeState
from argus.runtime.manager import mission_manager
from argus.runtime.mission import Mission

@pytest.fixture
def test_mission():
    mission = Mission(name="Auth Test Mission", target="example.com")
    mission.scope = ["example.com", "*.example.com"]
    mission_manager._active_missions[mission.id] = mission
    return mission

def test_gate_allowed_action(test_mission):
    gate = AuthorizationGate()
    decision = gate.can_execute_action("user1", "SCAN", "api.example.com", test_mission.id)
    assert decision.allowed == True
    assert decision.scope_decision.decision == ScopeState.IN_SCOPE

def test_gate_denied_scope(test_mission):
    gate = AuthorizationGate()
    decision = gate.can_execute_action("user1", "SCAN", "hacker.com", test_mission.id)
    assert decision.allowed == False
    assert decision.scope_decision.decision == ScopeState.OUT_OF_SCOPE
