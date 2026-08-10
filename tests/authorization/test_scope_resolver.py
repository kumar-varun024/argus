import pytest
from argus.authorization.scope import ScopeResolver, ScopeState
from argus.runtime.manager import mission_manager
from argus.runtime.mission import Mission

@pytest.fixture
def test_mission():
    mission = Mission(name="Test Mission Scope", target="example.com")
    mission.scope = ["example.com", "*.example.com", "192.168.1.0/24"]
    mission_manager._active_missions[mission.id] = mission
    return mission

def test_scope_resolver_exact(test_mission):
    resolver = ScopeResolver()
    decision = resolver.check_scope("example.com", test_mission.id)
    assert decision.decision == ScopeState.IN_SCOPE

def test_scope_resolver_wildcard(test_mission):
    resolver = ScopeResolver()
    decision = resolver.check_scope("api.example.com", test_mission.id)
    assert decision.decision == ScopeState.IN_SCOPE

def test_scope_resolver_out_of_scope(test_mission):
    resolver = ScopeResolver()
    decision = resolver.check_scope("external-domain.com", test_mission.id)
    assert decision.decision == ScopeState.OUT_OF_SCOPE

def test_scope_resolver_ip_range(test_mission):
    resolver = ScopeResolver()
    decision = resolver.check_scope("192.168.1.50", test_mission.id)
    assert decision.decision == ScopeState.IN_SCOPE

def test_scope_resolver_ip_out_of_range(test_mission):
    resolver = ScopeResolver()
    decision = resolver.check_scope("192.168.2.1", test_mission.id)
    assert decision.decision == ScopeState.OUT_OF_SCOPE
    
def test_scope_resolver_url(test_mission):
    resolver = ScopeResolver()
    decision = resolver.check_scope("https://api.example.com/v1/users", test_mission.id)
    assert decision.decision == ScopeState.IN_SCOPE
