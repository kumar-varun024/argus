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


def test_scope_resolver_wildcard_lookalike_blocked():
    """Verify lookalike domains like evilexample.com do NOT match *.example.com."""
    mission = Mission(name="Lookalike Test", target="example.com")
    mission.scope = ["*.example.com", "example.com"]
    mission_manager._active_missions[mission.id] = mission

    resolver = ScopeResolver()
    assert resolver.check_scope("evilexample.com", mission.id).decision == ScopeState.OUT_OF_SCOPE
    assert resolver.check_scope("badexample.com", mission.id).decision == ScopeState.OUT_OF_SCOPE
    assert resolver.check_scope("notexample.com", mission.id).decision == ScopeState.OUT_OF_SCOPE
    assert resolver.check_scope("http://evilexample.com:8080/path", mission.id).decision == ScopeState.OUT_OF_SCOPE

    # Legitimate subdomains must pass
    assert resolver.check_scope("api.example.com", mission.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("sub.api.example.com", mission.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("example.com", mission.id).decision == ScopeState.IN_SCOPE


def test_scope_resolver_ports_in_target(test_mission):
    """Verify targets with explicit ports normalize and match scope correctly."""
    resolver = ScopeResolver()
    assert resolver.check_scope("example.com:8080", test_mission.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("api.example.com:8443", test_mission.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("192.168.1.50:9000", test_mission.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("192.168.2.50:9000", test_mission.id).decision == ScopeState.OUT_OF_SCOPE


def test_scope_resolver_ipv6():
    """Verify IPv6 address scope resolution."""
    mission = Mission(name="IPv6 Mission", target="2001:db8::1")
    mission.scope = ["2001:db8::1", "fe80::/64"]
    mission_manager._active_missions[mission.id] = mission

    resolver = ScopeResolver()
    assert resolver.check_scope("2001:db8::1", mission.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("http://[2001:db8::1]:8080/v1", mission.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("2001:db8::2", mission.id).decision == ScopeState.OUT_OF_SCOPE


def test_scope_resolver_explain_decision(test_mission):
    """Verify human-readable explanation generation."""
    resolver = ScopeResolver()
    in_scope_dec = resolver.check_scope("api.example.com", test_mission.id)
    assert in_scope_dec.decision == ScopeState.IN_SCOPE
    assert "matches the mission's" in resolver.explain_scope_decision(in_scope_dec)

    out_scope_dec = resolver.check_scope("evil.com", test_mission.id)
    assert out_scope_dec.decision == ScopeState.OUT_OF_SCOPE
    assert "does not match" in resolver.explain_scope_decision(out_scope_dec)

    unknown_dec = resolver.check_scope("example.com", "non-existent-mission-id")
    assert unknown_dec.decision == ScopeState.UNKNOWN
    assert "can't determine" in resolver.explain_scope_decision(unknown_dec)


def test_mission_scope_defaulting_domain():
    """Mission with domain target defaults scope to domain and wildcard."""
    m = Mission(target="mycompany.org")
    assert m.scope == ["mycompany.org", "*.mycompany.org"]


def test_mission_scope_defaulting_wildcard():
    """Mission with wildcard target defaults scope to wildcard and base domain."""
    m = Mission(target="*.mycompany.org")
    assert m.scope == ["*.mycompany.org", "mycompany.org"]


def test_mission_scope_defaulting_ipv4():
    """Mission with IPv4 target defaults scope to IPv4."""
    m = Mission(target="192.168.1.100")
    assert m.scope == ["192.168.1.100"]


def test_mission_scope_defaulting_cidr():
    """Mission with CIDR target defaults scope to CIDR."""
    m = Mission(target="10.0.0.0/24")
    assert m.scope == ["10.0.0.0/24"]


def test_mission_scope_defaulting_url_with_port_and_path():
    """Mission with URL target extracts domain and defaults scope appropriately."""
    m = Mission(target="http://api.staging.corp.com:8080/v1/health")
    assert m.scope == ["api.staging.corp.com", "*.api.staging.corp.com"]


def test_mission_scope_defaulting_url_with_ip():
    """Mission with URL containing IP extracts IP."""
    m = Mission(target="http://192.168.1.1:8080/v1/api")
    assert m.scope == ["192.168.1.1"]


def test_mission_scope_custom_override():
    """Mission with explicit scope preserves custom scope without overriding."""
    m = Mission(target="example.com", scope=["custom.domain.com"])
    assert m.scope == ["custom.domain.com"]


def test_mission_scope_empty_target():
    """Mission with empty target produces empty scope."""
    m = Mission(target="")
    assert m.scope == []
