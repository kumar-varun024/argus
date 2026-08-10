import pytest
from argus.workspace.context.mission import MissionContextResolver
from argus.workspace.context.models import ContextQuery
from argus.runtime.manager import mission_manager
from argus.runtime.mission import Mission

@pytest.fixture
def active_mission():
    mission = mission_manager.create_mission("example.com")
    mission.name = "Test Mission"
    mission.scope = ["example.com", "api.example.com"]
    return mission

def test_resolve_mission_context_no_mission():
    resolver = MissionContextResolver()
    query = ContextQuery(conversation_id="c1", query="test")
    sources = resolver.resolve(query)
    assert len(sources) == 0

def test_resolve_mission_context_success(active_mission):
    resolver = MissionContextResolver()
    query = ContextQuery(conversation_id="c1", query="test", mission_id=active_mission.id)
    sources = resolver.resolve(query)
    
    # Expecting Mission State and Scope
    assert len(sources) == 2
    assert sources[0].semantic_status == "MISSION_STATE"
    assert "Test Mission" in sources[0].content
    
    assert sources[1].semantic_status == "SCOPE"
    assert "api.example.com" in sources[1].content
    
def test_resolve_mission_context_with_investigation(active_mission):
    from argus.investigation.models import Investigation, InvestigationCategory
    inv = Investigation(title="Auth Check", summary="Testing", description="Desc", category=InvestigationCategory.AUTHORIZATION)
    active_mission.investigations.add(inv)
    
    resolver = MissionContextResolver()
    query = ContextQuery(conversation_id="c1", query="test", mission_id=active_mission.id, investigation_id=str(inv.id))
    sources = resolver.resolve(query)
    
    # Mission State, Scope, and Investigation State
    assert len(sources) == 3
    assert sources[2].semantic_status == "INVESTIGATION_STATE"
    assert "Auth Check" in sources[2].title
    assert "Testing" in sources[2].content
