import pytest
from argus.plugins.graphql.reasoning import GraphQLReasoningEngine
from argus.plugins.graphql.models import GraphQLWorkflow, GraphQLInvestigation, GraphQLCRUD, GraphQLRelationship
from argus.runtime.mission import Mission, GraphQLState

@pytest.fixture
def base_mission():
    mission = Mission("test")
    mission.graphql = GraphQLState()
    return mission

def test_workflow_investigation_generation(base_mission):
    wf = GraphQLWorkflow(name="Invitation")
    wf.business_objects = ["Invitation", "User"]
    base_mission.graphql.workflows.append(wf)
    
    engine = GraphQLReasoningEngine()
    engine.analyze(base_mission)
    
    assert len(base_mission.graphql.investigations) == 1
    inv = base_mission.graphql.investigations[0]
    assert inv.title == "Review Invitation Workflow"
    assert inv.category == "Workflow Review"
    assert "Review whether authorized users" in inv.manual_validation_guidance
    assert "vulnerability" not in inv.reasoning.lower()
    assert inv.priority == "High"

def test_crud_authorization_investigation(base_mission):
    # Setup a CRUD operation that modifies an object with ownership
    crud = GraphQLCRUD(operation_name="updateOrganization", action="UPDATE", object_type="Organization")
    base_mission.graphql.crud.append(crud)
    
    rel = GraphQLRelationship(parent="Organization", child="User", type="OWNS")
    base_mission.graphql.relationships.append(rel)
    
    engine = GraphQLReasoningEngine()
    engine.analyze(base_mission)
    
    assert len(base_mission.graphql.investigations) == 1
    inv = base_mission.graphql.investigations[0]
    assert inv.title == "Review Organization Authorization"
    assert inv.category == "Object-Level Authorization Review"
    assert "Organization" in inv.business_objects
    assert "updateOrganization" in inv.related_operations
    assert inv.priority == "High"

def test_duplicate_detection(base_mission):
    # Generate the same investigation twice to see if it merges
    wf1 = GraphQLWorkflow(name="Checkout")
    wf1.evidence = ["Evidence 1"]
    
    wf2 = GraphQLWorkflow(name="Checkout")
    wf2.evidence = ["Evidence 2"]
    
    base_mission.graphql.workflows.extend([wf1, wf2])
    
    engine = GraphQLReasoningEngine()
    engine.analyze(base_mission)
    
    # Should only be one investigation due to deduplication
    assert len(base_mission.graphql.investigations) == 1
    inv = base_mission.graphql.investigations[0]
    
    # Evidence should be merged
    assert "Evidence 1" in inv.evidence
    assert "Evidence 2" in inv.evidence
    # Confidence should be boosted
    assert inv.confidence > 0.85

def test_priority_queue(base_mission):
    # Add manual investigations with different priorities
    inv1 = GraphQLInvestigation(title="Low Prio", description="", category="", reasoning="", priority="Low")
    inv2 = GraphQLInvestigation(title="High Prio", description="", category="", reasoning="", priority="High")
    inv3 = GraphQLInvestigation(title="Medium Prio", description="", category="", reasoning="", priority="Medium")
    
    base_mission.graphql.investigations.extend([inv1, inv2, inv3])
    
    engine = GraphQLReasoningEngine()
    engine._prioritize(base_mission)
    
    pq = base_mission.graphql.priority_queue
    assert len(pq) == 3
    assert pq[0].priority == "High"
    assert pq[1].priority == "Medium"
    assert pq[2].priority == "Low"
