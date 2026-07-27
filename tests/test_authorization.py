import pytest
from argus.core.mission import Mission
from argus.workflows.models import Workflow, WorkflowStep
from argus.authorization.builder import AuthorizationGraphBuilder
from argus.authorization.analyzer import AuthorizationAnalyzer
from argus.authorization.models import AuthNodeType, AuthEdgeType

def test_auth_graph_construction():
    mission = Mission(target="test")
    wf = Workflow(name="Organization Management", description="Manage orgs")
    wf.steps.append(WorkflowStep(title="Create Org", endpoint="/orgs", http_method="POST", required_role="Admin", business_object="Organization"))
    mission.workflows = [wf]
    
    builder = AuthorizationGraphBuilder(mission)
    graph = builder.build()
    
    assert graph is not None
    assert len(graph.nodes) >= 2
    
    admin_node = graph.get_node_by_name_and_type("Admin", AuthNodeType.ROLE)
    org_node = graph.get_node_by_name_and_type("Organization", AuthNodeType.ORGANIZATION)
    
    assert admin_node is not None
    assert org_node is not None
    
    edges = graph.get_outgoing_edges(admin_node.id, AuthEdgeType.CAN_CREATE)
    assert len(edges) == 1
    assert edges[0].target_id == org_node.id

def test_role_hierarchy_inference():
    mission = Mission(target="test")
    builder = AuthorizationGraphBuilder(mission)
    graph = builder.build()
    
    analyzer = AuthorizationAnalyzer(graph)
    hierarchy = analyzer.get_role_hierarchy()
    
    assert "Admin" in hierarchy.get("Owner", [])
    assert "Member" in hierarchy.get("Admin", [])
    assert "Manager" in hierarchy.get("Admin", [])

def test_ownership_chains():
    mission = Mission(target="test")
    wf1 = Workflow(name="Organization Management")
    wf1.steps.append(WorkflowStep(title="Create Org", endpoint="/orgs", http_method="POST", business_object="Organization"))
    
    wf2 = Workflow(name="Project Creation")
    wf2.steps.append(WorkflowStep(title="Create Project", endpoint="/projects", http_method="POST", business_object="Project"))
    
    wf3 = Workflow(name="Repository Management")
    wf3.steps.append(WorkflowStep(title="Create Repo", endpoint="/repos", http_method="POST", business_object="Repository"))
    
    mission.workflows = [wf1, wf2, wf3]
    
    builder = AuthorizationGraphBuilder(mission)
    graph = builder.build()
    
    analyzer = AuthorizationAnalyzer(graph)
    chains = analyzer.get_ownership_chains()
    
    assert len(chains) > 0
    # Expected chain: Organization -> Project -> Repository
    found_chain = False
    for chain in chains:
        if chain == ["Organization", "Project", "Repository"]:
            found_chain = True
    assert found_chain

def test_empty_mission():
    mission = Mission(target="test")
    builder = AuthorizationGraphBuilder(mission)
    graph = builder.build()
    
    # Should still generate base roles
    assert len(graph.nodes) > 0
    analyzer = AuthorizationAnalyzer(graph)
    assert "Owner" in analyzer.get_role_hierarchy()

def test_authorization_boundaries():
    mission = Mission(target="test")
    wf = Workflow(name="Settings")
    wf.steps.append(WorkflowStep(title="Update Settings", endpoint="/settings", http_method="PUT", required_role="Admin", business_object="Settings"))
    mission.workflows = [wf]
    
    builder = AuthorizationGraphBuilder(mission)
    graph = builder.build()
    
    analyzer = AuthorizationAnalyzer(graph)
    boundaries = analyzer.get_authorization_boundaries()
    
    assert "Settings" in boundaries
