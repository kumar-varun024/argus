import pytest
from argus.runtime.mission import Mission
from argus.agents.authorization.agent import AuthorizationSpecialist
from argus.agents.authorization.models import AuthzContext
from argus.agents.authorization.confidence import AuthzConfidenceScorer
from argus.agents.authorization.roles import RoleAnalyzer
from argus.agents.authorization.permissions import PermissionAnalyzer
from argus.agents.authorization.ownership import OwnershipAnalyzer
from argus.agents.authorization.heuristics import AUTHZ_HEURISTIC_REGISTRY, BaseAuthzHeuristic, AuthzHeuristicResult
from argus.intelligence.models import Investigation
from argus.authorization.graph import AuthorizationGraph
from argus.authorization.models import AuthNodeType, AuthNode, AuthEdge

def test_authz_specialist_initialization():
    specialist = AuthorizationSpecialist()
    assert len(specialist.heuristics) == 7

def test_authz_confidence_scorer():
    scorer = AuthzConfidenceScorer()
    
    class MockInv:
        def __init__(self):
            self.supporting_evidence = []
            self.workflow = "test_wf"
            
    class MockResult:
        def __init__(self):
            self.investigation = MockInv()
            self.heuristic_id = "cross_tenant_object"
            
    res = MockResult()
    context = AuthzContext(mission_id="test", target="test", workflows=[{"name": "test_wf"}])
    
    score = scorer.score(res, context)
    # base 50.0 * 1.15 (workflow) * 1.1 (heuristic reliability) = 63.25
    assert abs(score - 63.25) < 0.01
    
    res.investigation.supporting_evidence = ["a"]
    score = scorer.score(res, context)
    # 63.25 * 1.1 (evidence) = 69.575
    assert abs(score - 69.575) < 0.01

def test_role_analyzer():
    analyzer = RoleAnalyzer()
    context = AuthzContext(mission_id="t", target="t", roles=["User", "Admin", "SuperAdmin", "Guest"],
                           hierarchy={"Admin": ["Admin_Support", "Admin_Billing"], "Admin_Support": ["Admin_L1"]})
    
    admin_roles = analyzer.get_admin_roles(context)
    assert len(admin_roles) == 2
    assert "Admin" in admin_roles
    assert "SuperAdmin" in admin_roles
    
    # Hierarchy analysis
    overlaps = analyzer.get_overlapping_roles(context)
    # Admin -> Admin_Support, Admin -> Admin_Billing, Admin -> Admin_L1, Admin_Support -> Admin_L1
    assert len(overlaps) == 4

def test_permission_analyzer():
    analyzer = PermissionAnalyzer()
    
    ep1 = {"method": "GET", "path": "/users", "security": ["jwt"]}
    ep2 = {"method": "POST", "path": "/users", "security": []}
    ep3 = {"method": "DELETE", "path": "/users/1"}
    
    context = AuthzContext(mission_id="t", target="t", endpoints=[ep1, ep2, ep3])
    findings = analyzer.get_unprotected_mutations(context)
    
    assert len(findings) == 2
    assert findings[0] == ep2
    assert findings[1] == ep3

def test_ownership_analyzer():
    analyzer = OwnershipAnalyzer()
    
    # Mocking graph behavior for ownership analyzer
    graph = AuthorizationGraph()
    n1 = AuthNode(name="User", node_type=AuthNodeType.IDENTITY)
    n2 = AuthNode(name="Document", node_type=AuthNodeType.PROTECTED_RESOURCE)
    graph.add_node(n1)
    graph.add_node(n2)
    graph.add_edge(AuthEdge(source="User", target="Document", relation="owns"))
    
    context = AuthzContext(mission_id="t", target="t", graph=graph)
    cross_tenant = analyzer.get_cross_tenant_objects(context)
    # Should flag "Document" because "User" is not a tenant/org
    assert len(cross_tenant) > 0
    assert "Document" in cross_tenant

def test_authorization_specialist_generation_and_dedup():
    mission = Mission(target="test.local")
    # Setup mission with endpoints to trigger heuristics
    mission.endpoints = [
        {"method": "DELETE", "path": "/api/users/1"},
        {"method": "PUT", "path": "/api/users/1"},
        {"method": "GET", "path": "/admin/dashboard"}
    ]
    mission.workflows = [{"name": "Admin_Settings"}]
    
    specialist = AuthorizationSpecialist()
    
    # We will add a dummy duplicate heuristic to test duplicate suppression
    class DuplicateHeuristic(BaseAuthzHeuristic):
        @property
        def id(self) -> str: return "dup"
        def run(self, context):
            inv = Investigation(
                title="Authorization review for delete endpoint /api/users/1",
                category="Object-Level Authorization Review",
                affected_objects=["/api/users/1"],
                workflow="Object Mutation",
                reasoning="dup",
                manual_validation_steps=[],
                supporting_evidence=[]
            )
            return [AuthzHeuristicResult(investigation=inv, matched_nodes=["/api/users/1"], heuristic_id=self.id)]
            
    specialist.heuristics.append(DuplicateHeuristic())
    
    specialist.analyze(mission)
    
    investigations = mission.authorization_investigations
    # Admin endpoint (1), Delete endpoint (1), Update endpoint (1), OwnerAdmin workflow (1)
    # Total unique should be 4
    assert len(investigations) == 4
    assert mission.authorization_metrics["total_investigations_generated"] == 4
    
    # Cleanup
    specialist.heuristics.pop()

def test_plugin_heuristics():
    # Simulate a plugin adding a heuristic
    class PluginHeuristic(BaseAuthzHeuristic):
        @property
        def id(self) -> str: return "plugin_h"
        def run(self, context):
            inv = Investigation(title="Plugin", category="Plugin", affected_objects=["P"], reasoning="p", manual_validation_steps=[], supporting_evidence=[], workflow="p")
            return [AuthzHeuristicResult(investigation=inv, matched_nodes=[], heuristic_id=self.id)]
            
    AUTHZ_HEURISTIC_REGISTRY.append(PluginHeuristic())
    
    specialist = AuthorizationSpecialist()
    mission = Mission(target="test.local")
    specialist.analyze(mission)
    
    titles = [inv.title for inv in mission.authorization_investigations]
    assert "Plugin" in titles
    
    # Cleanup
    AUTHZ_HEURISTIC_REGISTRY.pop()
