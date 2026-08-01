import pytest
from argus.runtime.mission import Mission
from argus.plugins.interfaces import ControlledMission
from argus.plugins.api.plugin import APIIntelligencePlugin
from argus.plugins.api.resource_model import APICollection, APISingleton
from argus.plugins.api.schemas import SchemaParser
from argus.plugins.api.relationships import RelationshipInferencer
from argus.plugins.api.operations import OperationAnalyzer

def test_schema_parser():
    endpoints = [
        {"path": "/users", "method": "GET"},
        {"path": "/users/{id}", "method": "GET"}
    ]
    parser = SchemaParser()
    resources = parser.parse_endpoints(endpoints)
    assert "/users" in resources
    assert resources["/users"].is_collection is True

def test_relationship_inferencer():
    resources = [
        APICollection(name="orgs", path="/orgs"),
        APICollection(name="projects", path="/orgs/{org_id}/projects")
    ]
    inferencer = RelationshipInferencer()
    rels = inferencer.infer(resources)
    assert len(rels) == 1
    assert rels[0].parent == "orgs"
    assert rels[0].child == "projects"
    assert rels[0].relationship_type == "owns"

def test_api_intelligence_plugin():
    mission = Mission("test")
    mission.endpoints = [
        {"path": "/api/v1/users", "method": "GET"},
        {"path": "/api/v1/users", "method": "POST"},
        {"path": "/api/v1/users/bulk_update", "method": "POST"},
        {"path": "/api/v1/admin/settings", "method": "GET"}
    ]
    
    plugin = APIIntelligencePlugin()
    controlled = ControlledMission(mission)
    plugin.execute(controlled)
    
    assert len(mission.api_inventory) > 0
    titles = [inv.title.lower() for inv in mission.api_inventory]
    
    # Should flag administrative and bulk operations and incomplete CRUD
    assert any("admin" in t for t in titles)
    assert any("bulk" in t for t in titles)
    assert any("incomplete crud" in t or "hidden delete" in t for t in titles)
