import pytest
import os
import json
from argus.plugins.graphql.schema import GraphQLSchemaAnalyzer
from argus.plugins.graphql.models import GraphQLSchema
from argus.runtime.mission import Mission, GraphQLState
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph
from argus.plugins.graphql.agent import GraphQLSpecialist
from argus.plugins.graphql.models import GraphQLEndpoint

from unittest.mock import patch

@pytest.fixture(autouse=True)
def mock_http_client():
    from argus.http.client import HttpResponse
    from argus.authorization.scope import ScopeDecision, ScopeState
    from argus.authorization.gate import AuthDecision
    
    def side_effect(mission, url, *args, **kwargs):
        if "introspection-enabled" in url:
            mock_resp_body = json.dumps({
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "types": [
                            {
                                "kind": "OBJECT",
                                "name": "User"
                            }
                        ]
                    }
                }
            })
            return HttpResponse(
                success=True,
                status_code=200,
                headers={"content-type": "application/json"},
                body=mock_resp_body,
                url=url,
                method="POST",
                scope_decision=ScopeDecision("example.com", ScopeState.IN_SCOPE),
                authorization_decision=AuthDecision(True, "Allowed")
            )
        else:
            return HttpResponse(
                success=False,
                status_code=400,
                error="Introspection disabled",
                url=url,
                method="POST",
                scope_decision=ScopeDecision("example.com", ScopeState.IN_SCOPE),
                authorization_decision=AuthDecision(True, "Allowed")
            )
            
    with patch("argus.plugins.graphql.schema.AuthorizedHttpClient.post", side_effect=side_effect) as p:
        yield p


@pytest.fixture
def clean_cache():
    cache_dir = ".argus/cache/graphql"
    if os.path.exists(cache_dir):
        for f in os.listdir(cache_dir):
            os.remove(os.path.join(cache_dir, f))
    yield
    if os.path.exists(cache_dir):
        for f in os.listdir(cache_dir):
            os.remove(os.path.join(cache_dir, f))

def test_introspection_parsing(clean_cache):
    mission = Mission("test")
    mission.graphql = GraphQLState()
    mission.graphql.endpoints.append(GraphQLEndpoint(url="http://example.com/graphql?introspection-enabled"))
    
    analyzer = GraphQLSchemaAnalyzer()
    schema = analyzer.analyze(mission)
    
    assert schema is not None
    assert schema.source == "Introspection"
    assert "User" in schema.types
    assert len(mission.graphql.schemas) == 1

def test_schema_inference(clean_cache):
    mission = Mission("test")
    mission.graphql = GraphQLState()
    mission.graphql.endpoints.append(GraphQLEndpoint(url="http://example.com/graphql"))
    
    mission.evidence.add(Evidence(category="HTTP Request", value="query MyQuery { user { id } }", source="/graphql"))
    mission.evidence.add(Evidence(category="HTTP Request", value="mutation MyMutation { updateUser(id: 1) { id } }", source="/graphql"))
    mission.evidence.add(Evidence(category="HTTP Request", value="subscription MySub { userUpdated { id } }", source="/graphql"))
    
    analyzer = GraphQLSchemaAnalyzer()
    schema = analyzer.analyze(mission)
    
    assert schema is not None
    assert schema.source == "Inference"
    assert "InferredQuery" in schema.queries
    assert "InferredMutation" in schema.mutations
    assert "InferredSubscription" in schema.subscriptions
    
def test_object_parsing(clean_cache):
    mission = Mission("test")
    mission.graphql = GraphQLState()
    mission.graphql.endpoints.append(GraphQLEndpoint(url="http://example.com/graphql"))
    
    mission.evidence.add(Evidence(category="HTTP Response", value='{"data": {"__typename": "User", "id": 1}}', source="/graphql"))
    
    analyzer = GraphQLSchemaAnalyzer()
    schema = analyzer.analyze(mission)
    
    assert "User" in schema.types
    assert schema.types["User"].kind == "OBJECT"
    
def test_enum_interface_union_scalar_parsing(clean_cache):
    mission = Mission("test")
    mission.graphql = GraphQLState()
    mission.graphql.endpoints.append(GraphQLEndpoint(url="http://example.com/graphql"))
    
    mission.evidence.add(Evidence(category="HTTP Response", value='enum Role { ADMIN, USER }', source="/graphql"))
    mission.evidence.add(Evidence(category="HTTP Response", value='interface Node { id: ID! }', source="/graphql"))
    mission.evidence.add(Evidence(category="HTTP Response", value='union SearchResult = User | Post', source="/graphql"))
    mission.evidence.add(Evidence(category="HTTP Response", value='scalar Date', source="/graphql"))
    
    analyzer = GraphQLSchemaAnalyzer()
    schema = analyzer.analyze(mission)
    
    assert "InferredEnum" in schema.enums
    assert "InferredInterface" in schema.interfaces
    assert "InferredUnion" in schema.unions
    assert "CustomScalar" in schema.types
    
def test_cache_behavior(clean_cache):
    mission = Mission("test")
    mission.graphql = GraphQLState()
    mission.graphql.endpoints.append(GraphQLEndpoint(url="http://example.com/graphql?introspection-enabled"))
    
    analyzer = GraphQLSchemaAnalyzer()
    
    # First run: should download and cache
    schema1 = analyzer.analyze(mission)
    assert schema1.source == "Introspection"
    
    # Second run: should hit cache
    mission2 = Mission("test2")
    mission2.graphql = GraphQLState()
    mission2.graphql.endpoints.append(GraphQLEndpoint(url="http://example.com/graphql?introspection-enabled"))
    
    schema2 = analyzer.analyze(mission2)
    assert schema2.source == "Cache"

def test_knowledge_graph_updates(clean_cache):
    mission = Mission("test")
    mission.graph = KnowledgeGraph()
    mission.endpoints = [{"url": "http://example.com/graphql", "method": "POST"}]
    mission.evidence.add(Evidence(category="HTTP Request", value="query MyQuery { user { id } }", source="/graphql"))
    mission.evidence.add(Evidence(category="HTTP Response", value='{"data": {"__typename": "User"}}', source="/graphql"))
    mission.evidence.add(Evidence(category="HTTP Response", value='enum Role { ADMIN, USER }', source="/graphql"))
    mission.evidence.add(Evidence(category="HTTP Response", value='interface Node { id: ID! }', source="/graphql"))
    mission.evidence.add(Evidence(category="HTTP Response", value='union SearchResult = User | Post', source="/graphql"))

    specialist = GraphQLSpecialist()
    specialist.discover(mission) # Will run discovery + schema analyzer
    
    assert mission.graph.node_count() > 0
    
    nodes = mission.graph.all()
    types = [n.type for n in nodes]
    
    assert "Schema" in types
    assert "Object" in types
    assert "Operation" in types
    assert "Enum" in types
    assert "Interface" in types
    assert "Union" in types

def test_mission_storage(clean_cache):
    mission = Mission("test")
    mission.graph = KnowledgeGraph()
    mission.endpoints = [{"url": "http://example.com/graphql?introspection-enabled", "method": "POST"}]
    
    specialist = GraphQLSpecialist()
    specialist.discover(mission)
    
    assert len(mission.graphql.schemas) == 1
    assert "User" in mission.graphql.types
