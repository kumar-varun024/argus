import pytest
from argus.plugins.graphql.discovery import GraphQLDiscovery
from argus.runtime.mission import Mission
from argus.evidence.model import Evidence
from argus.plugins.graphql.agent import GraphQLSpecialist
from argus.graph.graph import KnowledgeGraph

def test_standard_graphql_endpoint():
    mission = Mission("test")
    mission.endpoints = [{"url": "http://example.com/graphql", "method": "POST"}]
    
    discovery = GraphQLDiscovery()
    endpoints = discovery.discover(mission)
    
    assert len(endpoints) == 1
    assert endpoints[0].url == "http://example.com/graphql"
    assert endpoints[0].confidence == 0.7
    assert endpoints[0].supports_post is True

def test_custom_endpoint_with_payload():
    mission = Mission("test")
    mission.evidence.add(Evidence(
        category="HTTP Request", 
        value='{"query": "query { user { id } }"}', 
        source="http://example.com/custom-api"
    ))
    
    discovery = GraphQLDiscovery()
    endpoints = discovery.discover(mission)
    
    assert len(endpoints) == 1
    assert endpoints[0].url == "http://example.com/custom-api"
    assert endpoints[0].confidence == 0.9
    assert endpoints[0].source == "HTTP Request"

def test_graphql_get():
    mission = Mission("test")
    mission.endpoints = [{"url": "http://example.com/graphql?query={me{name}}", "method": "GET"}]
    
    discovery = GraphQLDiscovery()
    endpoints = discovery.discover(mission)
    
    assert len(endpoints) == 1
    assert endpoints[0].supports_get is True

def test_apollo_detection():
    mission = Mission("test")
    mission.evidence.add(Evidence(
        category="JavaScript", 
        value='const client = new ApolloClient();', 
        source="/main.js"
    ))
    
    discovery = GraphQLDiscovery()
    endpoints = discovery.discover(mission)
    
    assert len(endpoints) == 1
    assert endpoints[0].framework_hint == "Apollo"
    assert endpoints[0].confidence == 0.85

def test_persisted_queries():
    mission = Mission("test")
    mission.evidence.add(Evidence(
        category="HTTP Request", 
        value='{"extensions": {"persistedQuery": {"sha256Hash": "..."}}}', 
        source="http://example.com/graphql"
    ))
    
    discovery = GraphQLDiscovery()
    endpoints = discovery.discover(mission)
    
    assert len(endpoints) == 1
    assert endpoints[0].confidence == 0.95

def test_duplicate_detection():
    mission = Mission("test")
    mission.endpoints = [{"url": "http://example.com/graphql", "method": "POST"}]
    mission.evidence.add(Evidence(
        category="HTTP Request", 
        value='{"query": "..."}', 
        source="http://example.com/graphql"
    ))
    
    discovery = GraphQLDiscovery()
    endpoints = discovery.discover(mission)
    
    assert len(endpoints) == 1
    assert len(endpoints[0].evidence) == 2
    assert endpoints[0].confidence == 1.0

def test_confidence_calculation():
    mission = Mission("test")
    mission.endpoints = [{"url": "http://example.com/graphql", "method": "POST"}]
    mission.evidence.add(Evidence(category="HTTP Response", value='{"data": {}, "errors": []}', source="http://example.com/graphql"))
    
    discovery = GraphQLDiscovery()
    endpoints = discovery.discover(mission)
    
    assert len(endpoints) == 1
    assert endpoints[0].confidence == 1.0

def test_mission_storage_and_observation():
    mission = Mission("test")
    mission.graph = KnowledgeGraph()
    mission.endpoints = [{"url": "http://example.com/graphql", "method": "POST"}]
    
    specialist = GraphQLSpecialist()
    specialist.discover(mission)
    
    # Verify mission storage
    assert hasattr(mission, "graphql")
    assert len(mission.graphql.endpoints) == 1
    
    # Verify graph nodes
    assert mission.graph.node_count() == 1
    node = mission.graph.nodes[list(mission.graph.nodes.keys())[0]]
    assert node.type == "Endpoint"
    assert node.value == "http://example.com/graphql"
    
    # Verify observation
    assert hasattr(mission, "findings")
    assert len(mission.findings) == 1
    assert mission.findings[0].description == "GraphQL endpoint discovered at http://example.com/graphql"
