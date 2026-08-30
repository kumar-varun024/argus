import uuid
import pytest
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority
from argus.correlation.matcher import CorrelationMatcher
from argus.correlation.engine import CorrelationEngine
from argus.correlation.graph import CorrelationGraph
from argus.correlation.registry import ObservationRegistry, CorrelationRegistry, EvidenceBundleRegistry
from argus.correlation.rules import match_shared_graph_nodes, match_graph_neighborhood
from argus.correlation.fusion import EvidenceFusionEngine, fuse_shared_graph_nodes


def create_sample_graph():
    kg = KnowledgeGraph()
    # Target
    kg.add(Node(id="target:example.com", type="target", value="example.com"))
    # Subdomains
    kg.add(Node(id="subdomain:api.example.com", type="subdomain", value="api.example.com"))
    kg.add(Node(id="subdomain:isolated.example.com", type="subdomain", value="isolated.example.com"))
    # Live Hosts
    kg.add(Node(id="live_host:http://api.example.com", type="live_host", value="http://api.example.com", metadata={"url": "http://api.example.com", "host": "api.example.com"}))
    kg.add(Node(id="live_host:http://isolated.example.com", type="live_host", value="http://isolated.example.com", metadata={"url": "http://isolated.example.com", "host": "isolated.example.com"}))
    # Endpoints & Technology
    kg.add(Node(id="endpoint:http://api.example.com/v1/users", type="endpoint", value="http://api.example.com/v1/users"))
    kg.add(Node(id="technology:Nginx", type="technology", value="Nginx"))
    # Edges
    kg.connect("target:example.com", "subdomain:api.example.com", "RESOLVES_TO")
    kg.connect("subdomain:api.example.com", "live_host:http://api.example.com", "HOSTS")
    kg.connect("live_host:http://api.example.com", "endpoint:http://api.example.com/v1/users", "HAS_ENDPOINT")
    kg.connect("live_host:http://api.example.com", "technology:Nginx", "RUNS_TECHNOLOGY")
    return kg


def test_match_graph_neighborhood_connected():
    kg = create_sample_graph()
    obs1 = Observation(
        source="scanner",
        category=ObservationCategory.API,
        title="Discovered Users API",
        description="Endpoint found",
        confidence=0.8,
        priority=ObservationPriority.MEDIUM,
        endpoints=["http://api.example.com/v1/users"]
    )
    obs2 = Observation(
        source="fingerprint",
        category=ObservationCategory.TECHNOLOGY,
        title="Detected Nginx Web Server",
        description="Tech found",
        confidence=0.8,
        priority=ObservationPriority.MEDIUM,
        technology=["Nginx"]
    )
    # Both are connected to live_host:http://api.example.com within 2 hops
    assert match_graph_neighborhood(obs1, obs2, graph=kg, max_hops=2) is True


def test_match_graph_neighborhood_disconnected():
    kg = create_sample_graph()
    obs1 = Observation(
        source="scanner",
        category=ObservationCategory.API,
        title="Discovered Users API",
        description="Endpoint found",
        confidence=0.8,
        priority=ObservationPriority.MEDIUM,
        endpoints=["http://api.example.com/v1/users"]
    )
    obs2 = Observation(
        source="probe",
        category=ObservationCategory.TECHNOLOGY,
        title="Isolated Host Found",
        description="Isolated host probe",
        confidence=0.8,
        priority=ObservationPriority.MEDIUM,
        graph_nodes=["live_host:http://isolated.example.com"]
    )
    # Unconnected to each other
    assert match_graph_neighborhood(obs1, obs2, graph=kg, max_hops=2) is False


def test_match_shared_graph_nodes_subgraph():
    kg = create_sample_graph()
    obs1 = Observation(
        source="scanner",
        category=ObservationCategory.API,
        title="Endpoint Obs",
        description="Endpoint on API host",
        confidence=0.8,
        priority=ObservationPriority.MEDIUM,
        graph_nodes=["endpoint:http://api.example.com/v1/users"]
    )
    obs2 = Observation(
        source="tech",
        category=ObservationCategory.TECHNOLOGY,
        title="Tech Obs",
        description="Tech on API host",
        confidence=0.8,
        priority=ObservationPriority.MEDIUM,
        graph_nodes=["technology:Nginx"]
    )
    # Both resolve to the same host subgraph
    assert match_shared_graph_nodes(obs1, obs2, graph=kg) is True


def test_correlation_engine_knowledge_graph_sync():
    kg = create_sample_graph()
    obs_reg = ObservationRegistry()
    corr_reg = CorrelationRegistry()
    corr_graph = CorrelationGraph()
    engine = CorrelationEngine(obs_reg, corr_reg, corr_graph)
    
    assert engine.knowledge_graph is None
    engine.knowledge_graph = kg
    assert engine.knowledge_graph is kg
    assert engine.matcher.graph is kg

    obs1 = Observation(
        source="test", category=ObservationCategory.API,
        title="Endpoint", description="Users endpoint",
        confidence=0.8, priority=ObservationPriority.MEDIUM,
        endpoints=["http://api.example.com/v1/users"]
    )
    obs2 = Observation(
        source="test", category=ObservationCategory.TECHNOLOGY,
        title="Tech", description="Nginx server",
        confidence=0.8, priority=ObservationPriority.MEDIUM,
        technology=["Nginx"]
    )
    engine.process_observation(obs1)
    engine.process_observation(obs2)

    correlations = corr_reg.get_all()
    assert len(correlations) >= 1
    assert obs1.id in correlations[0].observations
    assert obs2.id in correlations[0].observations


def test_fuse_shared_graph_nodes():
    obs1 = Observation(
        source="test", category=ObservationCategory.API,
        title="Obs 1", description="Obs 1 description",
        confidence=0.8, priority=ObservationPriority.MEDIUM,
        graph_nodes=["live_host:http://api.example.com"]
    )
    obs2 = Observation(
        source="test", category=ObservationCategory.TECHNOLOGY,
        title="Obs 2", description="Obs 2 description",
        confidence=0.8, priority=ObservationPriority.MEDIUM,
        graph_nodes=["live_host:http://api.example.com"]
    )
    assert fuse_shared_graph_nodes(obs1, obs2) is True
