import pytest
import uuid
from argus.correlation.engine import CorrelationEngine
from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority
from argus.correlation.registry import ObservationRegistry, CorrelationRegistry
from argus.correlation.graph import CorrelationGraph

def test_correlation_engine_linking():
    obs_registry = ObservationRegistry()
    corr_registry = CorrelationRegistry()
    graph = CorrelationGraph()
    
    engine = CorrelationEngine(obs_registry, corr_registry, graph)
    
    # GraphQL discovers Organization
    obs1 = Observation(
        source="graphql",
        category=ObservationCategory.GRAPHQL,
        title="GraphQL Org",
        description="Found Org",
        confidence=1.0,
        priority=ObservationPriority.LOW,
        business_objects=["Organization"]
    )
    
    # JavaScript discovers Organization route
    obs2 = Observation(
        source="javascript",
        category=ObservationCategory.JAVASCRIPT,
        title="JS Org",
        description="Found Org route",
        confidence=1.0,
        priority=ObservationPriority.LOW,
        business_objects=["Organization"]
    )
    
    # Authorization discovers Ownership
    obs3 = Observation(
        source="authorization",
        category=ObservationCategory.AUTHORIZATION,
        title="Authz Org",
        description="Ownership",
        confidence=1.0,
        priority=ObservationPriority.LOW,
        business_objects=["Organization"]
    )
    
    engine.process_observation(obs1)
    engine.process_observation(obs2)
    
    correlations = corr_registry.get_all()
    assert len(correlations) == 1
    corr = correlations[0]
    
    assert len(corr.observations) == 2
    assert obs1.id in corr.observations
    assert obs2.id in corr.observations
    
    # Test adding a 3rd observation to existing correlation
    engine.process_observation(obs3)
    
    correlations = corr_registry.get_all()
    assert len(correlations) == 1
    corr = correlations[0]
    
    assert len(corr.observations) == 3
    assert "Organization" in corr.business_objects

def test_correlation_engine_merging():
    obs_registry = ObservationRegistry()
    corr_registry = CorrelationRegistry()
    graph = CorrelationGraph()
    engine = CorrelationEngine(obs_registry, corr_registry, graph)
    
    obs1 = Observation(source="t", category=ObservationCategory.API, title="t", description="t", confidence=1.0, priority=ObservationPriority.LOW, business_objects=["A"])
    obs2 = Observation(source="t", category=ObservationCategory.API, title="t", description="t", confidence=1.0, priority=ObservationPriority.LOW, business_objects=["B"])
    
    engine.process_observation(obs1)
    engine.process_observation(obs2)
    
    # No correlations yet as they don't match
    assert len(corr_registry.get_all()) == 0
    
    # obs3 matches BOTH A and B, which should pull them into one correlation
    obs3 = Observation(source="t", category=ObservationCategory.API, title="t", description="t", confidence=1.0, priority=ObservationPriority.LOW, business_objects=["A", "B"])
    
    engine.process_observation(obs3)
    
    correlations = corr_registry.get_all()
    assert len(correlations) == 1
    corr = correlations[0]
    assert len(corr.observations) == 3
