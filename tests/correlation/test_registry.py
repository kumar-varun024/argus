import pytest
import uuid
from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority
from argus.correlation.registry import ObservationRegistry

def test_registry_add_find():
    registry = ObservationRegistry()
    obs = Observation(
        source="test",
        category=ObservationCategory.API,
        title="API Leak",
        description="Leak found",
        confidence=0.5,
        priority=ObservationPriority.LOW
    )
    
    registry.add(obs)
    assert registry.find(obs.id) == obs

def test_registry_remove():
    registry = ObservationRegistry()
    obs = Observation(
        source="test",
        category=ObservationCategory.API,
        title="API Leak",
        description="Leak found",
        confidence=0.5,
        priority=ObservationPriority.LOW
    )
    
    registry.add(obs)
    assert registry.remove(obs.id) is True
    assert registry.find(obs.id) is None
    assert registry.remove(uuid.uuid4()) is False

def test_registry_search_filter():
    registry = ObservationRegistry()
    
    obs1 = Observation(source="module_a", category=ObservationCategory.API, title="Key Exposure", description="Found key", confidence=0.8, priority=ObservationPriority.HIGH)
    obs2 = Observation(source="module_b", category=ObservationCategory.AUTHORIZATION, title="Bypass", description="Auth bypass", confidence=0.9, priority=ObservationPriority.CRITICAL)
    obs3 = Observation(source="module_a", category=ObservationCategory.API, title="SQLi", description="SQL injection", confidence=0.4, priority=ObservationPriority.MEDIUM)
    
    registry.add(obs1)
    registry.add(obs2)
    registry.add(obs3)
    
    # Search
    assert len(registry.search("key")) == 1
    assert len(registry.search("found")) == 1
    
    # Filter
    api_obs = registry.filter(category=ObservationCategory.API)
    assert len(api_obs) == 2
    
    module_a_obs = registry.filter(source="module_a")
    assert len(module_a_obs) == 2
    
    high_conf_obs = registry.filter(min_confidence=0.85)
    assert len(high_conf_obs) == 1
    assert high_conf_obs[0] == obs2
