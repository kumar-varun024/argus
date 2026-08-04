import pytest
from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority
from argus.correlation.serializer import ObservationSerializer

def test_json_serialization():
    obs = Observation(
        source="test",
        category=ObservationCategory.API,
        title="Test JSON",
        description="JSON test",
        confidence=1.0,
        priority=ObservationPriority.LOW,
        metadata={"foo": "bar"}
    )
    
    json_str = ObservationSerializer.to_json(obs)
    obs_restored = ObservationSerializer.from_json(json_str)
    
    assert obs.id == obs_restored.id
    assert obs.metadata == obs_restored.metadata

def test_yaml_serialization():
    obs = Observation(
        source="test",
        category=ObservationCategory.API,
        title="Test YAML",
        description="YAML test",
        confidence=1.0,
        priority=ObservationPriority.LOW
    )
    
    yaml_str = ObservationSerializer.to_yaml(obs)
    obs_restored = ObservationSerializer.from_yaml(yaml_str)
    
    assert obs.id == obs_restored.id

def test_msgpack_serialization():
    obs = Observation(
        source="test",
        category=ObservationCategory.API,
        title="Test MSGPACK",
        description="Msgpack test",
        confidence=1.0,
        priority=ObservationPriority.LOW
    )
    
    try:
        import msgpack
    except ImportError:
        pytest.skip("msgpack not installed")
        
    msgpack_bytes = ObservationSerializer.to_msgpack(obs)
    obs_restored = ObservationSerializer.from_msgpack(msgpack_bytes)
    
    assert obs.id == obs_restored.id
