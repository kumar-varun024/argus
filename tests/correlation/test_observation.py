import pytest
import uuid
from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority

def test_observation_creation():
    obs = Observation(
        source="test_source",
        category=ObservationCategory.AUTHORIZATION,
        title="Test Obs",
        description="This is a test",
        confidence=0.8,
        priority=ObservationPriority.HIGH
    )
    
    assert isinstance(obs.id, uuid.UUID)
    assert obs.source == "test_source"
    assert obs.category == ObservationCategory.AUTHORIZATION
    assert obs.title == "Test Obs"
    assert obs.confidence == 0.8
    assert obs.priority == ObservationPriority.HIGH
    assert obs.business_objects == []

def test_observation_validation_failure():
    from pydantic import ValidationError
    
    with pytest.raises(ValidationError):
        Observation(
            source="test",
            category="INVALID_CAT", # Invalid category
            title="Test",
            description="Desc",
            confidence=1.5, # > 1.0
            priority=ObservationPriority.LOW
        )

def test_observation_immutability():
    from pydantic import ValidationError
    
    obs = Observation(
        source="test",
        category=ObservationCategory.API,
        title="Test",
        description="Desc",
        confidence=0.9,
        priority=ObservationPriority.MEDIUM
    )
    
    with pytest.raises(ValidationError):
        obs.id = uuid.uuid4()
