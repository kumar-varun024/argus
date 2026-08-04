import pytest
from argus.correlation.matcher import CorrelationMatcher
from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority

def create_obs(**kwargs) -> Observation:
    defaults = {
        "source": "test",
        "category": ObservationCategory.API,
        "title": "test",
        "description": "test",
        "confidence": 1.0,
        "priority": ObservationPriority.LOW
    }
    defaults.update(kwargs)
    return Observation(**defaults)

def test_correlation_matcher():
    matcher = CorrelationMatcher()
    obs1 = create_obs(business_objects=["User"], tags=["critical"])
    obs2 = create_obs(business_objects=["User"], tags=["low"])
    obs3 = create_obs(business_objects=["Project"])
    
    matches = matcher.find_matches(obs1, obs2)
    assert "match_shared_business_objects" in matches
    assert "match_shared_tags" not in matches
    
    matches_none = matcher.find_matches(obs1, obs3)
    assert len(matches_none) == 0
