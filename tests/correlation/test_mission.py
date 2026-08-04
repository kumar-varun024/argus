import pytest
from argus.runtime.mission import Mission
from argus.correlation.registry import ObservationRegistry

def test_mission_observation_registry():
    mission = Mission("test")
    assert isinstance(mission.observations, ObservationRegistry)
