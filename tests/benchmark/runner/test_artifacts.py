import pytest
from argus.runtime.mission import Mission
from argus.benchmark.runner.artifacts import ArtifactCollector

def test_artifact_collection():
    mission = Mission(target="http://test")
    
    # Mock some registries
    class MockRegistry:
        def get_all(self):
            return ["item1", "item2"]
            
    mission.observations = MockRegistry()
    mission.execution_metrics = {"time": 100}
    mission.execution_history = ["log1"]
    
    artifacts = ArtifactCollector.collect(mission)
    
    assert artifacts.observations == ["item1", "item2"]
    assert artifacts.execution_metrics == {"time": 100}
    assert artifacts.logs == ["log1"]
    # Unset fields should fall back safely
    assert artifacts.correlations == []
