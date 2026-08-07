import pytest
from argus.runtime.mission import Mission
from argus.benchmark.metrics.performance import PerformanceCalculator

def test_performance_calculation():
    mission = Mission(target="http://test")
    mission.execution_metrics = {
        "memory_usage_mb": 150.5,
        "cpu_usage_percent": 45.2,
        "planner_time_ms": 100.0,
        "correlation_time_ms": 200.0,
        "investigation_time_ms": 300.0
    }
    
    class MockGraph:
        def nodes(self):
            return [1, 2, 3, 4]
            
    mission.correlation_graph = MockGraph()
    
    report = PerformanceCalculator.calculate(mission, execution_time_ms=1000.0)
    
    assert report.memory_usage_mb == 150.5
    assert report.cpu_usage_percent == 45.2
    assert report.planner_time_ms == 100.0
    assert report.correlation_time_ms == 200.0
    assert report.investigation_time_ms == 300.0
    assert report.execution_time_ms == 1000.0
    assert report.graph_size == 4
    # duration is calculated from created_at/updated_at, which we didn't mock strictly for time parsing but it will fallback or calculate
    assert report.mission_duration_ms > 0
