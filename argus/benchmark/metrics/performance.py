from argus.runtime.mission import Mission
from argus.benchmark.metrics.models import PerformanceReport
import time

class PerformanceCalculator:
    """Extracts and calculates performance metrics from the mission object."""
    
    @classmethod
    def calculate(cls, mission: Mission, execution_time_ms: float) -> PerformanceReport:
        """Calculates performance report."""
        
        # Determine duration from timestamps if possible
        try:
            from dateutil import parser
            start = parser.parse(mission.created_at)
            end = parser.parse(mission.updated_at)
            duration_ms = (end - start).total_seconds() * 1000
        except Exception:
            duration_ms = execution_time_ms

        # Fallback metric extraction (until a formal Profiling framework is available)
        graph_size = 0
        if mission.correlation_graph and hasattr(mission.correlation_graph, "nodes"):
            graph_size = len(mission.correlation_graph.nodes())
            
        memory_usage = 0.0 # Placeholder
        cpu_usage = 0.0 # Placeholder
        planner_time = 0.0
        correlation_time = 0.0
        investigation_time = 0.0
        
        if hasattr(mission, "execution_metrics"):
            metrics = mission.execution_metrics
            memory_usage = metrics.get("memory_usage_mb", 0.0)
            cpu_usage = metrics.get("cpu_usage_percent", 0.0)
            planner_time = metrics.get("planner_time_ms", 0.0)
            correlation_time = metrics.get("correlation_time_ms", 0.0)
            investigation_time = metrics.get("investigation_time_ms", 0.0)
            
        return PerformanceReport(
            mission_duration_ms=duration_ms,
            memory_usage_mb=memory_usage,
            cpu_usage_percent=cpu_usage,
            graph_size=graph_size,
            execution_time_ms=execution_time_ms,
            planner_time_ms=planner_time,
            correlation_time_ms=correlation_time,
            investigation_time_ms=investigation_time
        )
