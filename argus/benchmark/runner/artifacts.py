from typing import Any, List
from argus.runtime.mission import Mission
from argus.benchmark.runner.models import BenchmarkArtifacts

class ArtifactCollector:
    """Collects artifacts safely from a completed Mission object."""
    
    @classmethod
    def collect(cls, mission: Mission) -> BenchmarkArtifacts:
        def _get_all_safely(registry: Any) -> List[Any]:
            if hasattr(registry, "get_all"):
                return registry.get_all()
            return []

        return BenchmarkArtifacts(
            mission_results=getattr(mission, "raw_outputs", {}),
            execution_metrics=getattr(mission, "execution_metrics", {}),
            knowledge_graph=getattr(mission, "knowledge_graph", None),
            workflow_graph=getattr(mission, "workflow_graph", None),
            observations=_get_all_safely(getattr(mission, "observations", None)),
            correlations=_get_all_safely(getattr(mission, "correlations", None)),
            evidence_bundles=_get_all_safely(getattr(mission, "evidence_bundles", None)),
            investigations=_get_all_safely(getattr(mission, "investigations", None)),
            hypotheses=_get_all_safely(getattr(mission, "hypotheses", None)),
            logs=getattr(mission, "execution_history", []),
            runtime_statistics=getattr(mission, "metrics", {})
        )
