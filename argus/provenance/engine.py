from argus.provenance.graph import ProvenanceGraph
from argus.provenance.models import ProvenanceRecord
from argus.provenance.trace import ArtifactTracer
from argus.provenance.validator import ProvenanceValidator
from typing import Dict, Any

class ProvenanceEngine:
    def __init__(self):
        self.graph = ProvenanceGraph()
        self.tracer = ArtifactTracer(self.graph)
        self.validator = ProvenanceValidator(self.graph)

    def register_artifact(self, record: ProvenanceRecord):
        """Registers a new artifact node in the provenance graph."""
        self.graph.add_node(record)
        
    def link_artifacts(self, parent_id: str, child_id: str):
        """Links a child artifact to its parent source."""
        self.graph.link(parent_id, child_id)
        
    def explain(self, artifact_id: str) -> str:
        """Returns a human-readable explanation of an artifact's lineage."""
        return self.tracer.explain(artifact_id)
        
    def trace(self, artifact_id: str) -> Dict[str, Any]:
        """Returns a structured view of the lineage."""
        node = self.graph.get_node(artifact_id)
        if not node:
            return {"error": "Artifact not found."}
            
        return {
            "id": node.id,
            "type": node.artifact_type,
            "parents": [p.id for p in self.tracer.parents(artifact_id)],
            "source_evidence": node.source_evidence
        }
        
    def validate(self) -> bool:
        """Runs the validator over the graph to ensure complete provenance."""
        return self.validator.validate_graph()

    def get_stats(self) -> Dict[str, int]:
        nodes = self.graph.all_nodes()
        unsupported = [n for n in nodes if not self.validator._has_root_evidence(n.id, set())]
        return {
            "total_artifacts": len(nodes),
            "unsupported_artifacts": len(unsupported)
        }

# Global singleton for easy tracking across the platform
provenance_engine = ProvenanceEngine()
