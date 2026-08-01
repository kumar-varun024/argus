from typing import List, Optional
from argus.provenance.graph import ProvenanceGraph
from argus.provenance.models import ProvenanceRecord

class ArtifactTracer:
    def __init__(self, graph: ProvenanceGraph):
        self.graph = graph

    def parents(self, artifact_id: str) -> List[ProvenanceRecord]:
        node = self.graph.get_node(artifact_id)
        if not node:
            return []
        
        result = []
        for pid in node.parent_artifacts:
            p_node = self.graph.get_node(pid)
            if p_node:
                result.append(p_node)
        return result

    def children(self, artifact_id: str) -> List[ProvenanceRecord]:
        node = self.graph.get_node(artifact_id)
        if not node:
            return []
            
        result = []
        for cid in node.child_artifacts:
            c_node = self.graph.get_node(cid)
            if c_node:
                result.append(c_node)
        return result

    def explain(self, artifact_id: str) -> str:
        """Returns a human readable text trace showing lineage up to roots."""
        node = self.graph.get_node(artifact_id)
        if not node:
            return f"Artifact '{artifact_id}' not found in provenance graph."
            
        trace_lines = []
        
        def traverse(current_node: ProvenanceRecord, depth: int):
            indent = "  " * depth
            trace_lines.append(f"{indent}↓ {current_node.artifact_type} ({current_node.id}) created by {current_node.created_by}")
            
            for pid in current_node.parent_artifacts:
                parent_node = self.graph.get_node(pid)
                if parent_node:
                    traverse(parent_node, depth + 1)
            
            if not current_node.parent_artifacts and current_node.source_evidence:
                trace_lines.append(f"{indent}  ↳ Source Evidence: {', '.join(current_node.source_evidence)}")
            
        traverse(node, 0)
        return "\n".join(trace_lines)
