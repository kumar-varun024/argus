from argus.provenance.graph import ProvenanceGraph
import logging

logger = logging.getLogger(__name__)

class ProvenanceValidator:
    def __init__(self, graph: ProvenanceGraph):
        self.graph = graph

    def validate_graph(self) -> bool:
        """
        Validates that all nodes eventually trace back to source_evidence.
        Returns True if completely healthy, False if there are black-box/orphaned nodes.
        """
        is_healthy = True
        for node in self.graph.all_nodes():
            if not self._has_root_evidence(node.id, set()):
                logger.warning(f"Validation Error: Artifact {node.id} ({node.artifact_type}) has no supporting evidence lineage!")
                is_healthy = False
        return is_healthy

    def _has_root_evidence(self, node_id: str, visited: set) -> bool:
        if node_id in visited:
            return False
        
        visited.add(node_id)
        node = self.graph.get_node(node_id)
        if not node:
            return False
            
        if node.source_evidence:
            return True
            
        if not node.parent_artifacts:
            # Reached a root but no source evidence
            return False
            
        # If any parent path leads to root evidence, we consider this node supported.
        for pid in node.parent_artifacts:
            if self._has_root_evidence(pid, set(visited)):
                return True
                
        return False
