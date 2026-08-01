from typing import Dict, List, Optional
from argus.provenance.models import ProvenanceRecord

class ProvenanceGraph:
    def __init__(self):
        self._nodes: Dict[str, ProvenanceRecord] = {}

    def add_node(self, record: ProvenanceRecord):
        if record.id in self._nodes:
            raise ValueError(f"ProvenanceRecord with ID {record.id} already exists in graph.")
        self._nodes[record.id] = record

    def get_node(self, record_id: str) -> Optional[ProvenanceRecord]:
        return self._nodes.get(record_id)

    def link(self, parent_id: str, child_id: str):
        """Creates a directional edge from parent to child."""
        if parent_id not in self._nodes:
            raise ValueError(f"Parent node {parent_id} does not exist.")
        if child_id not in self._nodes:
            raise ValueError(f"Child node {child_id} does not exist.")
            
        parent = self._nodes[parent_id]
        child = self._nodes[child_id]
        
        if child_id not in parent.child_artifacts:
            parent.child_artifacts.append(child_id)
        if parent_id not in child.parent_artifacts:
            child.parent_artifacts.append(parent_id)

    def all_nodes(self) -> List[ProvenanceRecord]:
        return list(self._nodes.values())
