from typing import Any, Optional, Dict, List
from .node import Node
from .edge import Edge

class WorkflowGraph:
    """
    Workflow Graph for mapping multi-step business state transitions and relationships.
    """
    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []

    def add(self, node: Node) -> bool:
        if node.id in self.nodes:
            return False
        self.nodes[node.id] = node
        return True

    def get(self, node_id: str) -> Optional[Node]:
        return self.nodes.get(node_id)

    def connect(self, source: str, target: str, edge_type: str = "TRANSITION_TO", metadata: Optional[Dict[str, Any]] = None) -> bool:
        if source not in self.nodes or target not in self.nodes:
            return False
        
        for edge in self.edges:
            if edge.source == source and edge.target == target and edge.type == edge_type:
                return False
                
        edge = Edge(source=source, target=target, type=edge_type, metadata=metadata or {})
        self.edges.append(edge)
        return True

    def all(self) -> List[Node]:
        return list(self.nodes.values())
