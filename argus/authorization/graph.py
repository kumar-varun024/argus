from typing import List, Dict, Optional, Set
from argus.authorization.models import AuthNode, AuthEdge, AuthNodeType, AuthEdgeType

class AuthorizationGraph:
    def __init__(self):
        self.nodes: Dict[str, AuthNode] = {}
        self.edges: List[AuthEdge] = []
        # optimization lookups
        self._edges_by_source: Dict[str, List[AuthEdge]] = {}
        self._edges_by_target: Dict[str, List[AuthEdge]] = {}

    def add_node(self, node: AuthNode) -> AuthNode:
        if node.id not in self.nodes:
            self.nodes[node.id] = node
            self._edges_by_source[node.id] = []
            self._edges_by_target[node.id] = []
        return self.nodes[node.id]

    def get_node(self, node_id: str) -> Optional[AuthNode]:
        return self.nodes.get(node_id)
        
    def get_node_by_name_and_type(self, name: str, node_type: AuthNodeType) -> Optional[AuthNode]:
        for node in self.nodes.values():
            if node.name.lower() == name.lower() and node.node_type == node_type:
                return node
        return None

    def add_edge(self, edge: AuthEdge) -> AuthEdge:
        self.edges.append(edge)
        
        if edge.source_id not in self._edges_by_source:
            self._edges_by_source[edge.source_id] = []
        self._edges_by_source[edge.source_id].append(edge)
        
        if edge.target_id not in self._edges_by_target:
            self._edges_by_target[edge.target_id] = []
        self._edges_by_target[edge.target_id].append(edge)
        
        return edge

    def get_outgoing_edges(self, node_id: str, edge_type: Optional[AuthEdgeType] = None) -> List[AuthEdge]:
        edges = self._edges_by_source.get(node_id, [])
        if edge_type:
            return [e for e in edges if e.edge_type == edge_type]
        return edges

    def get_incoming_edges(self, node_id: str, edge_type: Optional[AuthEdgeType] = None) -> List[AuthEdge]:
        edges = self._edges_by_target.get(node_id, [])
        if edge_type:
            return [e for e in edges if e.edge_type == edge_type]
        return edges

    def get_nodes_by_type(self, node_type: AuthNodeType) -> List[AuthNode]:
        return [n for n in self.nodes.values() if n.node_type == node_type]
