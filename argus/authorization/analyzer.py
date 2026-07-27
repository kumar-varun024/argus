from typing import List, Dict, Set
from argus.authorization.graph import AuthorizationGraph
from argus.authorization.models import AuthNodeType, AuthEdgeType, AuthNode

class AuthorizationAnalyzer:
    def __init__(self, graph: AuthorizationGraph):
        self.graph = graph

    def get_role_hierarchy(self) -> Dict[str, List[str]]:
        """Returns a dict mapping parent role -> list of child roles."""
        hierarchy = {}
        for edge in self.graph.edges:
            if edge.edge_type == AuthEdgeType.INHERITS:
                parent = self.graph.get_node(edge.source_id)
                child = self.graph.get_node(edge.target_id)
                if parent and child:
                    hierarchy.setdefault(parent.name, []).append(child.name)
        return hierarchy

    def get_ownership_chains(self) -> List[List[str]]:
        """Finds all paths of OWNS edges and returns as lists of node names."""
        chains = []
        
        # Find roots of ownership (nodes with outgoing OWNS but no incoming OWNS)
        owns_edges = [e for e in self.graph.edges if e.edge_type == AuthEdgeType.OWNS]
        if not owns_edges:
            return []
            
        sources = set(e.source_id for e in owns_edges)
        targets = set(e.target_id for e in owns_edges)
        roots = sources - targets
        
        def dfs(node_id: str, current_chain: List[str]):
            node = self.graph.get_node(node_id)
            if not node:
                return
                
            new_chain = current_chain + [node.name]
            
            outgoing = self.graph.get_outgoing_edges(node_id, AuthEdgeType.OWNS)
            if not outgoing:
                if len(new_chain) > 1:
                    chains.append(new_chain)
            else:
                for edge in outgoing:
                    dfs(edge.target_id, new_chain)

        for root in roots:
            dfs(root, [])
            
        return chains

    def get_authorization_boundaries(self) -> List[str]:
        """Returns the names of business objects or resources that have role-based boundaries."""
        boundaries = set()
        for edge in self.graph.edges:
            if edge.edge_type in [AuthEdgeType.CAN_CREATE, AuthEdgeType.CAN_UPDATE, AuthEdgeType.CAN_DELETE]:
                source = self.graph.get_node(edge.source_id)
                target = self.graph.get_node(edge.target_id)
                if source and target and source.node_type == AuthNodeType.ROLE:
                    boundaries.add(target.name)
        return list(boundaries)
