from argus.authorization.graph import AuthorizationGraph
from argus.authorization.models import AuthNodeType
from typing import List, Set

class GraphHelper:
    """Helper methods for extracting specific insights from the Authorization Graph."""
    
    def __init__(self, graph: AuthorizationGraph):
        self.graph = graph

    def get_multi_role_resources(self) -> List[str]:
        """Finds resources that are accessed by multiple distinct roles."""
        multi_role = []
        resources = self.graph.get_nodes_by_type(AuthNodeType.PROTECTED_RESOURCE)
        for res in resources:
            roles = set()
            for edge in self.graph.edges:
                if edge.target == res.name and edge.relation == "can_access":
                    # Check if source is a role
                    source_node = self.graph.get_node(edge.source)
                    if source_node and source_node.node_type == AuthNodeType.ROLE:
                        roles.add(source_node.name)
            if len(roles) > 1:
                multi_role.append(res.name)
        return multi_role
        
    def get_isolated_resources(self) -> List[str]:
        """Finds resources that have no incoming access edges."""
        isolated = []
        resources = self.graph.get_nodes_by_type(AuthNodeType.PROTECTED_RESOURCE)
        for res in resources:
            has_access = False
            for edge in self.graph.edges:
                if edge.target == res.name and edge.relation in ["can_access", "owns"]:
                    has_access = True
                    break
            if not has_access:
                isolated.append(res.name)
        return isolated
