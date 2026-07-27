from typing import Any
from argus.authorization.graph import AuthorizationGraph
from argus.authorization.models import AuthNode, AuthEdge, AuthNodeType, AuthEdgeType
from argus.authorization.rules import (
    get_role_hierarchy_rules, 
    get_ownership_rules, 
    infer_permission_from_method,
    infer_node_type_for_business_object
)

class AuthorizationGraphBuilder:
    def __init__(self, mission: Any):
        self.mission = mission
        self.graph = AuthorizationGraph()

    def build(self) -> AuthorizationGraph:
        self._build_role_hierarchy()
        self._build_from_workflows()
        self._infer_ownership()
        
        if hasattr(self.mission, 'authorization_graph'):
            self.mission.authorization_graph = self.graph
            
        return self.graph

    def _build_role_hierarchy(self):
        rules = get_role_hierarchy_rules()
        for parent_role, children in rules.items():
            parent_node = self._get_or_create_node(parent_role, AuthNodeType.ROLE, inferred=True)
            for child_role in children:
                child_node = self._get_or_create_node(child_role, AuthNodeType.ROLE, inferred=True)
                # Parent INHERITS from Child, or Child BELONGS_TO Parent? 
                # "Admin inherits Manager". So Parent -> INHERITS -> Child
                self._add_edge(parent_node.id, child_node.id, AuthEdgeType.INHERITS, inferred=True)

    def _build_from_workflows(self):
        workflows = getattr(self.mission, "workflows", [])
        for wf in workflows:
            for step in wf.steps:
                bo_name = step.business_object or wf.name.replace(" Management", "")
                if not bo_name:
                    continue
                
                bo_type = infer_node_type_for_business_object(bo_name)
                bo_node = self._get_or_create_node(bo_name, bo_type)
                
                role_name = step.required_role or "Guest"
                role_node = self._get_or_create_node(role_name, AuthNodeType.ROLE)
                
                edge_type = infer_permission_from_method(step.http_method)
                self._add_edge(role_node.id, bo_node.id, edge_type, inferred=(not step.required_role))

    def _infer_ownership(self):
        # Based on constructed BOs, apply ownership rules
        ownership_rules = get_ownership_rules()
        
        for parent_name, children in ownership_rules.items():
            parent_node = self.graph.get_node_by_name_and_type(parent_name, AuthNodeType.ORGANIZATION) or \
                          self.graph.get_node_by_name_and_type(parent_name, AuthNodeType.PROJECT) or \
                          self.graph.get_node_by_name_and_type(parent_name, AuthNodeType.BUSINESS_OBJECT)
            
            if not parent_node:
                continue
                
            for child_name in children:
                child_node = self.graph.get_node_by_name_and_type(child_name, AuthNodeType.REPOSITORY) or \
                             self.graph.get_node_by_name_and_type(child_name, AuthNodeType.PROJECT) or \
                             self.graph.get_node_by_name_and_type(child_name, AuthNodeType.BUSINESS_OBJECT)
                
                if child_node:
                    self._add_edge(parent_node.id, child_node.id, AuthEdgeType.OWNS, inferred=True)

    def _get_or_create_node(self, name: str, node_type: AuthNodeType, inferred: bool = False) -> AuthNode:
        node = self.graph.get_node_by_name_and_type(name, node_type)
        if not node:
            node = AuthNode(name=name, node_type=node_type, inferred=inferred)
            self.graph.add_node(node)
        return node

    def _add_edge(self, source_id: str, target_id: str, edge_type: AuthEdgeType, inferred: bool = False) -> AuthEdge:
        # Check if edge already exists
        existing = self.graph.get_outgoing_edges(source_id, edge_type)
        for e in existing:
            if e.target_id == target_id:
                return e
                
        edge = AuthEdge(source_id=source_id, target_id=target_id, edge_type=edge_type, inferred=inferred)
        self.graph.add_edge(edge)
        return edge
