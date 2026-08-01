import logging
from typing import List, Dict, Any

from argus.plugins.graphql.models import (
    GraphQLSchema, GraphQLRelationship, GraphQLBusinessObject,
    GraphQLCRUD, GraphQLWorkflow, GraphQLWorkflowNode, Observation
)
from argus.graph.node import Node
from argus.graph.workflow import WorkflowGraph

logger = logging.getLogger(__name__)

class BusinessKnowledgeAnalyzer:
    """Analyzes GraphQL schema to infer business objects, relationships, CRUD ops, and workflows."""
    
    def __init__(self):
        pass
        
    def analyze(self, mission):
        logger.info("BusinessKnowledgeAnalyzer: Starting business logic analysis...")
        
        if not hasattr(mission, "graphql") or not mission.graphql.schemas:
            logger.info("BusinessKnowledgeAnalyzer: No schema found to analyze.")
            return
            
        # Ensure mission.graphql lists are initialized
        if not hasattr(mission.graphql, "business_objects"):
            mission.graphql.business_objects = []
        if not hasattr(mission.graphql, "crud"):
            mission.graphql.crud = []
        if not hasattr(mission.graphql, "relationship_graph") or mission.graphql.relationship_graph is None:
            mission.graphql.relationship_graph = WorkflowGraph()
            
        for schema in mission.graphql.schemas:
            self._infer_business_objects(mission, schema)
            self._infer_relationships(mission, schema)
            self._infer_crud(mission, schema)
            self._infer_workflows(mission, schema)
            
    def _infer_business_objects(self, mission, schema: GraphQLSchema):
        # We assume important OBJECT types are business objects. 
        # Typically skip types like Query, Mutation, Subscription, and edges/connections.
        skip_names = {"Query", "Mutation", "Subscription"}
        
        for t_name, t_obj in schema.types.items():
            if t_obj.kind == "OBJECT" and t_name not in skip_names and not t_name.endswith("Connection") and not t_name.endswith("Edge"):
                bo = GraphQLBusinessObject(
                    name=t_name,
                    object_type=t_name,
                    evidence=t_obj.evidence,
                    confidence=0.8
                )
                mission.graphql.business_objects.append(bo)
                logger.info(f"BusinessKnowledgeAnalyzer: Business object discovered: {t_name}")
                
                # Add to findings
                self._add_observation(mission, f"Business object discovered: {t_name}", bo.evidence)
                
    def _infer_relationships(self, mission, schema: GraphQLSchema):
        for t_name, t_obj in schema.types.items():
            if t_obj.kind != "OBJECT":
                continue
                
            for f_name, field in t_obj.fields.items():
                target_type = field.type
                
                # Simple heuristic for edge types
                edge_type = "ASSOCIATED_WITH"
                if field.is_list:
                    edge_type = "HAS_CHILD"
                    if f_name.endswith("s"): # Collections often mean ownership
                        edge_type = "OWNS"
                elif f_name.endswith("Id") or f_name == "owner" or f_name == "organization":
                    edge_type = "REFERENCES"
                    if f_name == "owner" or f_name == "organization":
                        edge_type = "BELONGS_TO"
                
                if target_type in schema.types and schema.types[target_type].kind == "OBJECT":
                    rel = GraphQLRelationship(
                        parent=t_name,
                        child=target_type,
                        type=edge_type,
                        source="Schema",
                        evidence=t_obj.evidence
                    )
                    mission.graphql.relationships.append(rel)
                    logger.info(f"BusinessKnowledgeAnalyzer: Relationship inferred: {t_name} {edge_type} {target_type}")
                    
                    if hasattr(mission, "graph") and mission.graph:
                        mission.graph.connect(f"graphql_type_{t_obj.id}", f"graphql_type_{schema.types[target_type].id}", edge_type)
                        
                    self._add_observation(mission, f"Relationship inferred: {t_name} {edge_type} {target_type}", rel.evidence)
                    
    def _infer_crud(self, mission, schema: GraphQLSchema):
        operations = list(schema.queries.values()) + list(schema.mutations.values())
        
        for op in operations:
            action = None
            op_name = op.name.lower()
            
            if op_name.startswith("create") or op_name.startswith("add") or op_name.startswith("insert"):
                action = "CREATE"
            elif op_name.startswith("update") or op_name.startswith("edit") or op_name.startswith("modify"):
                action = "UPDATE"
            elif op_name.startswith("delete") or op_name.startswith("remove") or op_name.startswith("destroy"):
                action = "DELETE"
            elif op_name.startswith("list") or op_name.startswith("getall"):
                action = "LIST"
            elif op_name.startswith("search") or op_name.startswith("find"):
                action = "SEARCH"
            elif op_name.startswith("get") or op.operation_type == "Query":
                action = "READ"
                
            if action:
                crud = GraphQLCRUD(
                    operation_name=op.name,
                    action=action,
                    object_type=op.return_type,
                    evidence=op.evidence
                )
                mission.graphql.crud.append(crud)
                logger.info(f"BusinessKnowledgeAnalyzer: CRUD classified: {op.name} -> {action} {op.return_type}")
                self._add_observation(mission, f"CRUD lifecycle inferred: {action} operation {op.name}", crud.evidence)
                
    def _infer_workflows(self, mission, schema: GraphQLSchema):
        # A simple workflow inference: look for grouped operations that might form a chain.
        # Example: invite -> accept -> join
        workflow_hints = [
            {"name": "Invitation", "keywords": ["invite", "invitation", "join", "accept"]},
            {"name": "Checkout", "keywords": ["checkout", "pay", "order", "ship", "refund"]},
            {"name": "Authentication", "keywords": ["register", "verify", "login", "auth", "session"]}
        ]
        
        mutations = schema.mutations.values()
        
        for hint in workflow_hints:
            related_ops = []
            for m in mutations:
                if any(kw in m.name.lower() for kw in hint["keywords"]):
                    related_ops.append(m)
                    
            if len(related_ops) > 1:
                # We have a workflow
                wf = GraphQLWorkflow(name=hint["name"])
                wf_graph = mission.graphql.relationship_graph
                
                prev_node = None
                for op in related_ops:
                    state_node = GraphQLWorkflowNode(name=op.name, state=op.name, evidence=op.evidence)
                    wf.states.append(state_node)
                    wf.business_objects.append(op.return_type)
                    wf.evidence.extend(op.evidence)
                    
                    graph_node = Node(id=f"wf_node_{op.name}", type="WorkflowState", value=op.name)
                    wf_graph.add(graph_node)
                    
                    if prev_node:
                        wf.transitions.append({"from": prev_node.id, "to": graph_node.id})
                        wf_graph.connect(prev_node.id, graph_node.id, "TRANSITION_TO")
                        
                    prev_node = graph_node
                    
                mission.graphql.workflows.append(wf)
                logger.info(f"BusinessKnowledgeAnalyzer: Workflow inferred: {wf.name}")
                self._add_observation(mission, f"Workflow inferred: {wf.name}", wf.evidence)
                
    def _add_observation(self, mission, description: str, evidence: List[Any]):
        if not hasattr(mission, "findings"):
            mission.findings = []
        obs = Observation(description=description, evidence=evidence)
        mission.findings.append(obs)
