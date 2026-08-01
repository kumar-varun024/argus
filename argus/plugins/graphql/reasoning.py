import logging
from typing import List, Dict, Any

from argus.plugins.graphql.models import (
    GraphQLInvestigation, GraphQLWorkflow, GraphQLBusinessObject, GraphQLCRUD, Observation
)

logger = logging.getLogger(__name__)

class GraphQLReasoningEngine:
    def __init__(self):
        pass

    def analyze(self, mission):
        logger.info("GraphQLReasoningEngine: Starting reasoning analysis...")
        
        if not hasattr(mission, "graphql"):
            return
            
        graphql = mission.graphql
        
        # 1. Review Workflows
        for wf in getattr(graphql, "workflows", []):
            self._analyze_workflow(mission, wf)
            
        # 2. Review Authorization context on sensitive ops
        self._analyze_crud(mission)
        
        # 3. Prioritize
        self._prioritize(mission)
        
    def _analyze_workflow(self, mission, workflow: GraphQLWorkflow):
        inv = GraphQLInvestigation(
            title=f"Review {workflow.name} Workflow",
            description=f"Administrative or business-critical workflow detected: {workflow.name}",
            category="Workflow Review",
            reasoning=f"{workflow.name} workflow discovered involving state transitions across mutations.",
            evidence=workflow.evidence,
            confidence=0.85,
            priority="High",
            related_workflow=workflow.name,
            business_objects=workflow.business_objects,
            manual_validation_guidance="Review whether authorized users with different roles can execute these workflow transitions in accordance with the application's intended authorization model.",
            tags=["workflow", "business-logic"]
        )
        self._merge_investigation(mission, inv)
        
    def _analyze_crud(self, mission):
        graphql = mission.graphql
        crud_ops = getattr(graphql, "crud", [])
        relationships = getattr(graphql, "relationships", [])
        
        # Build map of object to its relationships
        obj_rels = {}
        for rel in relationships:
            if rel.parent not in obj_rels:
                obj_rels[rel.parent] = []
            obj_rels[rel.parent].append(rel)
            
        for op in crud_ops:
            if op.action in ["CREATE", "UPDATE", "DELETE"]:
                # Check if the target object has ownership relationships
                target_rels = obj_rels.get(op.object_type, [])
                has_ownership = any(r.type in ["OWNS", "BELONGS_TO"] for r in target_rels)
                
                if has_ownership:
                    inv = GraphQLInvestigation(
                        title=f"Review {op.object_type} Authorization",
                        description=f"Administrative operation on {op.object_type} object with ownership constraints.",
                        category="Object-Level Authorization Review",
                        reasoning=f"Mutation {op.operation_name} modifies {op.object_type} objects. {op.object_type} has ownership relationships. Administrative workflow detected.",
                        evidence=op.evidence,
                        confidence=0.88,
                        priority="High",
                        related_operations=[op.operation_name],
                        business_objects=[op.object_type],
                        manual_validation_guidance=f"Review whether authorized users with different roles can modify {op.object_type} resources in accordance with the application's intended authorization model.",
                        tags=["authz", "ownership", op.action.lower()]
                    )
                    self._merge_investigation(mission, inv)
                    
    def _merge_investigation(self, mission, new_inv: GraphQLInvestigation):
        graphql = mission.graphql
        for existing in graphql.investigations:
            # Simple deduplication based on title
            if existing.title == new_inv.title:
                existing.evidence.extend(new_inv.evidence)
                existing.related_operations = list(set(existing.related_operations + new_inv.related_operations))
                existing.business_objects = list(set(existing.business_objects + new_inv.business_objects))
                # Boost confidence slightly
                existing.confidence = min(1.0, existing.confidence + 0.05)
                return
                
        graphql.investigations.append(new_inv)
        graphql.reasoning.append(f"Generated investigation: {new_inv.title}")
        logger.info(f"GraphQLReasoningEngine: Created investigation '{new_inv.title}'")

    def _prioritize(self, mission):
        # Sort investigations into priority_queue
        graphql = mission.graphql
        priority_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
        
        graphql.investigations.sort(key=lambda x: priority_map.get(x.priority, 0), reverse=True)
        graphql.priority_queue = [inv for inv in graphql.investigations]
