import logging
import re
from typing import List, Dict, Any, Set
from argus.workspace.context.models import ContextSource, ContextQuery
from argus.runtime.manager import mission_manager
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.edge import Edge
from argus.workspace.repository import ConversationRepository

logger = logging.getLogger(__name__)

class KnowledgeGraphRetriever:
    """Retrieves relevant entities and relationships from the Knowledge Graph."""
    
    def __init__(self, repository: ConversationRepository = None):
        self.repository = repository or ConversationRepository()
        from argus.authorization.scope import ScopeResolver
        self.scope_resolver = ScopeResolver()
        
    def resolve(self, query: ContextQuery) -> List[ContextSource]:
        """Resolves graph context for the given query."""
        if not query.mission_id:
            return []
            
        try:
            mission = mission_manager.get_mission(query.mission_id)
        except Exception as e:
            logger.error(f"Failed to load mission {query.mission_id}: {e}")
            return []
            
        graph: KnowledgeGraph = getattr(mission, "graph", None)
        if not graph:
            return []
            
        # 1. Identify Target Entities
        target_nodes = self._identify_target_entities(query, graph)
        if not target_nodes:
            # If no specific entities found in query, we might return the investigation's subgraph
            # Or just return empty to not overwhelm.
            return []
            
        # 2. Extract Subgraph (Bounded Traversal)
        sources = []
        visited = set()
        for node in target_nodes:
            if node.id in visited: continue
            visited.add(node.id)
            
            # Find neighbors (depth 1)
            edges_from = graph.edges_from(node)
            edges_to = graph.edges_to(node)
            
            scope_decision = self.scope_resolver.check_scope(node.value, query.mission_id)
            scope_status = scope_decision.decision.value
            
            # Format as a cohesive ContextSource
            content_parts = [f"ENTITY: {node.type}: {node.value} [SCOPE: {scope_status}]"]
            if edges_from or edges_to:
                content_parts.append("RELATIONSHIPS:")
                for e in edges_from:
                    target = graph.get(e.target)
                    if target:
                        status = e.metadata.get('status', 'OBSERVED')
                        target_scope = self.scope_resolver.check_scope(target.value, query.mission_id).decision.value
                        content_parts.append(f"-> {e.type} -> {target.type}: {target.value} [{status}] [SCOPE: {target_scope}]")
                for e in edges_to:
                    source = graph.get(e.source)
                    if source:
                        status = e.metadata.get('status', 'OBSERVED')
                        source_scope = self.scope_resolver.check_scope(source.value, query.mission_id).decision.value
                        content_parts.append(f"<- {e.type} <- {source.type}: {source.value} [{status}] [SCOPE: {source_scope}]")
                        
            sources.append(
                ContextSource(
                    source_id=f"graph_{node.id}",
                    source_type="graph_node",
                    title=f"Graph Entity: {node.value}",
                    content="\n".join(content_parts),
                    semantic_status="KNOWLEDGE_GRAPH",
                    mission_id=mission.id
                )
            )
            
        return sources

    def _identify_target_entities(self, query: ContextQuery, graph: KnowledgeGraph) -> List[Node]:
        """Identifies which nodes the user is asking about."""
        q_text = query.query.lower()
        matched = []
        
        # Exact value matching
        for node in graph.all():
            if node.value.lower() in q_text and len(node.value) > 3:
                matched.append(node)
                
        # Conversational referencing: "this endpoint", "this screenshot"
        if "this endpoint" in q_text or "that endpoint" in q_text:
            # Try to resolve from recent messages
            conv = self.repository.get(query.conversation_id)
            if conv:
                recent_endpoints = self._extract_recent_entities(conv, graph, "Endpoint")
                matched.extend(recent_endpoints)
                
        if "this evidence" in q_text or "screenshot" in q_text:
            conv = self.repository.get(query.conversation_id)
            if conv:
                recent_evidence = self._extract_recent_entities(conv, graph, "Evidence")
                matched.extend(recent_evidence)
                
        # Disambiguate or limit
        # For naive implementation, return top 3 matches to avoid context bloat
        return list({n.id: n for n in matched}.values())[:3]

    def _extract_recent_entities(self, conv, graph: KnowledgeGraph, entity_type: str) -> List[Node]:
        """Finds recent entities of a specific type mentioned in the conversation."""
        recent_text = " ".join([m.text for m in conv.messages[-5:]]).lower()
        matched = []
        for node in graph.nodes_by_type(entity_type):
            if node.value.lower() in recent_text:
                matched.append(node)
        return matched
