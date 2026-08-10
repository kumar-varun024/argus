from typing import List
from argus.workspace.context.models import ContextQuery, ContextSource, ContextResult
from argus.workspace.context.ranker import ContextRanker
from argus.workspace.context.policy import ContextPolicy
from argus.workspace.context.assembler import ContextAssembler
from argus.workspace.context.mission import MissionContextResolver
from argus.workspace.context.graph import KnowledgeGraphRetriever
from argus.evidence.manager import EvidenceManager

class ResearchContextEngine:
    """The central orchestrator for gathering research context."""
    
    def __init__(self):
        self.ranker = ContextRanker()
        self.policy = ContextPolicy()
        self.assembler = ContextAssembler()
        self.evidence_manager = EvidenceManager()
        self.mission_resolver = MissionContextResolver()
        self.graph_retriever = KnowledgeGraphRetriever()
        
    def _retrieve_sources(self, query: ContextQuery) -> List[ContextSource]:
        """
        Retrieves actual evidence from the EvidenceManager for the active investigation.
        """
        sources = []
        
        if query.investigation_id:
            evidence_list = self.evidence_manager.get_by_investigation(query.investigation_id)
            for ev in evidence_list:
                # Map Evidence to ContextSource
                source = ContextSource(
                    source_id=ev.evidence_id,
                    source_type=ev.source_type.lower(),
                    title=ev.title,
                    content=ev.description,
                    semantic_status="EVIDENCE" if ev.status in ["USER_REVIEWED", "CONFIRMED", "CORROBORATED"] else "OBSERVATION",
                    mission_id=ev.mission_id,
                    investigation_id=ev.investigation_id,
                    project_id=ev.project_id,
                    timestamp=ev.created_at
                )
                sources.append(source)
                
        # 2. Append Mission Context
        mission_sources = self.mission_resolver.resolve(query)
        sources.extend(mission_sources)
        
        # 3. Append Graph Context
        graph_sources = self.graph_retriever.resolve(query)
        sources.extend(graph_sources)
        
        # If we need mock sources for testing missing endpoints, we can optionally append them here
        # For now, we rely solely on the actual EvidenceManager.
        return sources

    def resolve_context(self, query: ContextQuery) -> str:
        """Retrieves, ranks, filters, and assembles context into a prompt string."""
        from argus.authorization.gate import authorization_gate
        
        # 0. Check Authorization
        user_id = query.user_id or "system_user"
        mission_id = query.mission_id
        project_id = query.project_id
        
        if mission_id:
            perm = authorization_gate.can_access_mission(user_id, mission_id)
            if not perm.allowed:
                return f"AUTHORIZATION DENIED: {perm.reason}"
                
        user_permission_state = "AUTHORIZED_FOR_MISSION"
        
        # 1. Retrieve raw sources
        raw_sources = self._retrieve_sources(query)
        
        # 1.5 Enforce Isolation
        isolated_sources = []
        for src in raw_sources:
            if src.mission_id and mission_id and src.mission_id != mission_id:
                continue
            if src.project_id and project_id and src.project_id != project_id:
                continue
            isolated_sources.append(src)
        
        # 2. Filter (Policy & Scope)
        allowed_sources = self.policy.apply(query, isolated_sources)
        
        # 3. Rank
        ranked_sources = self.ranker.rank(query, allowed_sources)
        
        # 4. Check for contradictions or insufficient data
        status = "OK"
        if not ranked_sources:
            status = "INSUFFICIENT_CONTEXT"
            
        result = ContextResult(
            sources=ranked_sources, 
            context_status=status,
            user_permission_state=user_permission_state,
            authorization_scope="RESTRICTED_TO_MISSION_SCOPE"
        )
        
        # 5. Assemble
        return self.assembler.assemble(result)
