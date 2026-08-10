from typing import List
from argus.workspace.context.models import ContextQuery, ContextSource, ContextResult
from argus.workspace.context.ranker import ContextRanker
from argus.workspace.context.policy import ContextPolicy
from argus.workspace.context.assembler import ContextAssembler
from argus.evidence.manager import EvidenceManager

class ResearchContextEngine:
    """The central orchestrator for gathering research context."""
    
    def __init__(self):
        self.ranker = ContextRanker()
        self.policy = ContextPolicy()
        self.assembler = ContextAssembler()
        self.evidence_manager = EvidenceManager()
        
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
                
        # If we need mock sources for testing missing endpoints, we can optionally append them here
        # For now, we rely solely on the actual EvidenceManager.
        return sources

    def resolve_context(self, query: ContextQuery) -> str:
        """Retrieves, ranks, filters, and assembles context into a prompt string."""
        
        # 1. Retrieve raw sources
        raw_sources = self._retrieve_sources(query)
        
        # 2. Filter (Policy & Scope)
        allowed_sources = self.policy.apply(query, raw_sources)
        
        # 3. Rank
        ranked_sources = self.ranker.rank(query, allowed_sources)
        
        # 4. Check for contradictions or insufficient data
        status = "OK"
        if not ranked_sources:
            status = "INSUFFICIENT_CONTEXT"
            
        result = ContextResult(sources=ranked_sources, context_status=status)
        
        # 5. Assemble
        return self.assembler.assemble(result)
