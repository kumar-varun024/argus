from typing import List, Optional
from argus.workspace.context.models import ContextQuery, ContextSource

class ContextRanker:
    """
    Blended Context Ranker combining vector similarity, lexical overlap,
    scope relevance, and semantic type priority.
    
    Hybrid Score Formula:
        S_hybrid = w_vec * S_vec + w_lex * S_lex + S_scope + S_type
        where w_vec = 0.6, w_lex = 0.4
    
    Backward Compatibility:
        When vector_score is absent or 0.0, w_lex defaults to 1.0 and w_vec to 0.0,
        ensuring 100% parity with legacy lexical-only ranking.
    """
    
    def __init__(
        self,
        w_vec: float = 0.6,
        w_lex: float = 0.4,
        max_context_sources: int = 15,
    ):
        self.w_vec = float(w_vec)
        self.w_lex = float(w_lex)
        self.max_context_sources = int(max_context_sources)
    
    def rank(self, query: ContextQuery, sources: List[ContextSource]) -> List[ContextSource]:
        """Assigns hybrid relevance scores and sorts the sources."""
        q_text = query.query.lower()
        q_terms = set(q_text.split())
        
        for source in sources:
            # 1. Scope Score (S_scope)
            s_scope = 0.0
            if query.mission_id and source.mission_id == query.mission_id:
                s_scope += 5.0
            if query.investigation_id and source.investigation_id == query.investigation_id:
                s_scope += 10.0
                
            # 2. Lexical Score (S_lex)
            s_text = f"{source.title} {source.content}".lower()
            overlap = sum(1 for term in q_terms if len(term) > 3 and term in s_text)
            s_lex = overlap * 2.0
            
            # 3. Type Priority (S_type)
            s_type = 0.0
            if source.semantic_status in [
                "EVIDENCE",
                "FINDING",
                "VECTOR_FINDING",
                "VECTOR_EVIDENCE",
                "CVE_KNOWLEDGE",
                "HISTORICAL_MEMORY",
            ]:
                s_type += 3.0

            # 4. Vector Score (S_vec) & Weight Resolution
            vec_score = source.vector_score
            if vec_score is None and "vector_score" in source.metadata:
                try:
                    vec_score = float(source.metadata["vector_score"])
                except (ValueError, TypeError):
                    vec_score = None

            if vec_score is not None and vec_score > 0.0:
                effective_w_vec = self.w_vec
                effective_w_lex = self.w_lex
                # Normalize cosine similarity to [0, 10.0] scale
                if vec_score <= 1.0:
                    s_vec = min(10.0, max(0.0, vec_score * 10.0))
                else:
                    s_vec = min(10.0, max(0.0, vec_score))
            else:
                # Backward-compatible pure lexical fallback
                effective_w_vec = 0.0
                effective_w_lex = 1.0
                s_vec = 0.0

            # 5. Hybrid Score Calculation
            score = (effective_w_vec * s_vec) + (effective_w_lex * s_lex) + s_scope + s_type

            # Record breakdown in metadata
            source.metadata["hybrid_score"] = round(score, 4)
            source.metadata["vector_score_component"] = round(effective_w_vec * s_vec, 4)
            source.metadata["lexical_score_component"] = round(effective_w_lex * s_lex, 4)
            source.metadata["scope_score_component"] = round(s_scope, 4)
            source.metadata["type_score_component"] = round(s_type, 4)

            # Classify
            if score >= 15.0:
                source.relevance_score = "Critical"
                source.relevance_reason = "Directly related to active investigation and query terms."
            elif score >= 10.0:
                source.relevance_score = "High"
                source.relevance_reason = "Strong relationship to mission and query."
            elif score >= 5.0:
                source.relevance_score = "Medium"
                source.relevance_reason = "Contains some matching context."
            else:
                source.relevance_score = "Low"
                source.relevance_reason = "Weak or general relationship."
                
        # Filter out 'Low' and sort by priority tier, then by numeric hybrid score
        priority = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        
        filtered = [s for s in sources if priority.get(s.relevance_score, 0) > 1]
        filtered.sort(
            key=lambda s: (priority.get(s.relevance_score, 0), s.metadata.get("hybrid_score", 0.0)),
            reverse=True
        )
        
        # Enforce maximum context size to prevent prompt overflow
        return filtered[:self.max_context_sources]
