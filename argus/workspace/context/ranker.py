from typing import List
from argus.workspace.context.models import ContextQuery, ContextSource

class ContextRanker:
    """Ranks retrieved research context based on relevance to the query."""
    
    def rank(self, query: ContextQuery, sources: List[ContextSource]) -> List[ContextSource]:
        """Assigns relevance scores and sorts the sources."""
        q_text = query.query.lower()
        q_terms = set(q_text.split())
        
        for source in sources:
            score = 0
            
            # Explicit relationship to active scope
            if query.mission_id and source.mission_id == query.mission_id:
                score += 5
            if query.investigation_id and source.investigation_id == query.investigation_id:
                score += 10
                
            # Term overlap (naive but effective baseline)
            s_text = f"{source.title} {source.content}".lower()
            overlap = sum(1 for term in q_terms if len(term) > 3 and term in s_text)
            score += overlap * 2
            
            # Recency / Semantic type priority
            if source.semantic_status in ["EVIDENCE", "FINDING"]:
                score += 3
                
            # Classify
            if score >= 15:
                source.relevance_score = "Critical"
                source.relevance_reason = "Directly related to active investigation and query terms."
            elif score >= 10:
                source.relevance_score = "High"
                source.relevance_reason = "Strong relationship to mission and query."
            elif score >= 5:
                source.relevance_score = "Medium"
                source.relevance_reason = "Contains some matching context."
            else:
                source.relevance_score = "Low"
                source.relevance_reason = "Weak or general relationship."
                
        # Filter out 'Low' and sort by score descending
        # Since we assigned categorical scores, let's just sort by a custom key
        priority = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        
        filtered = [s for s in sources if priority.get(s.relevance_score, 0) > 1]
        filtered.sort(key=lambda s: priority.get(s.relevance_score, 0), reverse=True)
        
        # Enforce maximum context size to prevent prompt overflow
        return filtered[:15]
