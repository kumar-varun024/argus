from typing import List
from argus.workspace.context.models import ContextQuery, ContextSource

class ContextPolicy:
    """Enforces authorization, scope isolation, and privacy policies on context."""
    
    def apply(self, query: ContextQuery, sources: List[ContextSource]) -> List[ContextSource]:
        """Filters context to ensure it strictly belongs to the current scope."""
        allowed = []
        for source in sources:
            # Enforce Project Isolation
            if query.project_id and source.project_id and source.project_id != query.project_id:
                continue
                
            # Enforce Mission Isolation (if query explicitly scopes to a mission)
            if query.mission_id and source.mission_id and source.mission_id != query.mission_id:
                continue
                
            # TODO: Future logic for secrets reduction, PII scrubbing, explicit RBAC.
            
            allowed.append(source)
            
        return allowed
