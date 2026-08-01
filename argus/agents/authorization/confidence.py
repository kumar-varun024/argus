from argus.agents.authorization.models import AuthzContext, AuthzHeuristicResult

class AuthzConfidenceScorer:
    """Scores authorization hypotheses based on evidence quality and graph completeness."""
    
    def score(self, result: AuthzHeuristicResult, context: AuthzContext) -> float:
        # Base score from heuristic context
        score = 50.0
        
        # Evidence quality modifier
        evidence_len = len(result.investigation.supporting_evidence)
        if evidence_len > 2:
            score *= 1.3
        elif evidence_len > 0:
            score *= 1.1
            
        # Graph completeness modifier
        if context.graph and len(context.graph.nodes) > 10:
            score *= 1.2
            
        # Workflow certainty modifier
        if any(result.investigation.workflow == wf.get("name") for wf in context.workflows):
            score *= 1.15
            
        # Heuristic reliability modifier (e.g. some heuristics are more reliable)
        if result.heuristic_id in ["cross_tenant_object", "owner_admin_workflow"]:
            score *= 1.1
            
        # Ensure we cap at 100 and don't go below 0
        return min(max(score, 0.0), 100.0)
