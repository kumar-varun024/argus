from argus.agents.business_logic.models import BusinessLogicContext, BusinessHeuristicResult

class BusinessLogicConfidenceScorer:
    """Scores business logic hypotheses based on context completeness."""
    
    def score(self, result: BusinessHeuristicResult, context: BusinessLogicContext) -> float:
        score = 50.0
        
        # Evidence quality modifier
        evidence_len = len(result.investigation.supporting_evidence)
        if evidence_len > 2:
            score *= 1.3
        elif evidence_len > 0:
            score *= 1.1
            
        # Workflow completeness modifier
        if context.workflows and len(context.workflows) > 0:
            score *= 1.1
            
        # State machine confidence
        if context.state_machines and len(context.state_machines) > 0:
            score *= 1.15
            
        # Heuristic reliability modifier
        if result.heuristic_id in ["missing_prerequisite", "replayable_transaction"]:
            score *= 1.1
            
        return min(max(score, 0.0), 100.0)
