from argus.explain.models import Explanation
from argus.explain.reasoning import ReasoningChainBuilder
from argus.explain.timeline import TimelineBuilder
from argus.explain.graph import ExplanationGraphBuilder
from argus.investigation.models import Investigation
from argus.runtime.mission import Mission
import uuid

class ExplainabilityEngine:
    """Orchestrates generation of Explanations for Investigations."""
    
    def __init__(self, mission: Mission):
        self.mission = mission
        self.reasoning_builder = ReasoningChainBuilder(mission)
        self.timeline_builder = TimelineBuilder(mission)
        self.graph_builder = ExplanationGraphBuilder(mission)

    def generate_explanation(self, investigation: Investigation) -> Explanation:
        """Generates a complete Explanation object for an Investigation."""
        
        # Build deterministic components
        chain = self.reasoning_builder.build_chain(investigation)
        timeline = self.timeline_builder.build_timeline(investigation)
        graph = self.graph_builder.build_graph(investigation)
        
        # Parse priority breakdown from explanation strings or just map them
        priority_breakdown = {"Total Score": float(investigation.priority_score)}
        for exp in investigation.priority_explanation:
            priority_breakdown[exp] = 1.0 # Indicator of presence
            
        confidence_breakdown = {"Base Confidence": float(investigation.confidence)}
        
        explanation = Explanation(
            investigation_id=investigation.id,
            title=investigation.title,
            summary=investigation.summary,
            reasoning_chain=chain,
            timeline=timeline,
            explanation_graph=graph,
            priority_breakdown=priority_breakdown,
            confidence_breakdown=confidence_breakdown,
            observations=investigation.observations,
            correlations=investigation.correlations,
            evidence_bundles=investigation.evidence_bundles,
            knowledge_graph_nodes=investigation.related_graph_nodes,
            workflow_nodes=investigation.workflows,
            manual_validation=investigation.manual_validation,
            metadata=investigation.metadata
        )
        
        # Store in mission
        inv_id_str = str(investigation.id)
        if not hasattr(self.mission, 'explanations'):
            self.mission.explanations = {}
        if not hasattr(self.mission, 'reasoning_chains'):
            self.mission.reasoning_chains = {}
        if not hasattr(self.mission, 'explanation_graph'):
            self.mission.explanation_graph = {}
            
        self.mission.explanations[inv_id_str] = explanation
        self.mission.reasoning_chains[inv_id_str] = [step.model_dump() for step in chain]
        self.mission.explanation_graph[inv_id_str] = graph.model_dump()
        
        return explanation
