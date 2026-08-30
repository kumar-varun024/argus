import logging
from typing import Any, List, Optional
from argus.correlation.registry import EvidenceBundleRegistry, CorrelationRegistry, ObservationRegistry
from argus.investigation.registry import InvestigationRegistry
from argus.investigation.generator import InvestigationGenerator
from argus.investigation.confidence import InvestigationConfidenceScorer
from argus.investigation.priority_engine import PriorityEngine
from argus.investigation.weights import WeightConfig
from argus.investigation.manual_validation import ManualValidationGenerator
from argus.investigation.explanation import ReasoningTreeBuilder
from argus.investigation.models import Investigation
from argus.graph.graph import KnowledgeGraph

logger = logging.getLogger(__name__)

class InvestigationBuilder:
    """Orchestrator to pull bundles from Mission and queue up new investigations."""
    
    def __init__(self, inv_registry: InvestigationRegistry, bundle_registry: EvidenceBundleRegistry,
                 corr_registry: CorrelationRegistry, obs_registry: ObservationRegistry,
                 weight_config: WeightConfig = None):
        self.inv_registry = inv_registry
        self.bundle_registry = bundle_registry
        
        # Initialize components
        self.conf_scorer = InvestigationConfidenceScorer(bundle_registry)
        self.prio_engine = PriorityEngine(bundle_registry, weight_config)
        self.val_gen = ManualValidationGenerator()
        self.reasoning_builder = ReasoningTreeBuilder(bundle_registry, corr_registry, obs_registry)
        
        self.generator = InvestigationGenerator(
            self.inv_registry, self.conf_scorer, self.prio_engine, 
            self.val_gen, self.reasoning_builder
        )

    def build_all(self, mission: Any = None, graph: Optional[KnowledgeGraph] = None) -> None:
        """Processes all Evidence Bundles to form Investigations."""
        kg = graph or (getattr(mission, 'attack_surface_graph', None) if mission else None)
        for bundle in self.bundle_registry.get_all():
            self.generator.process_bundle(bundle, mission=mission, graph=kg)
            
    def prioritize_all(self, mission: Any = None, graph: Optional[KnowledgeGraph] = None) -> List[Investigation]:
        """Evaluates and ranks all investigations, updating mission storage if mission is provided."""
        kg = graph or (getattr(mission, 'attack_surface_graph', None) if mission else None)
        invs = self.inv_registry.get_all()
        ranked = self.prio_engine.evaluate_all(invs, mission=mission, graph=kg)
        return ranked

    def update_reasoning_tree(self, reasoning_tree: dict) -> None:
        """Updates the mission reasoning tree dictionary."""
        for inv in self.inv_registry.get_all():
            tree = self.reasoning_builder.build_tree(inv)
            reasoning_tree[str(inv.id)] = tree
            logger.info("Reasoning tree built")
