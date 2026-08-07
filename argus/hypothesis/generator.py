import logging
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from argus.runtime.mission import Mission

from argus.investigation.models import Investigation
from argus.hypothesis.models import Hypothesis, HypothesisCategory, HypothesisStatus
from argus.hypothesis.registry import HypothesisRegistry
from argus.hypothesis.confidence import HypothesisConfidenceScorer
from argus.hypothesis.ranking import HypothesisRanker
from argus.hypothesis.templates import HypothesisTemplateBuilder

logger = logging.getLogger(__name__)

class HypothesisGenerator:
    """Generates Hypotheses from Investigations based on evidence thresholds."""
    
    def __init__(self, registry: HypothesisRegistry, conf_scorer: HypothesisConfidenceScorer, ranker: HypothesisRanker):
        self.registry = registry
        self.conf_scorer = conf_scorer
        self.ranker = ranker
        self.template_builder = HypothesisTemplateBuilder()

    def process_investigation(self, investigation: Investigation, mission: 'Mission' = None) -> Optional[Hypothesis]:
        """
        Evaluates an investigation and creates or refines a hypothesis if evidence is sufficient.
        """
        # Threshold: Do not create hypotheses from very low confidence investigations unless they have multiple evidence bundles.
        if investigation.confidence < 0.4 and len(investigation.evidence_bundles) < 2:
            logger.info(f"Investigation {investigation.id} lacks sufficient evidence to form a hypothesis.")
            return None

        # Map InvestigationCategory to HypothesisCategory
        try:
            category = HypothesisCategory(investigation.category.value)
        except ValueError:
            category = HypothesisCategory.GENERAL_RESEARCH

        # Check for existing hypotheses that can be refined
        existing = self._find_overlapping(investigation, category)
        if existing:
            self._refine(existing, investigation, mission)
            return existing

        # Create new hypothesis
        hyp = Hypothesis(
            title=f"Hypothesis: {investigation.title}",
            summary=f"Investigate potential issues in {category.value}.",
            description=investigation.description,
            category=category,
            status=HypothesisStatus.DRAFT
        )
        
        self._refine(hyp, investigation, mission)
        self.registry.add(hyp)
        logger.info(f"Hypothesis {hyp.id} generated from investigation {investigation.id}.")
        return hyp

    def _find_overlapping(self, inv: Investigation, category: HypothesisCategory) -> Optional[Hypothesis]:
        """Finds if an existing hypothesis covers similar grounds."""
        for hyp in self.registry.filter_by_category(category.value):
            shared_bo = set(hyp.business_objects) & set(inv.business_objects)
            shared_wf = set(hyp.workflows) & set(inv.workflows)
            if shared_bo or shared_wf:
                return hyp
        return None

    def _refine(self, hyp: Hypothesis, inv: Investigation, mission: 'Mission') -> None:
        """Merges investigation data into the hypothesis."""
        if inv.id not in hyp.related_investigations:
            hyp.related_investigations.append(inv.id)
            
        hyp.business_objects = list(set(hyp.business_objects + inv.business_objects))
        hyp.workflows = list(set(hyp.workflows + inv.workflows))
        hyp.related_endpoints = list(set(hyp.related_endpoints + inv.related_endpoints))
        hyp.supporting_graph_nodes = list(set(hyp.supporting_graph_nodes + inv.related_graph_nodes))
        hyp.supporting_graph_edges = list(set(hyp.supporting_graph_edges + inv.related_graph_edges))
        
        for eid in inv.evidence_bundles:
            if eid not in hyp.related_evidence:
                hyp.related_evidence.append(eid)
                
        for oid in inv.observations:
            if oid not in hyp.related_observations:
                hyp.related_observations.append(oid)
                
        for cid in inv.correlations:
            if cid not in hyp.related_correlations:
                hyp.related_correlations.append(cid)
                
        # Generate text
        hyp.reason = self.template_builder.generate_reasoning(hyp)
        hyp.manual_validation = self.template_builder.generate_manual_validation(hyp)
        
        # Update metrics
        hyp.confidence = self.conf_scorer.calculate_confidence(hyp, mission)
        self.ranker.evaluate_priority(hyp, mission)
