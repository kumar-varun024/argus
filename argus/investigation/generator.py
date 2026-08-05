import logging
from typing import List, Dict, Any, Optional

from argus.correlation.evidence import EvidenceBundle
from argus.investigation.models import Investigation, InvestigationCategory
from argus.investigation.registry import InvestigationRegistry
from argus.investigation.confidence import InvestigationConfidenceScorer
from argus.investigation.priority_engine import PriorityEngine
from argus.investigation.manual_validation import ManualValidationGenerator
from argus.investigation.explanation import ReasoningTreeBuilder

logger = logging.getLogger(__name__)

class InvestigationGenerator:
    """Converts Evidence Bundles into Investigations without asserting vulnerabilities."""
    
    def __init__(self, inv_registry: InvestigationRegistry, conf_scorer: InvestigationConfidenceScorer,
                 prio_engine: PriorityEngine, val_gen: ManualValidationGenerator,
                 reasoning_builder: ReasoningTreeBuilder):
        self.inv_registry = inv_registry
        self.conf_scorer = conf_scorer
        self.prio_engine = prio_engine
        self.val_gen = val_gen
        self.reasoning_builder = reasoning_builder

    def process_bundle(self, bundle: EvidenceBundle) -> Optional[Investigation]:
        """
        Creates or updates an Investigation based on an EvidenceBundle.
        Deduplicates if an existing investigation covers the same context.
        """
        if bundle.strength < 20 and bundle.confidence < 0.2:
            # Skip very weak evidence
            return None
            
        # Determine Category
        category = self._determine_category(bundle)
        
        # Deduplication Check
        existing_inv = self._find_duplicate(bundle, category)
        if existing_inv:
            self._merge(existing_inv, bundle)
            logger.info(f"Investigation merged: {existing_inv.id}")
            return existing_inv
            
        # Create New
        inv = Investigation(
            title=f"Review {category.value} Configuration",
            summary=f"Investigation into {category.value} based on fused evidence.",
            description=bundle.description,
            category=category
        )
        self._merge(inv, bundle)
        self.inv_registry.add(inv)
        logger.info(f"Investigation generated: {inv.id}")
        return inv
        
    def _determine_category(self, bundle: EvidenceBundle) -> InvestigationCategory:
        """Heuristic to map evidence to an InvestigationCategory."""
        # Simple heuristic based on context presence
        if bundle.authorization_context or "Role" in bundle.business_objects:
            return InvestigationCategory.AUTHORIZATION
        if bundle.authentication_context:
            return InvestigationCategory.AUTHENTICATION
        if bundle.workflows and not bundle.authorization_context:
            return InvestigationCategory.BUSINESS_LOGIC
        if bundle.metadata.get('graphql_types'):
            return InvestigationCategory.GRAPHQL
        if bundle.metadata.get('endpoints') or bundle.metadata.get('api_operations'):
            return InvestigationCategory.API
        
        return InvestigationCategory.TECHNOLOGY

    def _find_duplicate(self, bundle: EvidenceBundle, category: InvestigationCategory) -> Optional[Investigation]:
        """Finds if an existing investigation covers similar grounds."""
        for inv in self.inv_registry.get_all():
            if inv.category == category:
                # If they share primary business objects or workflows, merge them
                shared_bo = set(inv.business_objects) & set(bundle.business_objects)
                shared_wf = set(inv.workflows) & set(bundle.workflows)
                if shared_bo or shared_wf:
                    return inv
        return None

    def _merge(self, inv: Investigation, bundle: EvidenceBundle) -> None:
        """Merges bundle data into the investigation and updates metrics."""
        if bundle.id not in inv.evidence_bundles:
            inv.evidence_bundles.append(bundle.id)
            
        # Sync context
        inv.business_objects = list(set(inv.business_objects + bundle.business_objects))
        inv.workflows = list(set(inv.workflows + bundle.workflows))
        inv.related_endpoints = list(set(inv.related_endpoints + bundle.metadata.get('endpoints', [])))
        inv.related_graph_nodes = list(set(inv.related_graph_nodes + bundle.graph_nodes))
        inv.related_graph_edges = list(set(inv.related_graph_edges + bundle.graph_edges))
        
        for oid in bundle.observations:
            if oid not in inv.observations: inv.observations.append(oid)
        for cid in bundle.correlations:
            if cid not in inv.correlations: inv.correlations.append(cid)
            
        # Update metrics
        inv.priority = self.prio_engine.evaluate(inv)
        logger.info("Priority assigned")
        
        inv.confidence = self.conf_scorer.calculate_confidence(inv)
        logger.info("Confidence updated")
        
        # Generate Text
        inv.reasoning = self.reasoning_builder.generate_reasoning_text(inv)
        inv.manual_validation = self.val_gen.generate_guidance(inv)
