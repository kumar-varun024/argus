import logging
import uuid
from typing import List, Tuple, Callable

from argus.correlation.evidence import EvidenceBundle
from argus.correlation.registry import ObservationRegistry, CorrelationRegistry
from argus.correlation.strength import EvidenceStrengthScorer
from argus.correlation.confidence import ConfidenceCalculator
from argus.correlation.deduplication import EvidenceDeduplicator

logger = logging.getLogger(__name__)

# Fusion Rules
def fuse_shared_business_objects(item1, item2) -> bool:
    return bool(set(item1.business_objects) & set(item2.business_objects))

def fuse_shared_workflows(item1, item2) -> bool:
    return bool(set(item1.workflows) & set(item2.workflows))

def fuse_shared_technologies(item1, item2) -> bool:
    return bool(set(getattr(item1, 'technologies', getattr(item1, 'technology', []))) & 
                set(getattr(item2, 'technologies', getattr(item2, 'technology', []))))

def fuse_shared_endpoints(item1, item2) -> bool:
    e1 = getattr(item1, 'endpoints', [])
    e2 = getattr(item2, 'endpoints', [])
    return bool(set(e1) & set(e2))

def fuse_shared_graphql_types(item1, item2) -> bool:
    g1 = getattr(item1, 'graphql_types', [])
    g2 = getattr(item2, 'graphql_types', [])
    return bool(set(g1) & set(g2))

def fuse_shared_authentication_context(item1, item2) -> bool:
    return bool(set(item1.authentication_context) & set(item2.authentication_context))

def fuse_shared_authorization_context(item1, item2) -> bool:
    return bool(set(item1.authorization_context) & set(item2.authorization_context))

def fuse_shared_api_resource(item1, item2) -> bool:
    a1 = getattr(item1, 'api_operations', [])
    a2 = getattr(item2, 'api_operations', [])
    return bool(set(a1) & set(a2))

def fuse_shared_client_route(item1, item2) -> bool:
    u1 = getattr(item1, 'urls', [])
    u2 = getattr(item2, 'urls', [])
    return bool(set(u1) & set(u2))

DEFAULT_FUSION_RULES = [
    ("fuse_shared_business_objects", fuse_shared_business_objects),
    ("fuse_shared_workflows", fuse_shared_workflows),
    ("fuse_shared_technologies", fuse_shared_technologies),
    ("fuse_shared_endpoints", fuse_shared_endpoints),
    ("fuse_shared_graphql_types", fuse_shared_graphql_types),
    ("fuse_shared_authentication_context", fuse_shared_authentication_context),
    ("fuse_shared_authorization_context", fuse_shared_authorization_context),
    ("fuse_shared_api_resource", fuse_shared_api_resource),
    ("fuse_shared_client_route", fuse_shared_client_route)
]

class EvidenceFusionEngine:
    """
    Combines observations and correlations into unified EvidenceBundles.
    Does NOT generate investigations or security conclusions.
    """
    
    def __init__(self, obs_registry: ObservationRegistry, corr_registry: CorrelationRegistry, bundle_registry, rules=None):
        self.obs_registry = obs_registry
        self.corr_registry = corr_registry
        self.bundle_registry = bundle_registry
        self.rules = rules or DEFAULT_FUSION_RULES
        self.scorer = EvidenceStrengthScorer(self.obs_registry, self.corr_registry)
        self.confidence_calc = ConfidenceCalculator()
        self.deduplicator = EvidenceDeduplicator()

    def process_mission_state(self) -> None:
        """Processes all observations and correlations to form bundles."""
        items = list(self.obs_registry.get_all()) + list(self.corr_registry.get_all())
        
        for item in items:
            self._fuse_item(item)

    def _fuse_item(self, item) -> None:
        """Find matching bundles or create a new one."""
        matched_bundles = []
        for bundle in self.bundle_registry.get_all():
            for rule_name, rule_func in self.rules:
                try:
                    if rule_func(bundle, item):
                        matched_bundles.append(bundle)
                        break # Only need one match to fuse
                except Exception:
                    pass

        if not matched_bundles:
            new_bundle = self._create_bundle(item)
            logger.info(f"Bundle created: {new_bundle.id}")
        else:
            if len(matched_bundles) > 1:
                target_bundle = self._merge_bundles(matched_bundles)
                logger.info(f"Evidence merged into {target_bundle.id}")
            else:
                target_bundle = matched_bundles[0]
                
            self._update_bundle(target_bundle, item)
            logger.info(f"Bundle updated: {target_bundle.id}")
            
    def _create_bundle(self, item) -> EvidenceBundle:
        bundle = EvidenceBundle(title="Fused Evidence", description="Automatically aggregated evidence bundle")
        self._add_item_to_bundle(bundle, item)
        self._sync_metadata(bundle)
        self.bundle_registry.add(bundle)
        return bundle

    def _update_bundle(self, bundle: EvidenceBundle, item) -> None:
        self._add_item_to_bundle(bundle, item)
        self._sync_metadata(bundle)

    def _add_item_to_bundle(self, bundle: EvidenceBundle, item) -> None:
        from argus.correlation.observation import Observation
        if isinstance(item, Observation):
            if item.id not in bundle.observations:
                bundle.observations.append(item.id)
        else: # Correlation
            if item.id not in bundle.correlations:
                bundle.correlations.append(item.id)
                
    def _merge_bundles(self, bundles: List[EvidenceBundle]) -> EvidenceBundle:
        primary = bundles[0]
        for other in bundles[1:]:
            for oid in other.observations:
                if oid not in primary.observations:
                    primary.observations.append(oid)
            for cid in other.correlations:
                if cid not in primary.correlations:
                    primary.correlations.append(cid)
            self.bundle_registry.remove(other.id)
            
        self._sync_metadata(primary)
        return primary

    def _sync_metadata(self, bundle: EvidenceBundle) -> None:
        """Aggregates contexts from observations and correlations."""
        bo_set = set()
        wf_set = set()
        tech_set = set()
        gn_set = set()
        ge_set = set()
        authn_set = set()
        authz_set = set()
        ep_set = set()
        gq_set = set()
        api_set = set()
        url_set = set()
        evidence_list = []
        
        # Helper to extract from items
        def extract(item):
            bo_set.update(getattr(item, 'business_objects', []))
            wf_set.update(getattr(item, 'workflows', []))
            tech_set.update(getattr(item, 'technologies', getattr(item, 'technology', [])))
            gn_set.update(getattr(item, 'graph_nodes', []))
            ge_set.update(getattr(item, 'graph_edges', []))
            authn_set.update(getattr(item, 'authentication_context', []))
            authz_set.update(getattr(item, 'authorization_context', []))
            ep_set.update(getattr(item, 'endpoints', []))
            gq_set.update(getattr(item, 'graphql_types', []))
            api_set.update(getattr(item, 'api_operations', []))
            url_set.update(getattr(item, 'urls', []))
            evidence_list.extend(getattr(item, 'evidence', []))

        for oid in bundle.observations:
            obs = self.obs_registry.find(oid)
            if obs: extract(obs)
            
        for cid in bundle.correlations:
            corr = self.corr_registry.find(cid)
            if corr: extract(corr)
            
        bundle.business_objects = list(bo_set)
        bundle.workflows = list(wf_set)
        bundle.technologies = list(tech_set)
        bundle.graph_nodes = list(gn_set)
        bundle.graph_edges = list(ge_set)
        bundle.authentication_context = list(authn_set)
        bundle.authorization_context = list(authz_set)
        
        # Store extras in metadata or specific fields if they exist
        bundle.metadata['endpoints'] = list(ep_set)
        bundle.metadata['graphql_types'] = list(gq_set)
        bundle.metadata['api_operations'] = list(api_set)
        bundle.metadata['urls'] = list(url_set)
        
        # Deduplicate evidence
        bundle.evidence = self.deduplicator.deduplicate(evidence_list)
        
        # Calculate strength and confidence
        old_strength = bundle.strength
        bundle.strength = self.scorer.calculate_strength(bundle)
        if old_strength != bundle.strength:
            logger.info(f"Strength recalculated for {bundle.id}: {bundle.strength}")
            
        old_conf = bundle.confidence
        bundle.confidence = self.confidence_calc.calculate_confidence(bundle)
        if old_conf != bundle.confidence:
            logger.info(f"Confidence recalculated for {bundle.id}: {bundle.confidence}")
