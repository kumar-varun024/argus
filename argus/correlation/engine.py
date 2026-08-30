import uuid
import logging
from typing import List, Optional

from argus.correlation.observation import Observation
from argus.correlation.correlation import Correlation
from argus.correlation.matcher import CorrelationMatcher
from argus.correlation.scoring import CorrelationScorer
from argus.correlation.graph import CorrelationGraph
from argus.correlation.registry import ObservationRegistry, CorrelationRegistry

from argus.graph.graph import KnowledgeGraph

logger = logging.getLogger(__name__)

class CorrelationEngine:
    """
    Central engine for discovering relationships between observations.
    Consumes observations, evaluates matching rules, and maintains correlations.
    Does NOT generate investigations.
    """

    def __init__(self, observation_registry: ObservationRegistry, 
                 correlation_registry: CorrelationRegistry, 
                 graph: CorrelationGraph,
                 knowledge_graph: Optional[KnowledgeGraph] = None):
        self.obs_registry = observation_registry
        self.corr_registry = correlation_registry
        self.graph = graph
        self._knowledge_graph = knowledge_graph
        self.matcher = CorrelationMatcher(graph=knowledge_graph)
        self.scorer = CorrelationScorer(self.obs_registry)

    @property
    def knowledge_graph(self) -> Optional[KnowledgeGraph]:
        return self._knowledge_graph

    @knowledge_graph.setter
    def knowledge_graph(self, kg: Optional[KnowledgeGraph]) -> None:
        self._knowledge_graph = kg
        self.matcher.graph = kg

    def process_observation(self, new_obs: Observation) -> None:
        """Process a newly discovered observation."""
        self.obs_registry.add(new_obs)
        self.graph.add_observation(new_obs.id, title=new_obs.title, source=new_obs.source)
        
        matched_correlations = []
        
        # Check against existing observations to find matches
        all_obs = self.obs_registry.get_all()
        for existing_obs in all_obs:
            if existing_obs.id == new_obs.id:
                continue
                
            matched_rules = self.matcher.find_matches(new_obs, existing_obs)
            if matched_rules:
                for rule in matched_rules:
                    self.graph.link_observations(new_obs.id, existing_obs.id, rule)
                    logger.info(f"Observation linked: {new_obs.id} <-> {existing_obs.id} via {rule}")
                
                # Check if existing_obs is already part of a correlation
                corr_ids = self.graph.get_correlations_for_observation(existing_obs.id)
                for c_id in corr_ids:
                    corr = self.corr_registry.find(uuid.UUID(c_id))
                    if corr and corr not in matched_correlations:
                        matched_correlations.append(corr)
                        
        if not matched_correlations:
            # Check if it matched any observation that is NOT in a correlation yet
            # If it did, create a new correlation
            related = self.graph.get_related_observations(new_obs.id)
            if related:
                new_corr = self._create_correlation([new_obs.id] + [uuid.UUID(r['id']) for r in related])
                logger.info(f"Correlation created: {new_corr.id}")
        else:
            # It matched existing correlation(s). 
            # If multiple correlations matched, merge them first.
            if len(matched_correlations) > 1:
                merged_corr = self._merge_correlations(matched_correlations)
                logger.info(f"Duplicate correlation merged into: {merged_corr.id}")
            else:
                merged_corr = matched_correlations[0]
                
            # Update the chosen correlation with the new observation
            self._update_correlation(merged_corr, new_obs.id)
            logger.info(f"Correlation updated: {merged_corr.id}")

    def _create_correlation(self, obs_ids: List[uuid.UUID]) -> Correlation:
        """Create a new correlation from a set of observation IDs."""
        # Deduplicate
        obs_ids = list(set(obs_ids))
        corr = Correlation(title="Aggregated Correlation", description="Automatically generated correlation")
        corr.observations = obs_ids
        
        self.corr_registry.add(corr)
        self.graph.add_correlation(corr.id, title=corr.title)
        
        self._sync_correlation_metadata(corr)
        return corr

    def _update_correlation(self, corr: Correlation, new_obs_id: uuid.UUID) -> None:
        """Add an observation to an existing correlation."""
        if new_obs_id not in corr.observations:
            corr.observations.append(new_obs_id)
        
        self._sync_correlation_metadata(corr)

    def _merge_correlations(self, correlations: List[Correlation]) -> Correlation:
        """Merge multiple correlations into one."""
        if not correlations:
            raise ValueError("No correlations to merge")
            
        primary = correlations[0]
        for other in correlations[1:]:
            for obs_id in other.observations:
                if obs_id not in primary.observations:
                    primary.observations.append(obs_id)
            self.corr_registry.remove(other.id)
            # Remove from graph or mark obsolete
            # (Simplified: just relying on memory update for this exercise)
            
        self._sync_correlation_metadata(primary)
        return primary

    def _sync_correlation_metadata(self, corr: Correlation) -> None:
        """Aggregate contexts and calculate score."""
        bo_set = set()
        wf_set = set()
        tech_set = set()
        gn_set = set()
        ge_set = set()
        authn_set = set()
        authz_set = set()
        tag_set = set()
        
        for obs_id in corr.observations:
            self.graph.link_observation_to_correlation(obs_id, corr.id)
            obs = self.obs_registry.find(obs_id)
            if obs:
                bo_set.update(obs.business_objects)
                wf_set.update(obs.workflows)
                tech_set.update(obs.technology)
                gn_set.update(obs.graph_nodes)
                ge_set.update(obs.graph_edges)
                authn_set.update(obs.authentication_context)
                authz_set.update(obs.authorization_context)
                tag_set.update(obs.tags)
                
        corr.business_objects = list(bo_set)
        corr.workflows = list(wf_set)
        corr.technologies = list(tech_set)
        corr.graph_nodes = list(gn_set)
        corr.graph_edges = list(ge_set)
        corr.authentication_context = list(authn_set)
        corr.authorization_context = list(authz_set)
        corr.tags = list(tag_set)
        
        # Calculate final score
        old_score = corr.score
        corr.score = self.scorer.calculate_score(corr)
        
        if old_score != corr.score:
            logger.info(f"Score recalculated for {corr.id}: {corr.score}")
