import logging
from typing import List, Tuple, Any, Optional
from argus.investigation.models import Investigation, InvestigationCategory
from argus.investigation.weights import WeightConfig

from argus.graph.graph import KnowledgeGraph

logger = logging.getLogger(__name__)

class ScoreCalculator:
    """
    Calculates a 0-100 priority score for an investigation based on configurable weights and context.
    MUST NOT determine vulnerability status — only prioritizes investigation opportunities based on evidence.
    """
    
    def __init__(self, weight_config: Optional[WeightConfig] = None):
        self.weights = weight_config or WeightConfig()
        
    def calculate(self, investigation: Investigation, bundle_registry: Any = None, mission: Any = None, graph: Optional[KnowledgeGraph] = None) -> Tuple[float, List[str]]:
        """
        Calculates the 0-100 priority score and provides explainable reasoning strings.
        Returns (score, explanations).
        """
        score = 0.0
        explanations: List[str] = []
        
        # 1. Evidence Strength (Base weight)
        evidence_strength = self._calculate_evidence_strength(investigation, bundle_registry, mission)
        score += evidence_strength * self.weights.evidence_strength
        if evidence_strength > 75:
            explanations.append("Strong evidence from multiple specialists.")
        elif evidence_strength > 0:
            explanations.append("Contains supporting evidence bundles.")
            
        # 2. Observation Confidence (Base weight)
        obs_conf = self._calculate_observation_confidence(investigation, mission)
        score += obs_conf * self.weights.observation_confidence
        if obs_conf >= 80:
            explanations.append("High confidence in underlying observations.")
            
        # 3. Correlation Confidence (Base weight)
        corr_conf = self._calculate_correlation_confidence(investigation, mission)
        score += corr_conf * self.weights.correlation_confidence
        if corr_conf > 0:
            explanations.append("Multiple correlated observations strengthen findings.")
            
        # 4. Workflow Importance (Base weight)
        wf_importance = self._calculate_workflow_importance(investigation, mission)
        score += wf_importance * self.weights.workflow_importance
        if wf_importance > 0:
            explanations.append("Affects critical workflows.")
            
        # 5. Business Object Importance (Base weight)
        bo_importance = self._calculate_bo_importance(investigation, mission)
        score += bo_importance * self.weights.business_object_importance
        if bo_importance > 0:
            explanations.append("High-value business object involved.")
            
        # 6. Exposure & Reachability (Base weight)
        reachability = self._calculate_reachability(investigation, mission)
        score += reachability * self.weights.reachability
        if reachability >= 75:
            explanations.append("High endpoint exposure and reachability.")
            
        # 7. Graph Completeness (Bonus factor)
        graph_completeness = self._calculate_graph_completeness(investigation, mission)
        score += graph_completeness * self.weights.graph_completeness_weight
        if graph_completeness >= 60:
            explanations.append("Graph completeness indicates well-defined structural relationships.")
            
        # 8. Technology Confidence (Bonus factor)
        tech_confidence = self._calculate_technology_confidence(investigation, mission)
        score += tech_confidence * self.weights.technology_confidence_weight
        if tech_confidence >= 60:
            explanations.append("Target technology stack confirmed.")

        # 9. Administrative Operations Context (Multiplier)
        if self._is_administrative(investigation, mission):
            score *= self.weights.administrative_context_bonus
            explanations.append("Administrative workflow or operation.")

        # 10. Authorization Context (Multiplier)
        if self._is_authorization_related(investigation, mission):
            score *= self.weights.authorization_context_bonus
            explanations.append("Authorization context detected.")

        # 11. Authentication Context (Multiplier)
        if self._is_authentication_related(investigation, mission):
            score *= self.weights.authentication_context_bonus
            explanations.append("Authentication context detected.")

        # 12. Mission Policy Alignment (Multiplier)
        if self._matches_mission_policy(investigation, mission):
            score *= self.weights.mission_policy_bonus
            explanations.append("Matches high-priority mission policy rules.")

        # 13. Mission Scope Alignment (Multiplier)
        if self._is_in_mission_scope(investigation, mission):
            score *= self.weights.mission_scope_bonus
            explanations.append("Directly in mission scope focus.")

        # 14. Graph Topology Connectivity & Vulnerability Bonuses
        kg = graph or (getattr(mission, 'attack_surface_graph', None) if mission else None)
        if kg is not None and hasattr(kg, 'nodes'):
            candidate_node_ids = set(investigation.related_graph_nodes or [])
            for ep in (investigation.related_endpoints or []):
                candidate_node_ids.add(str(ep))
                candidate_node_ids.add(f"endpoint:{ep}")
                candidate_node_ids.add(f"live_host:{ep}")
            for t in (investigation.technologies or []):
                candidate_node_ids.add(f"technology:{t}")

            resolved_nodes = []
            for cid in candidate_node_ids:
                if cid in kg.nodes:
                    resolved_nodes.append(kg.nodes[cid])
                else:
                    for nid, n in kg.nodes.items():
                        if n.value == cid or (n.metadata and (n.metadata.get("url") == cid or n.metadata.get("host") == cid)):
                            resolved_nodes.append(n)

            host_nodes = {}
            for n in resolved_nodes:
                if n.type == "live_host":
                    host_nodes[n.id] = n
                elif hasattr(kg, 'get_host_for_node'):
                    h = kg.get_host_for_node(n)
                    if h:
                        host_nodes[h.id] = h

            # Connectivity bonus: host node degree >= 3
            max_degree = 0
            for h in host_nodes.values():
                if hasattr(kg, 'get_node_degree'):
                    deg = kg.get_node_degree(h)
                    if deg > max_degree:
                        max_degree = deg
            for n in resolved_nodes:
                if hasattr(kg, 'get_node_degree'):
                    deg = kg.get_node_degree(n)
                    if deg > max_degree:
                        max_degree = deg

            if max_degree >= 3:
                score *= self.weights.graph_connectivity_bonus
                explanations.append("High host topology connectivity bonus.")

            # Vulnerability bonus: host with HAS_VULNERABILITY edge
            has_vulnerability = False
            host_ids = set(host_nodes.keys())
            resolved_ids = {n.id for n in resolved_nodes}
            target_ids = host_ids | resolved_ids

            for e in kg.edges:
                if e.type == "HAS_VULNERABILITY" and (e.source in target_ids or e.target in target_ids):
                    has_vulnerability = True
                    break

            if not has_vulnerability:
                for n in resolved_nodes:
                    if n.type == "vulnerability":
                        has_vulnerability = True
                        break

            if has_vulnerability:
                score *= self.weights.graph_vulnerability_bonus
                explanations.append("Host has confirmed vulnerability associations.")

        # 15. Bounding & Deduplication
        final_score = float(round(min(100.0, max(0.0, score)), 2))
        
        # Deduplicate explanations preserving order
        unique_explanations = list(dict.fromkeys(explanations))
        if not unique_explanations:
            unique_explanations.append("Baseline score calculated based on available context.")
            
        return final_score, unique_explanations

    def _calculate_evidence_strength(self, investigation: Investigation, bundle_registry: Any, mission: Any) -> float:
        registry = bundle_registry or (getattr(mission, 'evidence_bundles', None) if mission else None)
        if not investigation.evidence_bundles:
            # Fallback to supporting evidence list if bundles not explicit
            return 50.0 if investigation.supporting_evidence else 0.0
            
        max_strength = 0.0
        for bid in investigation.evidence_bundles:
            bundle = registry.find(bid) if (registry and hasattr(registry, 'find')) else None
            if bundle and hasattr(bundle, 'strength'):
                max_strength = max(max_strength, float(bundle.strength))
        return max_strength if max_strength > 0 else (50.0 if investigation.evidence_bundles else 0.0)

    def _calculate_observation_confidence(self, investigation: Investigation, mission: Any) -> float:
        conf = float(investigation.confidence) * 100.0
        if conf > 0:
            return conf
        if investigation.observations and mission and hasattr(mission, 'observations'):
            obs_list = mission.observations.get_all() if hasattr(mission.observations, 'get_all') else []
            obs_map = {o.id: getattr(o, 'confidence', 0.8) for o in obs_list if hasattr(o, 'id')}
            matched = [obs_map[oid] for oid in investigation.observations if oid in obs_map]
            if matched:
                return float(max(matched)) * 100.0
        return 50.0

    def _calculate_correlation_confidence(self, investigation: Investigation, mission: Any) -> float:
        if not investigation.correlations:
            return 0.0
        if mission and hasattr(mission, 'correlations') and hasattr(mission.correlations, 'find'):
            max_conf = 0.0
            for cid in investigation.correlations:
                corr = mission.correlations.find(cid)
                if corr and hasattr(corr, 'confidence'):
                    max_conf = max(max_conf, float(corr.confidence))
            return max_conf * 100.0 if max_conf <= 1.0 else max_conf
        return 75.0

    def _calculate_workflow_importance(self, investigation: Investigation, mission: Any) -> float:
        if not investigation.workflows:
            if investigation.category in [InvestigationCategory.WORKFLOW, InvestigationCategory.BUSINESS_LOGIC]:
                return 70.0
            return 0.0
        
        # Check against mission workflows or critical names
        high_value_wfs = {"admin", "auth", "login", "payment", "checkout", "signup", "reset", "onboarding", "invitation", "organization"}
        max_score = 70.0
        for wf in investigation.workflows:
            wf_lower = str(wf).lower()
            if any(term in wf_lower for term in high_value_wfs):
                max_score = max(max_score, 90.0)
        return max_score

    def _calculate_bo_importance(self, investigation: Investigation, mission: Any) -> float:
        if not investigation.business_objects:
            return 0.0
            
        high_value_bos = {"user", "account", "organization", "org", "role", "permission", "token", "session", "payment", "billing", "admin", "tenant"}
        max_score = 70.0
        for bo in investigation.business_objects:
            bo_lower = str(bo).lower()
            if any(term in bo_lower for term in high_value_bos):
                max_score = max(max_score, 90.0)
        return max_score

    def _calculate_reachability(self, investigation: Investigation, mission: Any) -> float:
        if investigation.related_endpoints:
            return 90.0
        if investigation.category in [InvestigationCategory.API, InvestigationCategory.GRAPHQL, InvestigationCategory.CLIENT_SIDE]:
            return 75.0
        return 50.0

    def _calculate_graph_completeness(self, investigation: Investigation, mission: Any) -> float:
        nodes = len(investigation.related_graph_nodes)
        edges = len(investigation.related_graph_edges)
        if nodes > 0 and edges > 0:
            return 90.0
        if nodes > 0 or edges > 0:
            return 60.0
        if mission and (getattr(mission, 'correlation_graph', None) or getattr(mission, 'authorization_graph', None)):
            return 40.0
        return 0.0

    def _calculate_technology_confidence(self, investigation: Investigation, mission: Any) -> float:
        inv_techs = set([t.lower() for t in (investigation.technologies + investigation.tags)])
        if mission and getattr(mission, 'technologies', None):
            mission_techs = set([t.lower() for t in mission.technologies if isinstance(t, str)])
            if inv_techs & mission_techs:
                return 95.0
        if inv_techs:
            return 75.0
        return 0.0

    def _is_administrative(self, investigation: Investigation, mission: Any) -> bool:
        title_lower = investigation.title.lower()
        desc_lower = investigation.description.lower()
        if any(term in title_lower or term in desc_lower for term in ['admin', 'superuser', 'root', 'management', 'internal']):
            return True
        for wf in investigation.workflows:
            if 'admin' in str(wf).lower():
                return True
        return False

    def _is_authorization_related(self, investigation: Investigation, mission: Any) -> bool:
        if investigation.category == InvestigationCategory.AUTHORIZATION:
            return True
        title_lower = investigation.title.lower()
        if any(term in title_lower for term in ['authz', 'authorization', 'permission', 'rbac', 'abac', 'role', 'tenant', 'access control']):
            return True
        return False

    def _is_authentication_related(self, investigation: Investigation, mission: Any) -> bool:
        if investigation.category in [InvestigationCategory.AUTHENTICATION, InvestigationCategory.SESSION_MANAGEMENT]:
            return True
        title_lower = investigation.title.lower()
        if any(term in title_lower for term in ['authn', 'authentication', 'login', 'token', 'jwt', 'session', 'sso', 'password', 'oauth']):
            return True
        return False

    def _matches_mission_policy(self, investigation: Investigation, mission: Any) -> bool:
        if not mission or not getattr(mission, 'policy', None):
            return False
        policy = mission.policy
        priority_cats = policy.get('priority_categories', [])
        if investigation.category.value in priority_cats or investigation.category in priority_cats:
            return True
        high_priority_terms = policy.get('high_priority_terms', [])
        title_lower = investigation.title.lower()
        if any(str(term).lower() in title_lower for term in high_priority_terms):
            return True
        return False

    def _is_in_mission_scope(self, investigation: Investigation, mission: Any) -> bool:
        if not mission or not getattr(mission, 'scope', None):
            return False
        scope = mission.scope
        for ep in investigation.related_endpoints:
            if any(str(s).lower() in ep.lower() for s in scope):
                return True
        for bo in investigation.business_objects:
            if any(str(s).lower() in bo.lower() for s in scope):
                return True
        return False
