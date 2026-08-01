from argus.runtime.mission import Mission
from argus.agents.authorization.models import AuthzContext
from argus.agents.authorization.heuristics import AUTHZ_HEURISTIC_REGISTRY
from argus.agents.authorization.confidence import AuthzConfidenceScorer
from argus.authorization.models import AuthNodeType
from argus.intelligence.models import Investigation
import logging
import hashlib

logger = logging.getLogger(__name__)

class AuthorizationSpecialist:
    """Specialist agent for identifying authorization risks."""
    
    def __init__(self):
        self.heuristics = AUTHZ_HEURISTIC_REGISTRY
        self.scorer = AuthzConfidenceScorer()
        
    def analyze(self, mission: Mission):
        """Runs the authorization specialist against a mission."""
        logger.info(f"Authorization Specialist starting analysis for Mission {mission.id}")
        
        # Build Context
        roles = []
        if mission.authorization_graph:
            role_nodes = mission.authorization_graph.get_nodes_by_type(AuthNodeType.ROLE)
            roles = [r.name for r in role_nodes]
            
        workflows_dicts = []
        for wf in mission.workflows:
            name = getattr(wf, "name", str(wf))
            if isinstance(wf, dict) and "name" in wf:
                name = wf["name"]
            workflows_dicts.append({"name": name})
            
        context = AuthzContext(
            mission_id=mission.id,
            target=mission.target,
            roles=roles,
            endpoints=mission.endpoints,
            workflows=workflows_dicts,
            graph=mission.authorization_graph
        )
        
        investigations = []
        
        for heuristic in self.heuristics:
            logger.info(f"Running heuristic {heuristic.id}")
            results = heuristic.run(context)
            
            for res in results:
                # Score confidence
                res.investigation.confidence = self.scorer.score(res, context)
                
                # Determine priority based on confidence (simplified logic)
                if res.investigation.confidence > 80:
                    res.investigation.priority = "High"
                elif res.investigation.confidence > 50:
                    res.investigation.priority = "Medium"
                else:
                    res.investigation.priority = "Low"
                    
                investigations.append(res.investigation)
                
        # Deduplicate and store
        seen_hashes = set()
        deduped = []
        for inv in investigations:
            # Create a deterministic hash for deduplication
            hash_str = f"{inv.title}|{inv.category}|{','.join(sorted(inv.affected_objects))}"
            inv_hash = hashlib.sha256(hash_str.encode()).hexdigest()
            if inv_hash not in seen_hashes:
                seen_hashes.add(inv_hash)
                deduped.append(inv)
                
        mission.authorization_investigations.extend(deduped)
        mission.authorization_metrics["total_investigations_generated"] = len(deduped)
        
        logger.info(f"Authorization Specialist finished. Generated {len(deduped)} investigations.")
