import logging
import hashlib
from typing import Dict, Any
from argus.plugins.interfaces import ControlledMission
from argus.plugins.authentication.identity import IdentityAnalyzer
from argus.plugins.authentication.sessions import SessionAnalyzer
from argus.plugins.authentication.tokens import TokenAnalyzer
from argus.plugins.authentication.oauth import OAuthAnalyzer
from argus.plugins.authentication.mfa import MFAAnalyzer
from argus.plugins.authentication.heuristics import AUTHN_HEURISTIC_REGISTRY
from argus.plugins.authentication.confidence import AuthenticationConfidenceScorer

logger = logging.getLogger(__name__)

class AuthenticationIntelligenceSpecialist:
    """Specialist agent for identifying authentication mechanisms."""
    
    def __init__(self):
        self.identity_analyzer = IdentityAnalyzer()
        self.session_analyzer = SessionAnalyzer()
        self.token_analyzer = TokenAnalyzer()
        self.oauth_analyzer = OAuthAnalyzer()
        self.mfa_analyzer = MFAAnalyzer()
        self.heuristics = AUTHN_HEURISTIC_REGISTRY
        self.scorer = AuthenticationConfidenceScorer()
        
    def analyze(self, mission: ControlledMission):
        logger.info(f"Authentication Intelligence starting for Mission {mission.target}")
        
        # Extract inputs
        endpoints = mission._mission.endpoints if hasattr(mission._mission, 'endpoints') else []
        cookies = mission._mission.cookies if hasattr(mission._mission, 'cookies') else []
        tokens = mission._mission.tokens if hasattr(mission._mission, 'tokens') else []
        evidence = mission.evidence if hasattr(mission, 'evidence') and isinstance(mission.evidence, list) else []
        
        # Run analyzers
        identities = self.identity_analyzer.extract_identities(evidence)
        sessions = self.session_analyzer.analyze(cookies, [])
        token_models = self.token_analyzer.analyze(tokens)
        has_oauth = self.oauth_analyzer.analyze(endpoints)
        has_mfa = self.mfa_analyzer.analyze(endpoints)
        
        context = {
            "endpoints": endpoints,
            "identities": identities,
            "sessions": sessions,
            "tokens": token_models,
            "has_oauth": has_oauth,
            "has_mfa": has_mfa
        }
        
        investigations = []
        
        for heuristic in self.heuristics:
            logger.info(f"Running heuristic {heuristic.__class__.__name__}")
            results = heuristic.run(context)
            
            for inv in results:
                inv.confidence = self.scorer.score(inv, context)
                
                if inv.confidence > 80:
                    inv.priority = "High"
                elif inv.confidence > 50:
                    inv.priority = "Medium"
                else:
                    inv.priority = "Low"
                    
                investigations.append(inv)
                
        # Deduplicate
        seen_hashes = set()
        deduped = []
        for inv in investigations:
            hash_str = f"{inv.title}|{inv.category}|{','.join(sorted(inv.affected_objects))}"
            inv_hash = hashlib.sha256(hash_str.encode()).hexdigest()
            if inv_hash not in seen_hashes:
                seen_hashes.add(inv_hash)
                deduped.append(inv)
                
        # Publish to mission
        if not hasattr(mission._mission, 'authentication_workflows'):
            mission._mission.authentication_workflows = []
            
        mission._mission.authentication_workflows.extend(deduped)
        mission._mission.identities.extend(identities)
        mission._mission.sessions.extend(sessions)
        
        logger.info(f"Authentication Intelligence finished. Generated {len(deduped)} investigations.")
