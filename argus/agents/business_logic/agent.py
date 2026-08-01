import logging
import hashlib
from argus.runtime.mission import Mission
from argus.agents.business_logic.models import BusinessLogicContext
from argus.agents.business_logic.states import StateMachineBuilder
from argus.agents.business_logic.workflow import WorkflowAnalyzer
from argus.agents.business_logic.heuristics import BUSINESS_LOGIC_HEURISTIC_REGISTRY
from argus.agents.business_logic.confidence import BusinessLogicConfidenceScorer
from argus.intelligence.models import Investigation

logger = logging.getLogger(__name__)

class BusinessLogicSpecialist:
    """Specialist agent for identifying business logic risks and state machine vulnerabilities."""
    
    def __init__(self):
        self.heuristics = BUSINESS_LOGIC_HEURISTIC_REGISTRY
        self.scorer = BusinessLogicConfidenceScorer()
        self.sm_builder = StateMachineBuilder()
        self.wf_analyzer = WorkflowAnalyzer()
        
    def analyze(self, mission: Mission):
        """Runs the business logic specialist against a mission."""
        logger.info(f"Business Logic Specialist starting analysis for Mission {mission.id}")
        
        # Build Context
        context = BusinessLogicContext(
            mission_id=mission.id,
            target=mission.target,
            workflows=mission.workflows,
            business_objects=mission.business_objects
        )
        
        # Extract state machines and rules
        context.state_machines = self.sm_builder.extract(context)
        context.rules = self.wf_analyzer.extract_rules(context)
        
        investigations = []
        
        for heuristic in self.heuristics:
            logger.info(f"Running heuristic {heuristic.id}")
            results = heuristic.run(context)
            
            for res in results:
                # Score confidence
                res.investigation.confidence = self.scorer.score(res, context)
                
                # Prioritize
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
            # Create a deterministic hash
            hash_str = f"{inv.title}|{inv.category}|{','.join(sorted(inv.affected_objects))}"
            inv_hash = hashlib.sha256(hash_str.encode()).hexdigest()
            if inv_hash not in seen_hashes:
                seen_hashes.add(inv_hash)
                deduped.append(inv)
                
        # Store back into mission
        mission.business_logic.extend(deduped)
        mission.state_machines.update(context.state_machines)
        mission.workflow_rules.extend(context.rules)
        
        # Basic metrics update (assuming metric fields exist, else use generic findings or similar)
        # We don't have business_logic_metrics, but we can store it in mission.metrics if needed, 
        # or just log.
        logger.info(f"Business Logic Specialist finished. Generated {len(deduped)} investigations.")
