from typing import List
from argus.methodology.models import PlaybookStep
from argus.runtime.mission import Mission
import logging

logger = logging.getLogger(__name__)

class StepEvaluator:
    """Evaluates if a PlaybookStep's prerequisites are met within the Mission context."""
    
    def evaluate_prerequisites(self, step: PlaybookStep, mission: Mission) -> bool:
        """
        Checks if the required evidence, graph nodes, and workflows exist.
        """
        # Validate Evidence
        # For a full implementation, we'd check mission.evidence store
        # Here we do a simplified check for illustration
        if step.required_evidence and not mission.evidence:
            logger.debug(f"Step {step.id} blocked: Missing evidence store.")
            return False
            
        # Validate Workflows
        if step.required_workflows:
            existing_workflows = [w.name for w in mission.workflows] if hasattr(mission.workflows, '__iter__') else []
            for req in step.required_workflows:
                if req not in existing_workflows:
                    logger.debug(f"Step {step.id} blocked: Missing required workflow {req}")
                    return False
                    
        return True
