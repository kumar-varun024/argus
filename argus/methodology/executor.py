from argus.methodology.models import Playbook, PlaybookResult
from argus.methodology.step import StepEvaluator
from argus.runtime.mission import Mission
import logging

logger = logging.getLogger(__name__)

class PlaybookExecutor:
    """Executes a Playbook step-by-step against a Mission."""
    
    def __init__(self):
        self.step_evaluator = StepEvaluator()
        
    def execute(self, playbook: Playbook, mission: Mission) -> PlaybookResult:
        logger.info(f"Executing playbook {playbook.name} on mission {mission.id}")
        
        result = PlaybookResult(playbook_id=playbook.id, status="running")
        
        # Verify inputs
        # (Simplified dependency validation)
        if playbook.required_inputs:
            logger.info(f"Checking prerequisites for {playbook.name}")
            
        for step in playbook.steps:
            logger.info(f"Evaluating step: {step.title}")
            
            if self.step_evaluator.evaluate_prerequisites(step, mission):
                logger.info(f"Executing step: {step.title}")
                # In a real engine, this would dispatch to agents or prompt a researcher
                result.completed_steps.append(step.id)
                # Simulated finding for demonstration
                result.findings.append({
                    "step": step.id,
                    "title": f"Finding from {step.title}",
                    "details": "Evidence-backed finding based on context."
                })
            else:
                logger.warning(f"Step '{step.title}' prerequisites not met. Skipping.")
                
        # If any steps completed, mark as completed
        if result.completed_steps:
            result.status = "completed"
        else:
            result.status = "failed"
            
        logger.info(f"Playbook {playbook.name} finished with status: {result.status}")
        return result
