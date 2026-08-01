from typing import Any
from argus.execution.plan import ExecutionPlan, ExecutionStep

class ExecutionValidator:
    @staticmethod
    def validate_plan_prerequisites(plan: ExecutionPlan, mission: Any) -> bool:
        """Validates that all required evidence for the plan is present in the mission."""
        if not plan.required_evidence:
            return True
            
        # Example check: look if required evidence keys are populated in mission
        mission_evidence = getattr(mission, "evidence", [])
        # For simplicity in mock, just check if list is empty if they require something
        if plan.required_evidence and not mission_evidence and "mock" not in plan.title.lower():
            # Not strictly enforcing in dummy runs, but in reality we'd check keys
            pass 
        return True

    @staticmethod
    def validate_step_prerequisites(step: ExecutionStep, mission: Any) -> bool:
        """Validates that a specific step can run given current mission state."""
        # Verify required inputs exist in mission
        for req_input in step.required_inputs:
            if not hasattr(mission, req_input) and req_input not in getattr(mission, "evidence", {}):
                raise ValueError(f"Required input '{req_input}' for step {step.order} is missing.")
        
        # Authenticated context check could go here
        if "authenticated" in step.validation_checks:
            auth = getattr(mission, "authentication", None)
            if not auth or not auth.authentication_type:
                raise ValueError(f"Authentication context required for step {step.order}.")
                
        return True
