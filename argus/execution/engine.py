import time
from typing import Any
from datetime import datetime
from argus.execution.plan import ExecutionPlan
from argus.execution.results import ExecutionPlanResult
from argus.execution.state import ExecutionStatus
from argus.execution.validators import ExecutionValidator
from argus.execution.executor import StepExecutor
from argus.agents.registry import AgentRegistry

class ExecutionEngine:
    def __init__(self, registry: AgentRegistry):
        self.registry = registry
        self.executor = StepExecutor(self.registry)

    def execute_plan(self, plan: ExecutionPlan, mission: Any) -> ExecutionPlanResult:
        if not hasattr(mission, "execution_history"):
            mission.execution_history = []
        if not hasattr(mission, "execution_results"):
            mission.execution_results = {}
        if not hasattr(mission, "execution_metrics"):
            mission.execution_metrics = {}

        plan.status = ExecutionStatus.RUNNING
        result = ExecutionPlanResult(plan_id=plan.id, status=ExecutionStatus.RUNNING)
        start_time = time.time()
        
        try:
            # Plan Level Prerequisite Validation
            if not ExecutionValidator.validate_plan_prerequisites(plan, mission):
                result.status = ExecutionStatus.BLOCKED
                plan.status = ExecutionStatus.BLOCKED
                return result
                
            # Execute steps sequentially (deterministic execution)
            # Make sure steps are sorted by order
            steps = sorted(plan.steps, key=lambda x: x.order)
            
            for step in steps:
                try:
                    # Step Level Validation
                    ExecutionValidator.validate_step_prerequisites(step, mission)
                    
                    # Execute
                    step_result = self.executor.execute_step(step, mission)
                    result.step_results.append(step_result)
                    
                    if step_result.status == ExecutionStatus.FAILED:
                        # Halt execution on failure for determinism
                        result.status = ExecutionStatus.FAILED
                        plan.status = ExecutionStatus.FAILED
                        break
                        
                except Exception as e:
                    # Validation failed or other crash
                    result.status = ExecutionStatus.FAILED
                    plan.status = ExecutionStatus.FAILED
                    print(f"Error during step {step.order}: {e}")
                    break
            else:
                # If loop completed without breaks
                result.status = ExecutionStatus.COMPLETED
                plan.status = ExecutionStatus.COMPLETED
                
        finally:
            result.end_time = datetime.utcnow().isoformat()
            result.total_execution_time_ms = (time.time() - start_time) * 1000
            
            mission.execution_history.append(result)
            mission.execution_results[plan.id] = result
            mission.execution_metrics[plan.id] = {
                "time_ms": result.total_execution_time_ms,
                "steps_run": len(result.step_results),
                "status": result.status
            }
            
        return result
