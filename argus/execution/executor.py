import time
from typing import Any
from argus.execution.plan import ExecutionStep
from argus.execution.results import ExecutionStepResult
from argus.agents.registry import AgentRegistry
from argus.execution.state import ExecutionStatus

class StepExecutor:
    def __init__(self, registry: AgentRegistry):
        self.registry = registry

    def execute_step(self, step: ExecutionStep, mission: Any) -> ExecutionStepResult:
        agent = self.registry.get_agent(step.agent)
        result = ExecutionStepResult(
            step_order=step.order,
            agent=step.agent,
            status=ExecutionStatus.PENDING
        )
        
        if not agent:
            result.status = ExecutionStatus.FAILED
            result.errors.append(f"Agent '{step.agent}' not found in registry.")
            return result
            
        start_time = time.time()
        result.status = ExecutionStatus.RUNNING
        
        try:
            # We don't perform active exploitation. The Agent is assumed to respect this.
            # Call agent's standardized lifecycle
            agent.run(mission)
            
            # The agent might have stored results in mission.agent_results
            # Or we can capture it through agent.produce()
            outputs = agent.produce()
            
            result.outputs = {"recommendations": outputs}
            result.status = ExecutionStatus.COMPLETED
            
        except Exception as e:
            result.status = ExecutionStatus.FAILED
            result.errors.append(str(e))
            
        finally:
            result.execution_time_ms = (time.time() - start_time) * 1000
            
        return result
