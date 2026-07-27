import time
from typing import Any
from argus.agents.registry import AgentRegistry
from argus.agents.results import AgentResult, AgentMetric, AgentHealth

class AgentScheduler:
    def __init__(self, registry: AgentRegistry):
        self.registry = registry
        self.executed_agents = set()

    def run(self, mission: Any):
        """Execute agents deterministically based on dependency order."""
        if not hasattr(mission, "agent_results"):
            mission.agent_results = {}
        if not hasattr(mission, "agent_health"):
            mission.agent_health = {}
        if not hasattr(mission, "agent_metrics"):
            mission.agent_metrics = {}

        execution_order = self.registry.resolve_execution_order()

        for agent in execution_order:
            if agent.name in self.executed_agents:
                continue

            # Ensure dependencies are met
            deps_met = all(dep in self.executed_agents for dep in agent.dependencies)
            if not deps_met:
                mission.agent_health[agent.name] = AgentHealth.FAILED
                mission.agent_metrics[agent.name] = {"error": "Dependencies not met"}
                continue

            start_time = time.time()
            error_count = 0
            
            try:
                # Standard lifecycle
                agent.run(mission)
                
                # Collect output
                recommendations = agent.produce()
                confidence = agent.confidence()
                health = agent.health()
                
                result = AgentResult(
                    agent_name=agent.name,
                    recommendations=recommendations,
                    confidence=confidence
                )
                
                mission.agent_results[agent.name] = result
                mission.agent_health[agent.name] = health
                
            except Exception as e:
                mission.agent_health[agent.name] = AgentHealth.FAILED
                error_count += 1
                # Log or handle exception as needed
                print(f"Error running agent {agent.name}: {e}")
                
            finally:
                execution_time_ms = (time.time() - start_time) * 1000
                items_produced = 0
                if agent.name in mission.agent_results:
                    items_produced = len(mission.agent_results[agent.name].recommendations)
                    
                metric = AgentMetric(
                    execution_time_ms=execution_time_ms,
                    items_processed=0,  # Could be populated if agent returned this detail
                    items_produced=items_produced,
                    errors=error_count
                )
                mission.agent_metrics[agent.name] = metric
                
                # Mark as executed so dependents can run
                # Even if failed, we mark as executed? Or do we halt dependents?
                # Usually we mark it executed, but dependent agents could check health.
                # For deterministic execution, we add to executed_agents.
                self.executed_agents.add(agent.name)

