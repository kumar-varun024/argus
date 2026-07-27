from typing import List, Dict, Type
from collections import defaultdict, deque
from argus.agents.base import BaseAgent

class AgentRegistry:
    def __init__(self):
        self._agents: Dict[str, BaseAgent] = {}

    def register(self, agent: BaseAgent):
        """Register an agent instance."""
        if agent.name in self._agents:
            raise ValueError(f"Agent {agent.name} is already registered.")
        self._agents[agent.name] = agent

    def get_agent(self, name: str) -> BaseAgent:
        return self._agents.get(name)

    def list_agents(self) -> List[BaseAgent]:
        return list(self._agents.values())

    def resolve_execution_order(self) -> List[BaseAgent]:
        """
        Perform a topological sort based on dependencies to determine execution order.
        """
        in_degree = {name: 0 for name in self._agents}
        graph = defaultdict(list)
        
        for name, agent in self._agents.items():
            for dep in agent.dependencies:
                if dep in self._agents:
                    graph[dep].append(name)
                    in_degree[name] += 1
                else:
                    # Optional: warn or ignore missing dependencies
                    pass
                    
        queue = deque([name for name in self._agents if in_degree[name] == 0])
        execution_order = []
        
        while queue:
            current = queue.popleft()
            execution_order.append(self._agents[current])
            
            for neighbor in graph[current]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
                    
        if len(execution_order) != len(self._agents):
            raise ValueError("Circular dependency detected among registered agents.")
            
        return execution_order
