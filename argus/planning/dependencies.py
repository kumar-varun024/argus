from typing import List, Dict, Set
from argus.planning.models import PlanStep, PlanDependency

class DependencyResolver:
    """Resolves dependencies between steps and builds a valid execution DAG."""
    
    @staticmethod
    def resolve(steps: List[PlanStep]) -> List[PlanDependency]:
        """Generate formal PlanDependency objects from step dependency names."""
        dependencies = []
        step_names = {s.name for s in steps}
        
        for step in steps:
            for dep_name in step.dependencies:
                if dep_name in step_names:
                    dependencies.append(PlanDependency(
                        source_step=dep_name,
                        target_step=step.name,
                        is_hard_dependency=True
                    ))
        return dependencies

    @staticmethod
    def topological_sort(steps: List[PlanStep], dependencies: List[PlanDependency]) -> List[PlanStep]:
        """Sorts steps based on their dependencies (Topological Sort)."""
        # Build graph
        graph: Dict[str, List[str]] = {s.name: [] for s in steps}
        in_degree: Dict[str, int] = {s.name: 0 for s in steps}
        
        for dep in dependencies:
            if dep.source_step in graph and dep.target_step in in_degree:
                graph[dep.source_step].append(dep.target_step)
                in_degree[dep.target_step] += 1
                
        # Find nodes with 0 in-degree
        queue = [name for name, degree in in_degree.items() if degree == 0]
        sorted_names = []
        
        while queue:
            node = queue.pop(0)
            sorted_names.append(node)
            
            for neighbor in graph[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
                    
        if len(sorted_names) != len(steps):
            raise ValueError("Cyclic dependency detected in planning steps.")
            
        step_map = {s.name: s for s in steps}
        return [step_map[name] for name in sorted_names]
