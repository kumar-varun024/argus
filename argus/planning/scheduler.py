from typing import List
from argus.planning.models import PlanStep, PlanDependency
from argus.planning.dependencies import DependencyResolver

class PlanScheduler:
    """Schedules the execution order for a Research Plan."""
    
    @staticmethod
    def schedule(steps: List[PlanStep], dependencies: List[PlanDependency]) -> List[PlanStep]:
        """Returns the steps in topological order."""
        return DependencyResolver.topological_sort(steps, dependencies)
