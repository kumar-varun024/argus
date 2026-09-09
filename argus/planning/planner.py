from typing import List, Any
from argus.planning.models import ResearchPlan, PlanStep
from argus.planning.steps import ALL_STEPS_BUILDERS
from argus.planning.dependencies import DependencyResolver
from argus.planning.scheduler import PlanScheduler

class MissionPlanner:
    """Analyzes a Mission and generates a dependency-aware Research Plan."""
    
    def __init__(self, mission: Any):
        self.mission = mission

    def analyze(self) -> ResearchPlan:
        """Inspects the mission state to select and schedule appropriate steps."""
        
        # Determine available technologies and constraints
        technologies = set(self.mission.technologies) if hasattr(self.mission, 'technologies') else set()
        
        # Instantiate potential steps
        all_steps = [builder() for builder in ALL_STEPS_BUILDERS]
        
        selected_steps = []
        for step in all_steps:
            # Automatic Specialist Selection and conditional skipping
            if step.specialist_assigned == "GraphQLSpecialist":
                if "graphql" not in map(str.lower, technologies):
                    # Skip GraphQL specialist if GraphQL is not detected
                    continue
                    
            if step.specialist_assigned == "NextjsSpecialist":
                if "next.js" not in map(str.lower, technologies):
                    continue
                    
            selected_steps.append(step)
            
        # Resolve dependencies strictly among the selected steps
        dependencies = DependencyResolver.resolve(selected_steps)
        
        # Build DAG and sort
        scheduled_steps = PlanScheduler.schedule(selected_steps, dependencies)
        
        plan = ResearchPlan(
            mission_id=str(self.mission.id),
            objectives=["Complete automated security assessment"],
            scope=self.mission.scope if hasattr(self.mission, 'scope') else [],
            policy=self.mission.policy if hasattr(self.mission, 'policy') else {},
            steps=scheduled_steps,
            dependencies=dependencies,
            status="READY"
        )
        
        # Populate mission fields
        self.mission.plan = plan
        if hasattr(self.mission, 'plan_steps'):
            self.mission.plan_steps = scheduled_steps
        if hasattr(self.mission, 'plan_dependencies'):
            self.mission.plan_dependencies = dependencies
            
        from argus.runtime.events import get_event_bus, RuntimeEventType
        get_event_bus().publish(RuntimeEventType.PLAN_CREATED, str(self.mission.id), details={"steps_count": len(scheduled_steps)})
            
        return plan
