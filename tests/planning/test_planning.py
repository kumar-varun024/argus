import pytest
from argus.planning.planner import MissionPlanner
from argus.planning.dependencies import DependencyResolver
from argus.planning.models import PlanStep
from argus.runtime.mission import Mission

def test_planner_generates_valid_dag():
    mission = Mission(target="test.local")
    mission.technologies = ["REST", "React"]
    
    planner = MissionPlanner(mission)
    plan = planner.analyze()
    
    # We shouldn't see GraphQL here because it wasn't in tech
    step_names = [s.name for s in plan.steps]
    assert "Discover Technologies" in step_names
    assert "Discover GraphQL" not in step_names
    
    # Verify order: Discover Technologies -> Discover APIs -> Analyze Authentication
    tech_idx = step_names.index("Discover Technologies")
    api_idx = step_names.index("Discover APIs")
    auth_idx = step_names.index("Analyze Authentication")
    
    assert tech_idx < api_idx
    assert api_idx < auth_idx
    
    assert mission.plan is not None
    assert mission.plan_steps == plan.steps

def test_planner_graphql_injection():
    mission = Mission(target="test.local")
    mission.technologies = ["REST", "GraphQL", "React"]
    
    planner = MissionPlanner(mission)
    plan = planner.analyze()
    
    step_names = [s.name for s in plan.steps]
    assert "Discover GraphQL" in step_names
    
    # Check that Discover GraphQL happens after Discover Technologies
    tech_idx = step_names.index("Discover Technologies")
    gql_idx = step_names.index("Discover GraphQL")
    assert tech_idx < gql_idx
    
    # Check that Analyze Authorization happens after Discover GraphQL
    authz_idx = step_names.index("Analyze Authorization")
    assert gql_idx < authz_idx

def test_cyclic_dependency_prevention():
    step1 = PlanStep(name="Step 1", description="s1", dependencies=["Step 2"])
    step2 = PlanStep(name="Step 2", description="s2", dependencies=["Step 1"])
    
    deps = DependencyResolver.resolve([step1, step2])
    
    with pytest.raises(ValueError, match="Cyclic dependency"):
        DependencyResolver.topological_sort([step1, step2], deps)
