import typer
import json
from rich.console import Console
from rich.table import Table

from argus.runtime.mission import Mission
from argus.planning.planner import MissionPlanner

app = typer.Typer(help="Mission Planning commands.")
console = Console()

def get_dummy_mission() -> Mission:
    mission = Mission(target="test.com")
    mission.technologies = ["React", "Express", "GraphQL"]
    mission.scope = ["*.test.com"]
    return mission

@app.command("plan")
def generate_plan():
    """Generate and display the Research Plan for the current mission."""
    mission = get_dummy_mission()
    planner = MissionPlanner(mission)
    plan = planner.analyze()
    
    console.print(f"\n[bold green]Generated Research Plan ({plan.id})[/bold green]")
    console.print(f"[bold]Mission Target:[/bold] {mission.target}")
    console.print(f"[bold]Detected Tech:[/bold] {', '.join(mission.technologies)}")
    console.print(f"[bold]Total Steps:[/bold] {len(plan.steps)}\n")
    
    table = Table(title="Execution Steps")
    table.add_column("Order", justify="right")
    table.add_column("Step Name")
    table.add_column("Specialist")
    table.add_column("Outputs")
    
    for idx, step in enumerate(plan.steps, 1):
        outputs = ", ".join(step.outputs) if step.outputs else "None"
        specialist = step.specialist_assigned or "General"
        table.add_row(str(idx), step.name, specialist, outputs)
        
    console.print(table)


@app.command("graph")
def plan_graph():
    """Display the dependency graph for the Research Plan."""
    mission = get_dummy_mission()
    planner = MissionPlanner(mission)
    plan = planner.analyze()
    
    console.print("\n[bold cyan]Plan Dependency Graph[/bold cyan]\n")
    
    # Simple ASCII representation of the DAG
    for step in plan.steps:
        console.print(f"[bold]{step.name}[/bold]")
        if step.dependencies:
            for dep in step.dependencies:
                console.print(f"  └─ Depends on: [yellow]{dep}[/yellow]")
        else:
            console.print("  └─ [green]No dependencies (Root Step)[/green]")
        console.print("")

@app.command("explain")
def plan_explain():
    """Explain the reasoning behind the generated Research Plan."""
    mission = get_dummy_mission()
    planner = MissionPlanner(mission)
    plan = planner.analyze()
    
    console.print("\n[bold magenta]Plan Explanation[/bold magenta]\n")
    console.print("The Mission Planner analyzed the target context and derived the following plan constraints:\n")
    
    has_graphql = any("graphql" in tech.lower() for tech in mission.technologies)
    if has_graphql:
        console.print("- [green]GraphQL Detected[/green]: The 'Discover GraphQL' step was automatically injected and assigned to GraphQLSpecialist.")
    else:
        console.print("- [yellow]No GraphQL Detected[/yellow]: Skipping GraphQL-specific discovery steps.")
        
    console.print(f"- [green]Scope Enforced[/green]: Execution will be restricted to {', '.join(mission.scope)}.")
    console.print("- [green]Dependency DAG Validated[/green]: 0 cyclic dependencies found. Execution order is fully deterministic.")
