import typer
import json
from rich.console import Console
from rich.table import Table

from argus.runtime.mission import Mission
from argus.planning.research_planner import ResearchPlanner

app = typer.Typer(help="Research Planning commands.")
console = Console()


def _get_demo_mission() -> Mission:
    """Create a demo mission with some state for demonstration."""
    mission = Mission(target="demo.example.com")
    mission.technologies = ["React", "Express", "GraphQL"]
    mission.scope = ["*.example.com"]
    mission.endpoints = [
        {"url": "/api/users", "method": "GET"},
        {"url": "/api/orders", "method": "POST"},
    ]
    return mission


@app.command("plan")
def research_plan():
    """Generate and display the current research queue."""
    mission = _get_demo_mission()
    planner = ResearchPlanner(mission)
    tasks = planner.plan()

    console.print(f"\n[bold green]Research Queue ({len(tasks)} tasks)[/bold green]\n")

    table = Table(title="Prioritized Research Tasks")
    table.add_column("#", justify="right")
    table.add_column("Title")
    table.add_column("Category")
    table.add_column("Priority", justify="right")
    table.add_column("Specialist")
    table.add_column("Reason")

    for idx, task in enumerate(tasks, 1):
        specialists = ", ".join(task.required_specialists) if task.required_specialists else "—"
        table.add_row(
            str(idx),
            task.title,
            task.category.value,
            f"{task.priority:.2f}",
            specialists,
            task.reason[:60] + "…" if len(task.reason) > 60 else task.reason,
        )

    console.print(table)


@app.command("queue")
def research_queue():
    """Show the ordered task queue IDs."""
    mission = _get_demo_mission()
    planner = ResearchPlanner(mission)
    tasks = planner.plan()

    console.print(f"\n[bold cyan]Research Queue Order[/bold cyan]\n")
    for idx, task in enumerate(tasks, 1):
        console.print(f"  {idx}. [{task.status}] {task.title} (priority={task.priority:.2f})")


@app.command("explain")
def research_explain():
    """Explain the reasoning behind each generated research task."""
    mission = _get_demo_mission()
    planner = ResearchPlanner(mission)
    tasks = planner.plan()

    console.print(f"\n[bold magenta]Research Plan Explanation[/bold magenta]\n")
    for task in tasks:
        console.print(f"[bold]{task.title}[/bold]")
        console.print(f"  Goal: {task.goal}")
        console.print(f"  Reason: {task.reason}")
        console.print(f"  Category: {task.category.value}")
        console.print(f"  Priority: {task.priority:.2f}")
        if task.dependencies:
            console.print(f"  Depends on: {', '.join(task.dependencies)}")
        console.print("")


@app.command("coverage")
def research_coverage():
    """Display the current coverage report."""
    mission = _get_demo_mission()
    planner = ResearchPlanner(mission)
    coverage = planner.get_coverage()

    console.print(f"\n[bold yellow]Coverage Report[/bold yellow]\n")
    console.print(f"  Overall Coverage: [bold]{coverage.overall_coverage:.1%}[/bold]")
    console.print(f"  Endpoints: {coverage.endpoints_covered}/{coverage.endpoints_total}")
    console.print(f"  Business Objects: {coverage.business_objects_covered}/{coverage.business_objects_total}")
    console.print(f"  Workflows: {coverage.workflows_covered}/{coverage.workflows_total}")
    console.print(f"  Authentication: {'✓' if coverage.authentication_covered else '✗'}")
    console.print(f"  Authorization: {'✓' if coverage.authorization_covered else '✗'}")
    console.print(f"  Technologies: {coverage.technologies_covered}/{coverage.technologies_total}")

    if coverage.gaps:
        console.print(f"\n[bold red]Coverage Gaps ({len(coverage.gaps)})[/bold red]")
        for gap in coverage.gaps:
            console.print(f"  • {gap.area}: {gap.description} (severity={gap.severity:.2f})")
