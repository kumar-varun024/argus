import typer
from rich.console import Console
from rich.table import Table

from argus.runtime.mission import Mission
from argus.runtime.executor import TaskScheduler
from argus.planning.models import ResearchTask, TaskCategory
from argus.runtime.models import TaskState

app = typer.Typer(help="Task Scheduler commands.")
console = Console()


def _get_demo_mission_and_scheduler():
    mission = Mission(target="scheduler.example.com")
    scheduler = TaskScheduler(mission, max_workers=2)
    
    tasks = [
        ResearchTask(id="task-1", title="Discover APIs", description="Find endpoints", goal="Recon", category=TaskCategory.API_DISCOVERY, priority=0.9),
        ResearchTask(id="task-2", title="Analyze APIs", description="Analyze endpoints", goal="Vuln", category=TaskCategory.GRAPHQL_ANALYSIS, priority=0.8, dependencies=["Discover APIs"]),
        ResearchTask(id="task-3", title="Tech Fingerprint", description="Find tech", goal="Recon", category=TaskCategory.TECHNOLOGY_DISCOVERY, priority=0.7),
    ]
    scheduler.schedule_tasks(tasks)
    return mission, scheduler


@app.command("queue")
def scheduler_queue():
    """Display the current execution queue state."""
    mission, scheduler = _get_demo_mission_and_scheduler()
    
    console.print(f"\n[bold green]Execution Queue[/bold green] (Active Workers: {scheduler.queue_manager.queue.active_workers}/{scheduler.queue_manager.queue.max_workers})\n")
    
    table = Table(title="Scheduled Tasks")
    table.add_column("Task ID")
    table.add_column("Title")
    table.add_column("State")
    table.add_column("Priority", justify="right")
    table.add_column("Dependencies")
    table.add_column("Retries")

    for t in scheduler.queue_manager.queue.tasks:
        deps = ", ".join(t.dependencies) if t.dependencies else "—"
        state_color = "yellow" if t.state == TaskState.PENDING else "cyan" if t.state == TaskState.READY else "blue"
        table.add_row(
            t.task_id[:8],
            t.task_title,
            f"[{state_color}]{t.state.value}[/{state_color}]",
            f"{t.priority:.2f}",
            deps,
            f"{t.retry_count}/{t.retry_policy.max_retries}"
        )

    console.print(table)


@app.command("history")
def scheduler_history():
    """Display execution history events."""
    mission, scheduler = _get_demo_mission_and_scheduler()
    
    # Simulate some execution
    batch = scheduler.get_executable_batch()
    if batch:
        scheduler.report_success(batch[0].task_id)
        if len(batch) > 1:
            scheduler.report_failure(batch[1].task_id, error="Simulated timeout", is_timeout=True)
            
    console.print(f"\n[bold magenta]Execution History[/bold magenta]\n")
    
    for event in scheduler.event_bus.get_history():
        console.print(f"[[cyan]{event.timestamp}[/cyan]] [bold]{event.event_type.value}[/bold] -> {event.task_title}")
        if event.details:
            console.print(f"  Details: {event.details}")


@app.command("graph")
def scheduler_graph():
    """Display the dependency graph of scheduled tasks."""
    mission, scheduler = _get_demo_mission_and_scheduler()
    
    console.print(f"\n[bold yellow]Task Dependency Graph[/bold yellow]\n")
    
    tasks = scheduler.queue_manager.queue.tasks
    for t in tasks:
        if not t.dependencies:
            console.print(f"🟢 [bold]{t.task_title}[/bold]")
            _print_children(t.task_title, tasks, level=1)


def _print_children(parent_title: str, tasks: list, level: int):
    for t in tasks:
        if parent_title in t.dependencies:
            indent = "  " * level
            console.print(f"{indent}↳ 🟡 [bold]{t.task_title}[/bold]")
            _print_children(t.task_title, tasks, level + 1)
