import os
import json
import typer
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from argus.runtime.registry import registry
from argus.runtime.orchestrator import ToolOrchestrator
from argus.runtime.manager import mission_manager
from argus.planning.models import ResearchTask, TaskCategory
from argus.runtime.models import ToolExecutionStatus

app = typer.Typer(help="Manage and execute Argus Tools.")
console = Console()


@app.command("list")
def list_tools():
    """List all registered executable tools and capabilities."""
    tools = registry.list()
    if not tools:
        console.print("[yellow]No tools registered.[/yellow]")
        return

    table = Table(title="Registered Tools & Specialist Plugins")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="bold green")
    table.add_column("Version", style="magenta")
    table.add_column("Supported Tasks")
    table.add_column("Capabilities")
    table.add_column("Safety Type")

    for tool in tools:
        tasks = ", ".join(tool.supported_tasks) if tool.supported_tasks else "None"
        caps = ", ".join(tool.capabilities) if tool.capabilities else "None"
        safety_type = tool.safety_requirements.get("type", "external")
        table.add_row(
            tool.id,
            tool.name,
            tool.version,
            tasks,
            caps,
            safety_type
        )

    console.print(table)


@app.command("run")
def run_tool(
    tool_id: str = typer.Argument(..., help="The unique ID of the tool to run."),
    task_id: str = typer.Argument(..., help="The ID of the task requesting this tool."),
    mission_id: Optional[str] = typer.Option(None, help="The ID of the mission context. Auto-created if omitted.")
):
    """Executes a tool on a specific task under a mission context."""
    tool = registry.get(tool_id)
    if not tool:
        console.print(f"[red]Error: Tool '{tool_id}' not found in registry.[/red]")
        raise typer.Exit(code=1)

    # 1. Retrieve or create mission context
    mission = None
    if mission_id:
        try:
            mission = mission_manager.get_mission(mission_id)
        except Exception:
            console.print(f"[yellow]Mission checkpoint '{mission_id}' not found. Creating brand new mission.[/yellow]")
    
    if not mission:
        # Check if there is an active mission in the manager or checkpoints
        missions = mission_manager.list_missions()
        if missions:
            mission = missions[0]
            console.print(f"[green]Using existing mission: {mission.id} for target {mission.target}[/green]")
        else:
            # Create a default mission
            mission = mission_manager.create_mission("cli-test.example.com")
            console.print(f"[green]Created new mission context: {mission.id} for target {mission.target}[/green]")

    # Ensure mission has target in scope for safety validation
    if not mission.scope:
        mission.scope = [mission.target]

    # 2. Create matching ResearchTask
    # Match the category dynamically to one of the tool's supported categories so selection succeeds
    category = tool.supported_tasks[0] if tool.supported_tasks else "API Discovery"
    task = ResearchTask(
        id=task_id,
        title=f"CLI manual task {task_id}",
        description=f"Manually run tool: {tool.name}",
        goal="Manual verification",
        category=category
    )

    console.print(f"[bold blue]Orchestrator: Executing {tool.name} on task {task_id}...[/bold blue]")

    # 3. Instantiate Orchestrator and run
    orchestrator = ToolOrchestrator()
    result = orchestrator.execute_task(mission, task)

    # 4. Display result summary
    status_color = "green" if result.status == ToolExecutionStatus.SUCCEEDED else "red"
    console.print(Panel.fit(
        f"[bold]Run ID:[/bold] {result.id}\n"
        f"[bold]Tool ID:[/bold] {result.tool_id}\n"
        f"[bold]Status:[/bold] [{status_color}]{result.status.value}[/{status_color}]\n"
        f"[bold]Duration:[/bold] {result.execution_time_ms:.2f} ms\n"
        f"[bold]Artifacts Produced:[/bold] {len(result.artifacts)}\n"
        f"[bold]Error:[/bold] {result.error or 'None'}",
        title="Execution Summary",
        border_style="blue"
    ))


@app.command("status")
def status_tool(
    run_id: str = typer.Argument(..., help="The unique execution Run ID to look up.")
):
    """Retrieve detailed execution status and logs for a past tool execution."""
    history_file = ".argus/tool_history.json"
    if not os.path.exists(history_file):
        console.print("[yellow]No tool execution history found.[/yellow]")
        return

    try:
        with open(history_file, 'r') as f:
            history = json.load(f)
    except Exception as e:
        console.print(f"[red]Failed to read execution history: {e}[/red]")
        return

    # Find the run
    run = None
    for entry in history:
        if entry.get("run_id") == run_id:
            run = entry
            break

    if not run:
        console.print(f"[red]Error: Tool run '{run_id}' not found in history.[/red]")
        return

    status_color = "green" if run["status"] == "Succeeded" else "red"
    console.print(Panel(
        f"[bold]Run ID:[/bold] {run['run_id']}\n"
        f"[bold]Mission ID:[/bold] {run['mission_id']}\n"
        f"[bold]Task ID:[/bold] {run['task_id']}\n"
        f"[bold]Tool ID:[/bold] {run['tool_id']}\n"
        f"[bold]Status:[/bold] [{status_color}]{run['status']}[/{status_color}]\n"
        f"[bold]Started At:[/bold] {run['started_at']}\n"
        f"[bold]Completed At:[/bold] {run['completed_at'] or 'N/A'}\n"
        f"[bold]Duration:[/bold] {run['execution_time_ms']:.2f} ms\n"
        f"[bold]Error:[/bold] {run['error'] or 'None'}",
        title=f"Tool Run Status: {run_id}",
        border_style="cyan"
    ))


@app.command("history")
def history_tools():
    """Display history logs of all executed tools."""
    history_file = ".argus/tool_history.json"
    if not os.path.exists(history_file):
        console.print("[yellow]No tool execution history found.[/yellow]")
        return

    try:
        with open(history_file, 'r') as f:
            history = json.load(f)
    except Exception as e:
        console.print(f"[red]Failed to read history: {e}[/red]")
        return

    if not history:
        console.print("[yellow]Tool execution history is empty.[/yellow]")
        return

    table = Table(title="Tool Execution History")
    table.add_column("Run ID", style="cyan")
    table.add_column("Tool", style="bold green")
    table.add_column("Mission", style="blue")
    table.add_column("Task ID", style="magenta")
    table.add_column("Status")
    table.add_column("Duration (ms)", justify="right")

    for entry in history:
        status = entry.get("status", "Unknown")
        status_color = "green" if status == "Succeeded" else "red"
        table.add_row(
            entry.get("run_id")[:8],
            entry.get("tool_id"),
            entry.get("mission_id")[:8],
            entry.get("task_id")[:8],
            f"[{status_color}]{status}[/{status_color}]",
            f"{entry.get('execution_time_ms', 0.0):.2f}"
        )

    console.print(table)
