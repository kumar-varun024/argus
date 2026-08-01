import typer
from typing import Optional
from rich.console import Console
from rich.table import Table

from argus.runtime.manager import mission_manager
from argus.methodology.engine import MethodologyEngine
from argus.methodology.registry import PlaybookRegistry

app = typer.Typer(help="Manage and run Methodology Playbooks")
console = Console()

registry = PlaybookRegistry()
engine = MethodologyEngine(registry=registry)

@app.command()
def list():
    """Lists all available playbooks."""
    playbooks = registry.get_all()
    
    if not playbooks:
        console.print("[yellow]No playbooks found.[/yellow]")
        return
        
    table = Table(title="Available Playbooks")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Steps")
    
    for pb in playbooks:
        table.add_row(pb.id, pb.name, pb.category, str(len(pb.steps)))
        
    console.print(table)

@app.command()
def show(playbook_id: str):
    """Shows details of a specific playbook."""
    pb = registry.get(playbook_id)
    if not pb:
        console.print(f"[red]Playbook {playbook_id} not found.[/red]")
        return
        
    console.print(f"\n[bold cyan]Playbook:[/bold cyan] {pb.name} ({pb.id})")
    console.print(f"[bold]Category:[/bold] {pb.category}")
    console.print(f"[bold]Description:[/bold] {pb.description}\n")
    
    table = Table(title="Steps")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Required Workflows")
    
    for step in pb.steps:
        table.add_row(step.id, step.title, ", ".join(step.required_workflows) if step.required_workflows else "None")
        
    console.print(table)

@app.command()
def run(mission_id: str, playbook_id: Optional[str] = typer.Argument(None)):
    """Runs methodology engine on a mission, optionally specifying a playbook."""
    try:
        mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    console.print(f"[cyan]Running Methodology Engine for Mission {mission_id}...[/cyan]")
    try:
        engine.run(mission, playbook_id)
        mission_manager.checkpointer.checkpoint(mission)
        console.print("[green]Execution complete.[/green]")
    except Exception as e:
        console.print(f"[red]Engine failed:[/red] {e}")

@app.command()
def status(mission_id: str):
    """Shows the execution progress of playbooks for a mission."""
    try:
        mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    console.print(f"\n[bold cyan]Methodology Status for Mission:[/bold cyan] {mission.id}\n")
    
    console.print("[bold]Completed Playbooks:[/bold]")
    if not mission.completed_playbooks:
        console.print("  None")
    for pb_id in mission.completed_playbooks:
        console.print(f"  [green]✓[/green] {pb_id}")
        
    console.print("\n[bold]Active Playbooks:[/bold]")
    if not mission.active_playbooks:
        console.print("  None")
    for pb_id in mission.active_playbooks:
        console.print(f"  [yellow]↻[/yellow] {pb_id}")
        
    console.print()
