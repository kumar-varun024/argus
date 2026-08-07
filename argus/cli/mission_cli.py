import typer
import json
from rich.console import Console
from rich.table import Table

from argus.runtime.manager import mission_manager
from argus.runtime.checkpoint import MissionCheckpointer
from argus.runtime.controller import MissionController

app = typer.Typer(help="Manage Argus Missions")
console = Console()

checkpointer = MissionCheckpointer()
controller = MissionController(checkpointer)

@app.command()
def create(target: str, start: bool = False):
    """Creates a new mission."""
    mission = mission_manager.create_mission(target)
    console.print(f"[green]Created Mission:[/green] {mission.id} for target [bold]{mission.target}[/bold]")
    if start:
        controller.start(mission)
        console.print(f"[green]Mission {mission.id} started.[/green]")

@app.command()
def list():
    """Lists all known missions."""
    missions = mission_manager.list_missions()
    if not missions:
        console.print("[yellow]No missions found.[/yellow]")
        return
        
    table = Table(title="Missions")
    table.add_column("ID", style="cyan")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Phase")
    
    for m in missions:
        table.add_row(m.id, m.target, m.status.value, m.phase)
        
    console.print(table)

@app.command()
def start(mission_id: str):
    """Starts a created mission."""
    try:
        mission = mission_manager.get_mission(mission_id)
        controller.start(mission)
        console.print(f"[green]Mission {mission_id} started successfully.[/green]")
    except Exception as e:
        console.print(f"[red]Error starting mission:[/red] {e}")

@app.command()
def pause(mission_id: str):
    """Pauses a running mission."""
    try:
        mission = mission_manager.get_mission(mission_id)
        controller.pause(mission)
        console.print(f"[yellow]Mission {mission_id} paused.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error pausing mission:[/red] {e}")

@app.command()
def resume(mission_id: str):
    """Resumes a paused mission."""
    try:
        mission = mission_manager.get_mission(mission_id)
        controller.resume(mission)
        console.print(f"[green]Mission {mission_id} resumed.[/green]")
    except Exception as e:
        console.print(f"[red]Error resuming mission:[/red] {e}")

@app.command()
def cancel(mission_id: str):
    """Cancels a mission."""
    try:
        mission = mission_manager.get_mission(mission_id)
        controller.cancel(mission)
        console.print(f"[red]Mission {mission_id} cancelled.[/red]")
    except Exception as e:
        console.print(f"[red]Error cancelling mission:[/red] {e}")

@app.command()
def status(mission_id: str):
    """Displays detailed status of a mission."""
    try:
        mission = mission_manager.get_mission(mission_id)
        console.print(f"\n[bold cyan]Mission Status:[/bold cyan] {mission.id}")
        console.print(f"[bold]Target:[/bold] {mission.target}")
        console.print(f"[bold]State:[/bold] {mission.status.value}")
        console.print(f"[bold]Phase:[/bold] {mission.phase}")
        console.print(f"[bold]Updated At:[/bold] {mission.updated_at}\n")
    except Exception as e:
        console.print(f"[red]Error getting mission status:[/red] {e}")

@app.command()
def history(mission_id: str):
    """Displays state transition history for a mission."""
    try:
        mission = mission_manager.get_mission(mission_id)
        if not hasattr(mission, 'state_transitions') or not mission.state_transitions:
            console.print(f"[yellow]No history available for mission {mission_id}[/yellow]")
            return
            
        table = Table(title=f"Transition History for {mission_id}")
        table.add_column("Timestamp", style="cyan")
        table.add_column("From State")
        table.add_column("To State")
        table.add_column("Reason")
        
        for record in mission.state_transitions:
            table.add_row(
                record.get('timestamp', ''),
                record.get('from', ''),
                record.get('to', ''),
                record.get('reason', '')
            )
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error getting history:[/red] {e}")

@app.command()
def explain(mission_id: str):
    """Explains mission metrics and checkpoints."""
    try:
        mission = mission_manager.get_mission(mission_id)
        console.print(f"[bold]Metrics for {mission_id}[/bold]")
        console.print(json.dumps(mission.metrics, indent=2))
        
        if hasattr(mission, 'checkpoints') and mission.checkpoints:
            console.print("\n[bold]Checkpoints evaluated:[/bold]")
            for cp in mission.checkpoints:
                console.print(f"- {cp['name']} -> {cp['action']}")
    except Exception as e:
        console.print(f"[red]Error explaining mission:[/red] {e}")
