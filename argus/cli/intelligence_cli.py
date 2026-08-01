import typer
import json
from rich.console import Console
from rich.table import Table

from argus.runtime.manager import mission_manager
from argus.intelligence.engine import VulnerabilityIntelligenceEngine

app = typer.Typer(help="Manage and view Vulnerability Intelligence Investigations")
console = Console()

engine = VulnerabilityIntelligenceEngine()

@app.command("run")
def investigate(mission_id: str):
    """Triggers the intelligence engine to generate hypotheses for a mission."""
    try:
        mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    console.print(f"[cyan]Running Vulnerability Intelligence Engine on {mission_id}...[/cyan]")
    engine.run(mission)
    mission_manager.checkpointer.checkpoint(mission)
    
    console.print(f"[green]Complete! Generated {len(mission.investigations)} investigations.[/green]")

@app.command()
def list(mission_id: str):
    """Lists investigations for a mission."""
    try:
        mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    if not mission.investigations:
        console.print("[yellow]No investigations found.[/yellow]")
        return
        
    table = Table(title=f"Investigations for {mission_id}")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Priority")
    table.add_column("Confidence")
    
    for inv in mission.investigations:
        style = "red" if inv.priority == "Critical" else "yellow" if inv.priority == "High" else "white"
        table.add_row(inv.id[:8], inv.title, f"[{style}]{inv.priority}[/{style}]", f"{inv.confidence:.1f}")
        
    console.print(table)

@app.command()
def show(mission_id: str, inv_id: str):
    """Shows details for a specific investigation."""
    try:
        mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    for inv in mission.investigations:
        if inv.id.startswith(inv_id):
            console.print(f"\n[bold cyan]Investigation:[/bold cyan] {inv.title}")
            console.print(f"[bold]Category:[/bold] {inv.category}")
            console.print(f"[bold]Priority:[/bold] {inv.priority} (Confidence: {inv.confidence:.1f})")
            console.print(f"[bold]Affected Objects:[/bold] {', '.join(inv.affected_objects)}")
            console.print(f"[bold]Workflow:[/bold] {inv.workflow}")
            return
            
    console.print(f"[red]Investigation starting with {inv_id} not found.[/red]")

@app.command()
def explain(mission_id: str, inv_id: str):
    """Explains reasoning and validation steps for an investigation."""
    try:
        mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    for inv in mission.investigations:
        if inv.id.startswith(inv_id):
            console.print(f"\n[bold cyan]Reasoning for '{inv.title}'[/bold cyan]\n")
            console.print(inv.reasoning)
            console.print(f"\n[bold yellow]Supporting Evidence:[/bold yellow]")
            for ev in inv.supporting_evidence:
                console.print(f" - {ev}")
            console.print(f"\n[bold magenta]Manual Validation Steps:[/bold magenta]")
            for step in inv.manual_validation_steps:
                console.print(f" - {step}")
            console.print("\n[red]NOTE: This is a hypothesis. It must be manually validated and does NOT claim a vulnerability exists.[/red]\n")
            return
            
    console.print(f"[red]Investigation starting with {inv_id} not found.[/red]")
