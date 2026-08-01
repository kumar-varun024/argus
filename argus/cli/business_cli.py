import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Manage Business Logic Investigations")
console = Console()

@app.command()
def investigations(mission_id: str):
    """List generated business logic investigations."""
    from argus.runtime.manager import mission_manager
    
    try:
        if mission_id == "dummy":
            mission = __import__("argus.runtime.mission", fromlist=["Mission"]).Mission("dummy")
            from argus.cli.workflow_cli import get_dummy_workflows
            mission.workflows = get_dummy_workflows()
            from argus.agents.business_logic.agent import BusinessLogicSpecialist
            BusinessLogicSpecialist().analyze(mission)
        else:
            mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    if not mission.business_logic:
        console.print("[yellow]No business logic investigations found.[/yellow]")
        return
        
    table = Table(title=f"Business Logic Investigations for {mission_id}")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Category")
    table.add_column("Priority")
    table.add_column("Confidence")
    
    for inv in mission.business_logic:
        style = "red" if inv.priority == "Critical" else "yellow" if inv.priority == "High" else "white"
        table.add_row(inv.id[:8], inv.title, inv.category, f"[{style}]{inv.priority}[/{style}]", f"{inv.confidence:.1f}")
        
    console.print(table)
