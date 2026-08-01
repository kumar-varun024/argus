import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Manage API Intelligence")
console = Console()

@app.command()
def inventory(mission_id: str):
    """List generated API intelligence investigations."""
    from argus.runtime.manager import mission_manager
    
    try:
        if mission_id == "dummy":
            mission = __import__("argus.runtime.mission", fromlist=["Mission"]).Mission("dummy")
            mission.endpoints = [
                {"path": "/api/v1/users", "method": "GET"},
                {"path": "/api/v1/users", "method": "POST"},
                {"path": "/api/v1/users/bulk_update", "method": "POST"},
                {"path": "/api/v1/admin/settings", "method": "GET"}
            ]
            from argus.plugins.api.plugin import APIIntelligencePlugin
            from argus.plugins.interfaces import ControlledMission
            APIIntelligencePlugin().execute(ControlledMission(mission))
        else:
            mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    if not mission.api_inventory:
        console.print("[yellow]No API investigations found.[/yellow]")
        return
        
    table = Table(title=f"API Investigations for {mission_id}")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Category")
    table.add_column("Priority")
    table.add_column("Confidence")
    
    for inv in mission.api_inventory:
        style = "red" if inv.priority == "Critical" else "yellow" if inv.priority == "High" else "white"
        table.add_row(inv.id[:8], inv.title, inv.category, f"[{style}]{inv.priority}[/{style}]", f"{inv.confidence:.1f}")
        
    console.print(table)

@app.command()
def graph(mission_id: str):
    console.print("[cyan]Displaying API relationships graph...[/cyan]")
    console.print("(Not fully implemented in CLI yet. Refer to relationships data in the mission object.)")
    
@app.command()
def resources(mission_id: str):
    """List extracted API resources."""
    from argus.runtime.manager import mission_manager
    try:
        if mission_id == "dummy":
            mission = __import__("argus.runtime.mission", fromlist=["Mission"]).Mission("dummy")
            mission.endpoints = [{"path": "/api/users"}]
            from argus.plugins.api.plugin import APIIntelligencePlugin
            from argus.plugins.interfaces import ControlledMission
            APIIntelligencePlugin().execute(ControlledMission(mission))
        else:
            mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    if not getattr(mission, 'resources', None):
        console.print("[yellow]No resources found.[/yellow]")
        return
        
    for path, r in mission.resources.items():
        console.print(f"- [green]{r.name}[/green] ({path}) - Collection: {r.is_collection}")

@app.command()
def explain(resource_id: str):
    console.print(f"[cyan]Explaining resource {resource_id}...[/cyan]")
    console.print("(Detailed explanations to be implemented.)")
