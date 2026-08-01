import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Manage File Upload Intelligence")
console = Console()

@app.command()
def analyze(mission_id: str):
    """Run File Upload Intelligence Specialist."""
    from argus.runtime.manager import mission_manager
    from argus.plugins.interfaces import ControlledMission
    from argus.plugins.file_upload.plugin import FileUploadPlugin
    
    try:
        if mission_id == "dummy":
            mission = __import__("argus.runtime.mission", fromlist=["Mission"]).Mission("dummy")
            mission.endpoints = [
                {"path": "/api/upload/avatar", "method": "POST"},
                {"path": "/api/import/csv", "method": "POST"},
                {"path": "/api/tmp/download", "method": "GET"}
            ]
        else:
            mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    console.print(f"[cyan]Running File Upload Intelligence on Mission {mission_id}...[/cyan]")
    plugin = FileUploadPlugin()
    plugin.execute(ControlledMission(mission))
    
    if mission_id != "dummy":
        mission_manager.checkpointer.checkpoint(mission)
    
    console.print(f"[green]Analysis complete! Generated {len(mission.upload_workflows)} investigations.[/green]")

@app.command()
def investigations(mission_id: str):
    """List generated file upload intelligence investigations."""
    from argus.runtime.manager import mission_manager
    try:
        if mission_id == "dummy":
            mission = __import__("argus.runtime.mission", fromlist=["Mission"]).Mission("dummy")
            mission.endpoints = [
                {"path": "/api/upload/avatar", "method": "POST"},
                {"path": "/api/import/csv", "method": "POST"},
                {"path": "/api/tmp/download", "method": "GET"}
            ]
            from argus.plugins.interfaces import ControlledMission
            from argus.plugins.file_upload.plugin import FileUploadPlugin
            FileUploadPlugin().execute(ControlledMission(mission))
        else:
            mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    if not getattr(mission, 'upload_workflows', None):
        console.print("[yellow]No file upload investigations found.[/yellow]")
        return
        
    table = Table(title=f"File Upload Investigations for {mission_id}")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Category")
    table.add_column("Priority")
    table.add_column("Confidence")
    
    for inv in mission.upload_workflows:
        style = "red" if inv.priority == "Critical" else "yellow" if inv.priority == "High" else "white"
        table.add_row(inv.id[:8], inv.title, inv.category, f"[{style}]{inv.priority}[/{style}]", f"{inv.confidence:.1f}")
        
    console.print(table)

@app.command()
def graph(mission_id: str):
    console.print("[cyan]Displaying File Upload and Processing graph...[/cyan]")
    console.print("(Graph view is under construction. Please use 'investigations' to view extracted models.)")

@app.command()
def explain(mission_id: str, inv_id: str):
    """Explain a specific file upload investigation."""
    from argus.runtime.manager import mission_manager
    try:
        if mission_id == "dummy":
            mission = __import__("argus.runtime.mission", fromlist=["Mission"]).Mission("dummy")
            mission.endpoints = [{"path": "/api/upload/avatar", "method": "POST"}]
            from argus.plugins.interfaces import ControlledMission
            from argus.plugins.file_upload.plugin import FileUploadPlugin
            FileUploadPlugin().execute(ControlledMission(mission))
        else:
            mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    workflows = getattr(mission, 'upload_workflows', [])
    for inv in workflows:
        if inv.id.startswith(inv_id) or inv.title.lower().replace(" ", "-") == inv_id:
            console.print(f"\n[bold cyan]Investigation:[/bold cyan] {inv.title}")
            console.print(f"[bold]Category:[/bold] {inv.category}")
            console.print(f"[bold]Priority:[/bold] {inv.priority} (Confidence: {inv.confidence:.1f})")
            console.print(f"[bold]Affected Objects:[/bold] {', '.join(inv.affected_objects)}")
            console.print(f"\n[bold]Reasoning:[/bold]\n{inv.reasoning}")
            
            if inv.supporting_evidence:
                console.print(f"\n[bold yellow]Supporting Evidence:[/bold yellow]")
                for ev in inv.supporting_evidence:
                    console.print(f" - {ev}")
                    
            if inv.manual_validation_steps:
                console.print(f"\n[bold magenta]Manual Validation Steps:[/bold magenta]")
                for step in inv.manual_validation_steps:
                    console.print(f" - {step}")
            return
            
    console.print(f"[red]Investigation matching {inv_id} not found.[/red]")
