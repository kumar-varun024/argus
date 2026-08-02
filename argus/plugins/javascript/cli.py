import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from argus.plugins.javascript.agent import JavaScriptSpecialist

app = typer.Typer(help="Manage JavaScript Intelligence")
console = Console()

def _get_or_mock_mission(mission_id: str = None):
    mission = None
    if mission_id:
        try:
            from argus.runtime.manager import mission_manager
            mission = mission_manager.get_mission(mission_id)
        except Exception:
            pass
            
    if not mission:
        from argus.runtime.mission import Mission
        from argus.evidence.model import Evidence
        from argus.graph.graph import KnowledgeGraph
        mission = Mission("test_target")
        mission.graph = KnowledgeGraph()
        mission.evidence.add(Evidence(category="JavaScript", value="React", source="/static/main.js"))
    return mission

@app.command()
def discover(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Discover JavaScript context with rich CLI output."""
    specialist = JavaScriptSpecialist()
    mission = _get_or_mock_mission(mission_id)
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("[cyan]Discovering JavaScript context...", total=None)
        specialist.discover(mission)
        progress.update(task, completed=1)
        
    console.print(Panel("[bold green]JavaScript discovery completed successfully.[/bold green]", title="Discovery Results"))

@app.command()
def analyze(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Analyze JavaScript context with rich CLI output."""
    specialist = JavaScriptSpecialist()
    mission = _get_or_mock_mission(mission_id)
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task1 = progress.add_task("[cyan]Discovering JavaScript context...", total=None)
        specialist.discover(mission)
        progress.update(task1, completed=1)
        
        task2 = progress.add_task("[magenta]Analyzing AST and Symbols...", total=None)
        specialist.analyze(mission)
        progress.update(task2, completed=1)
        
        task3 = progress.add_task("[yellow]Generating Investigations...", total=None)
        specialist.generate_investigations(mission)
        progress.update(task3, completed=1)
        
    # Output Table summary
    if getattr(mission, "javascript", None):
        table = Table(title="JavaScript Intelligence Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="magenta")
        
        js = mission.javascript
        table.add_row("Symbols Discovered", str(len(js.symbols)))
        table.add_row("Routes Found", str(len(js.routes)))
        table.add_row("Frameworks Detected", str(len(js.frameworks)))
        table.add_row("Investigations Generated", str(len(js.investigations)))
        
        console.print(table)
        
    console.print(Panel("[bold green]JavaScript analysis completed successfully.[/bold green]", title="Analysis Complete"))
