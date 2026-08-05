import typer
from rich.console import Console
from rich.table import Table
import uuid

from argus.correlation.cli import _get_active_mission

console = Console()
investigations_app = typer.Typer(help="Manage Investigations")

@investigations_app.command(name="list")
def list_investigations(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """List all investigations for a mission."""
    mission = _get_active_mission(mission_id)
    if not hasattr(mission, 'investigations'):
        console.print("[red]Investigation Builder not initialized.[/red]")
        return
        
    invs = mission.investigations.get_all()
    if not invs:
        console.print("[yellow]No investigations found.[/yellow]")
        return
        
    table = Table(title="Investigations Queue")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Category", style="blue")
    table.add_column("Priority", style="red")
    table.add_column("Score", justify="right")
    table.add_column("Confidence", style="magenta")
    
    for inv in invs:
        table.add_row(
            str(inv.id),
            inv.title,
            inv.category.value,
            inv.priority.value,
            f"{inv.priority_score:.1f}",
            f"{int(inv.confidence * 100)}%"
        )
        
    console.print(table)

@investigations_app.command(name="show")
def show_investigation(inv_id: str, mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Show details of a specific investigation."""
    mission = _get_active_mission(mission_id)
    try:
        uid = uuid.UUID(inv_id)
    except ValueError:
        console.print("[red]Invalid UUID format.[/red]")
        return
        
    if not hasattr(mission, 'investigations'):
        return
        
    inv = mission.investigations.find(uid)
    if not inv:
        console.print(f"[red]Investigation {inv_id} not found.[/red]")
        return
        
    console.print("[bold cyan]Investigation[/bold cyan]")
    console.print(f"[bold]Title[/bold]\n{inv.title}")
    console.print(f"[bold]Category[/bold]\n{inv.category.value}")
    console.print(f"[bold]Priority[/bold]\n{inv.priority.value}")
    console.print(f"[bold]Priority Score[/bold]\n{inv.priority_score:.1f}")
    console.print(f"[bold]Confidence[/bold]\n{int(inv.confidence * 100)}%")
    
    if inv.priority_explanation:
        console.print("[bold]Priority Explanations[/bold]")
        for exp in inv.priority_explanation:
            console.print(f"• {exp}")
            
    console.print(f"[bold]Reason[/bold]\n{inv.reasoning}")
    
    if inv.business_objects:
        console.print("[bold]Business Objects[/bold]")
        for bo in sorted(inv.business_objects):
            console.print(bo)
            
    if inv.workflows:
        console.print("[bold]Workflows[/bold]")
        for wf in sorted(inv.workflows):
            console.print(wf)
            
    if inv.manual_validation:
        console.print("[bold]Manual Validation[/bold]")
        console.print(inv.manual_validation)

@investigations_app.command(name="explain")
def explain_investigation(inv_id: str, mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Show the reasoning tree and priority explanations for an investigation."""
    mission = _get_active_mission(mission_id)
    if not hasattr(mission, 'investigations'):
        return
        
    try:
        uid = uuid.UUID(inv_id)
        inv = mission.investigations.find(uid)
    except Exception:
        inv = None
        
    if inv and inv.priority_explanation:
        console.print("[bold cyan]Priority Explanation[/bold cyan]")
        for exp in inv.priority_explanation:
            console.print(f"- {exp}")
            
    if hasattr(mission, 'reasoning_tree'):
        tree = mission.reasoning_tree.get(inv_id)
        if tree:
            import json
            console.print("[bold cyan]Reasoning Tree[/bold cyan]")
            console.print(json.dumps(tree, indent=2))

@investigations_app.command(name="export")
def export_investigations(format: str = typer.Argument("json", help="Export format: json"),
                          mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Export all investigations."""
    mission = _get_active_mission(mission_id)
    if not hasattr(mission, 'investigations'):
        return
        
    invs = mission.investigations.get_all()
    import json
    from argus.correlation.serializer import _JSONEncoder
    out = [i.model_dump() for i in invs]
    console.print(json.dumps(out, indent=2, cls=_JSONEncoder))

@investigations_app.command(name="priority")
def calculate_priority(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Calculate priorities for all investigations, updating priority queue and scores."""
    mission = _get_active_mission(mission_id)
    if not hasattr(mission, 'investigations'):
        console.print("[red]Investigation Builder not initialized.[/red]")
        return
        
    from argus.investigation.priority_engine import PriorityEngine
    from argus.investigation.weights import WeightConfig
    
    engine = PriorityEngine(mission.evidence_bundles, WeightConfig())
    invs = mission.investigations.get_all()
    
    ranked = engine.evaluate_all(invs, mission)
    
    table = Table(title="Priority Queue")
    table.add_column("Rank", style="cyan")
    table.add_column("Title")
    table.add_column("Priority", style="red")
    table.add_column("Score", justify="right")
    table.add_column("Explanation")
    
    for i, inv in enumerate(ranked):
        exp_summary = inv.priority_explanation[0] if inv.priority_explanation else ""
        table.add_row(
            str(i + 1),
            inv.title,
            inv.priority.value,
            f"{inv.priority_score:.1f}",
            exp_summary
        )
    console.print(table)
    console.print(f"[green]Priority calculated for {len(invs)} investigations.[/green]")

@investigations_app.command(name="top")
def show_top_investigations(
    limit: int = typer.Option(5, "--limit", "-l", help="Number of items to show"),
    mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")
):
    """Show the top priority investigations."""
    mission = _get_active_mission(mission_id)
    if not hasattr(mission, 'investigations'):
        console.print("[red]Investigation Builder not initialized.[/red]")
        return
        
    invs = mission.investigations.get_all()
    if not invs:
        console.print("[yellow]No investigations found.[/yellow]")
        return
        
    from argus.investigation.ranking import InvestigationRanker
    ranked = InvestigationRanker.rank(invs, highest_first=True)
    
    table = Table(title=f"Top {limit} Priority Investigations")
    table.add_column("Rank", style="cyan")
    table.add_column("Title")
    table.add_column("Category", style="blue")
    table.add_column("Priority", style="red")
    table.add_column("Score", justify="right")
    table.add_column("Explanation")
    
    for i, inv in enumerate(ranked[:limit]):
        exp_summary = "; ".join(inv.priority_explanation[:2]) if inv.priority_explanation else ""
        table.add_row(
            str(i + 1),
            inv.title,
            inv.category.value,
            inv.priority.value,
            f"{inv.priority_score:.1f}",
            exp_summary
        )
    console.print(table)

@investigations_app.command(name="rank")
def rank_investigations(
    highest_first: bool = typer.Option(True, "--highest/--lowest", help="Sort order"),
    category: str = typer.Option(None, "--category", "-c", help="Filter by category"),
    priority: str = typer.Option(None, "--priority", "-p", help="Filter by priority"),
    business_object: str = typer.Option(None, "--business-object", "-b", help="Filter by business object"),
    workflow: str = typer.Option(None, "--workflow", "-w", help="Filter by workflow"),
    technology: str = typer.Option(None, "--technology", "-t", help="Filter by technology"),
    mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")
):
    """Rank and filter investigations."""
    mission = _get_active_mission(mission_id)
    if not hasattr(mission, 'investigations'):
        console.print("[red]Investigation Builder not initialized.[/red]")
        return
        
    invs = mission.investigations.get_all()
    from argus.investigation.ranking import InvestigationRanker
    
    ranked = InvestigationRanker.rank(
        invs, 
        highest_first=highest_first, 
        category=category, 
        priority=priority,
        business_object=business_object,
        workflow=workflow,
        technology=technology
    )
    
    table = Table(title="Ranked Investigations")
    table.add_column("Rank", style="cyan")
    table.add_column("Title")
    table.add_column("Category", style="blue")
    table.add_column("Priority", style="red")
    table.add_column("Score", justify="right")
    
    for i, inv in enumerate(ranked):
        table.add_row(
            str(i + 1),
            inv.title,
            inv.category.value,
            inv.priority.value,
            f"{inv.priority_score:.1f}"
        )
    console.print(table)
