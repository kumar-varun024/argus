import typer
from rich.console import Console
from rich.table import Table
import uuid

from argus.correlation.cli import _get_active_mission
from argus.hypothesis.ranking import HypothesisRanker

console = Console()
hypothesis_app = typer.Typer(help="Manage Research Hypotheses")

@hypothesis_app.command(name="list")
def list_hypotheses(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """List all hypotheses for a mission."""
    mission = _get_active_mission(mission_id)
    if not hasattr(mission, 'hypotheses'):
        console.print("[red]Hypothesis Engine not initialized.[/red]")
        return
        
    hyps = mission.hypotheses.get_all()
    if not hyps:
        console.print("[yellow]No hypotheses found.[/yellow]")
        return
        
    ranked = HypothesisRanker.rank(hyps)
        
    table = Table(title="Hypotheses Queue")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Category", style="blue")
    table.add_column("Status", style="green")
    table.add_column("Priority", style="red")
    table.add_column("Confidence", style="magenta")
    
    for hyp in ranked:
        table.add_row(
            str(hyp.id)[:8],
            hyp.title,
            hyp.category.value,
            hyp.status.value,
            hyp.priority.value,
            f"{int(hyp.confidence * 100)}%"
        )
        
    console.print(table)

@hypothesis_app.command(name="show")
def show_hypothesis(hyp_id: str, mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Show details of a specific hypothesis."""
    mission = _get_active_mission(mission_id)
    if not hasattr(mission, 'hypotheses'):
        return
        
    try:
        if len(hyp_id) == 8:
            # Prefix match
            found = [h for h in mission.hypotheses.get_all() if str(h.id).startswith(hyp_id)]
            if not found:
                console.print(f"[red]Hypothesis starting with {hyp_id} not found.[/red]")
                return
            hyp = found[0]
        else:
            uid = uuid.UUID(hyp_id)
            hyp = mission.hypotheses.find(uid)
            if not hyp:
                console.print(f"[red]Hypothesis {hyp_id} not found.[/red]")
                return
    except ValueError:
        console.print("[red]Invalid UUID format.[/red]")
        return
        
    console.print("[bold cyan]Hypothesis Details[/bold cyan]")
    console.print(f"[bold]Title:[/bold] {hyp.title}")
    console.print(f"[bold]Status:[/bold] {hyp.status.value}")
    console.print(f"[bold]Category:[/bold] {hyp.category.value}")
    console.print(f"[bold]Priority:[/bold] {hyp.priority.value} ({hyp.priority_score:.1f})")
    console.print(f"[bold]Confidence:[/bold] {int(hyp.confidence * 100)}%")
    console.print(f"[bold]Description:[/bold] {hyp.description}")
    console.print(f"\n[bold]Reasoning:[/bold] {hyp.reason}")
    
    if hyp.business_objects:
        console.print(f"\n[bold]Business Objects:[/bold] {', '.join(hyp.business_objects)}")
    if hyp.workflows:
        console.print(f"[bold]Workflows:[/bold] {', '.join(hyp.workflows)}")
    if hyp.related_endpoints:
        console.print(f"[bold]Endpoints:[/bold] {', '.join(hyp.related_endpoints)}")

@hypothesis_app.command(name="explain")
def explain_hypothesis(hyp_id: str, mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Show manual validation steps and reasoning for a hypothesis."""
    mission = _get_active_mission(mission_id)
    if not hasattr(mission, 'hypotheses'):
        return
        
    try:
        if len(hyp_id) == 8:
            found = [h for h in mission.hypotheses.get_all() if str(h.id).startswith(hyp_id)]
            hyp = found[0] if found else None
        else:
            uid = uuid.UUID(hyp_id)
            hyp = mission.hypotheses.find(uid)
    except Exception:
        hyp = None
        
    if not hyp:
        console.print(f"[red]Hypothesis {hyp_id} not found.[/red]")
        return
        
    console.print(f"[bold cyan]Reasoning for Hypothesis:[/bold cyan] {hyp.title}")
    console.print(hyp.reason)
    console.print("\n[bold cyan]Manual Validation Steps:[/bold cyan]")
    console.print(hyp.manual_validation)

@hypothesis_app.command(name="history")
def show_hypothesis_history(hyp_id: str, mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Show the lifecycle history of a hypothesis."""
    mission = _get_active_mission(mission_id)
    if not hasattr(mission, 'hypotheses'):
        return
        
    try:
        if len(hyp_id) == 8:
            found = [h for h in mission.hypotheses.get_all() if str(h.id).startswith(hyp_id)]
            hyp = found[0] if found else None
        else:
            uid = uuid.UUID(hyp_id)
            hyp = mission.hypotheses.find(uid)
    except Exception:
        hyp = None
        
    if not hyp:
        console.print(f"[red]Hypothesis {hyp_id} not found.[/red]")
        return
        
    table = Table(title=f"History: {hyp.title}")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Confidence", style="magenta")
    table.add_column("Reason")
    
    for entry in hyp.history:
        table.add_row(
            entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            entry.status.value,
            f"{int(entry.confidence * 100)}%",
            entry.reason
        )
        
    console.print(table)
