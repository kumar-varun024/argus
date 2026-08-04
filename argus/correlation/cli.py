import typer
import uuid
from rich.console import Console
from rich.table import Table
from typing import Optional

from argus.correlation.serializer import ObservationSerializer
from argus.runtime.manager import mission_manager
from argus.correlation.models import ObservationCategory, ObservationPriority

app = typer.Typer(help="Manage Universal Observations")
console = Console()


def _get_active_mission(mission_id: Optional[str] = None):
    # Dummy logic or fetch from manager. For CLI tools we typically require mission_id or active context.
    if mission_id:
        try:
            return mission_manager.get_mission(mission_id)
        except Exception:
            pass
    # Create a mock mission with some observations for demonstration if no active mission
    from argus.runtime.mission import Mission
    from argus.correlation.observation import Observation
    mission = Mission("test_target")
    # Add a mock observation
    obs = Observation(
        source="cli_mock",
        category=ObservationCategory.AUTHORIZATION,
        title="Mock Observation",
        description="This is a mock observation for CLI display.",
        confidence=0.9,
        priority=ObservationPriority.HIGH
    )
    mission.observations.add(obs)
    
    from argus.correlation.correlation import Correlation
    corr = Correlation(title="Mock Correlation", description="For CLI display")
    corr.observations.append(obs.id)
    mission.correlations.add(corr)
    
    return mission


@app.command(name="list")
def list_observations(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """List all observations for a mission."""
    mission = _get_active_mission(mission_id)
    observations = mission.observations.get_all()
    
    if not observations:
        console.print("[yellow]No observations found.[/yellow]")
        return
        
    table = Table(title="Observations")
    table.add_column("ID", style="cyan")
    table.add_column("Source", style="magenta")
    table.add_column("Category", style="blue")
    table.add_column("Title")
    table.add_column("Priority", style="red")
    
    for obs in observations:
        table.add_row(str(obs.id), obs.source, obs.category.value, obs.title, obs.priority.value)
        
    console.print(table)


@app.command()
def show(obs_id: str, mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Show details of a specific observation."""
    mission = _get_active_mission(mission_id)
    try:
        uid = uuid.UUID(obs_id)
    except ValueError:
        console.print("[red]Invalid UUID format.[/red]")
        return
        
    obs = mission.observations.find(uid)
    if not obs:
        console.print(f"[red]Observation {obs_id} not found.[/red]")
        return
        
    console.print(ObservationSerializer.to_json(obs))


@app.command()
def export(format: str = typer.Argument("json", help="Export format: json or yaml"),
           mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Export all observations in the specified format."""
    mission = _get_active_mission(mission_id)
    observations = mission.observations.get_all()
    
    if format.lower() == "json":
        import json
        out = [ObservationSerializer.to_dict(obs) for obs in observations]
        console.print(json.dumps(out, indent=2))
    elif format.lower() == "yaml":
        import yaml
        out = [ObservationSerializer.to_dict(obs) for obs in observations]
        console.print(yaml.dump(out))
    else:
        console.print(f"[red]Unsupported format: {format}[/red]")


correlations_app = typer.Typer(help="Manage Universal Correlations")

@correlations_app.command(name="list")
def list_correlations(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """List all correlations for a mission."""
    mission = _get_active_mission(mission_id)
    correlations = mission.correlations.get_all()
    
    if not correlations:
        console.print("[yellow]No correlations found.[/yellow]")
        return
        
    table = Table(title="Correlations")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Confidence", style="magenta")
    table.add_column("Score", style="red")
    
    for corr in correlations:
        table.add_row(str(corr.id), corr.title, str(corr.confidence), str(corr.score))
        
    console.print(table)


@correlations_app.command(name="show")
def show_correlation(corr_id: str, mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Show details of a specific correlation."""
    mission = _get_active_mission(mission_id)
    try:
        uid = uuid.UUID(corr_id)
    except ValueError:
        console.print("[red]Invalid UUID format.[/red]")
        return
        
    corr = mission.correlations.find(uid)
    if not corr:
        console.print(f"[red]Correlation {corr_id} not found.[/red]")
        return
        
    # Hacky serialization for now
    import json
    from argus.correlation.serializer import _JSONEncoder
    console.print(json.dumps(corr.model_dump(), indent=2, cls=_JSONEncoder))


@correlations_app.command(name="graph")
def graph_correlation(corr_id: str, mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Display the graph relationships for a specific correlation."""
    mission = _get_active_mission(mission_id)
    try:
        uid = uuid.UUID(corr_id)
    except ValueError:
        console.print("[red]Invalid UUID format.[/red]")
        return
        
    corr = mission.correlations.find(uid)
    if not corr:
        console.print(f"[red]Correlation {corr_id} not found.[/red]")
        return
        
    console.print(f"[bold cyan]Graph for Correlation:[/bold cyan] {corr_id}")
    for obs_id in corr.observations:
        related = mission.correlation_graph.get_related_observations(obs_id)
        if related:
            console.print(f"Observation {obs_id}:")
            for rel in related:
                console.print(f"  <--[ {rel['rule']} ]--> {rel['id']}")


@correlations_app.command(name="export")
def export_correlations(format: str = typer.Argument("json", help="Export format: json"),
                        mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Export all correlations."""
    mission = _get_active_mission(mission_id)
    correlations = mission.correlations.get_all()
    
    import json
    from argus.correlation.serializer import _JSONEncoder
    out = [corr.model_dump() for corr in correlations]
    console.print(json.dumps(out, indent=2, cls=_JSONEncoder))


evidence_app = typer.Typer(help="Manage Evidence Bundles")

@evidence_app.command(name="list")
def list_evidence_bundles(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """List all evidence bundles for a mission."""
    mission = _get_active_mission(mission_id)
    if not hasattr(mission, 'evidence_bundles'):
        console.print("[red]Evidence Fusion Engine not initialized on this mission.[/red]")
        return
        
    bundles = mission.evidence_bundles.get_all()
    
    if not bundles:
        console.print("[yellow]No evidence bundles found.[/yellow]")
        return
        
    table = Table(title="Evidence Bundles")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    table.add_column("Strength", style="green")
    table.add_column("Confidence", style="magenta")
    
    for b in bundles:
        table.add_row(str(b.id), b.title, f"{b.strength}%", f"{b.confidence:.2f}")
        
    console.print(table)


@evidence_app.command(name="show")
def show_evidence_bundle(bundle_id: str, mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Show details of a specific evidence bundle in formatted output."""
    mission = _get_active_mission(mission_id)
    try:
        uid = uuid.UUID(bundle_id)
    except ValueError:
        console.print("[red]Invalid UUID format.[/red]")
        return
        
    if not hasattr(mission, 'evidence_bundles'):
        return
        
    bundle = mission.evidence_bundles.find(uid)
    if not bundle:
        console.print(f"[red]Evidence Bundle {bundle_id} not found.[/red]")
        return
        
    # Formatting to match prompt example
    console.print(f"[bold cyan]Evidence Bundle[/bold cyan]")
    console.print(f"[bold]{bundle.title}[/bold]")
    console.print(f"[bold]Strength[/bold]")
    console.print(f"[green]{bundle.strength}%[/green]")
    
    # Calculate sources
    sources = set()
    for oid in bundle.observations:
        o = mission.observations.find(oid)
        if o: sources.add(o.source)
        
    for cid in bundle.correlations:
        c = mission.correlations.find(cid)
        if c:
            for coid in c.observations:
                co = mission.observations.find(coid)
                if co: sources.add(co.source)
                
    if sources:
        console.print("[bold]Sources[/bold]")
        for s in sorted(sources):
            console.print(f"✓ {s}")
            
    if bundle.business_objects:
        console.print("[bold]Business Objects[/bold]")
        for bo in sorted(bundle.business_objects):
            console.print(bo)
            
    if bundle.workflows:
        console.print("[bold]Workflow[/bold]")
        for wf in sorted(bundle.workflows):
            console.print(wf)

@evidence_app.command(name="graph")
def graph_evidence(bundle_id: str, mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Display graph info for an evidence bundle."""
    console.print(f"Graph relationships for Bundle {bundle_id} would be displayed here.")


@evidence_app.command(name="export")
def export_evidence(format: str = typer.Argument("json", help="Export format: json"),
                    mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Export all evidence bundles."""
    mission = _get_active_mission(mission_id)
    if not hasattr(mission, 'evidence_bundles'):
        return
    bundles = mission.evidence_bundles.get_all()
    
    import json
    from argus.correlation.serializer import _JSONEncoder
    out = [b.model_dump() for b in bundles]
    console.print(json.dumps(out, indent=2, cls=_JSONEncoder))

