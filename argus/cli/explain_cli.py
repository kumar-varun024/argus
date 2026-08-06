import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import uuid
import json

from argus.correlation.cli import _get_active_mission
from argus.explain.engine import ExplainabilityEngine
from argus.explain.export import ExplanationExporter

console = Console()
app = typer.Typer(help="Explainability Engine Commands")

def _get_explanation(inv_id: str, mission_id: str):
    mission = _get_active_mission(mission_id)
    if not hasattr(mission, 'investigations'):
        console.print("[red]Investigation Builder not initialized.[/red]")
        raise typer.Exit(1)
        
    try:
        uid = uuid.UUID(inv_id)
        inv = mission.investigations.find(uid)
    except Exception:
        inv = None
        
    if not inv:
        console.print(f"[red]Investigation {inv_id} not found.[/red]")
        raise typer.Exit(1)
        
    # Check if already explained in mission
    if hasattr(mission, 'explanations') and str(inv.id) in mission.explanations:
        return mission.explanations[str(inv.id)]
        
    engine = ExplainabilityEngine(mission)
    return engine.generate_explanation(inv)

@app.command("summary")
def explain_summary(inv_id: str, mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Show the summary reasoning chain and breakdowns for an investigation."""
    explanation = _get_explanation(inv_id, mission_id)
    
    console.print(f"[bold cyan]Investigation:[/bold cyan] {explanation.title}")
    
    console.print("\n[bold]Reasoning Chain[/bold]")
    for step in explanation.reasoning_chain:
        console.print(f"- [yellow]{step.source_type}[/yellow]: {step.description}")
        
    if explanation.priority_breakdown:
        console.print("\n[bold]Priority Breakdown[/bold]")
        table = Table(show_header=False, box=None)
        for k, v in explanation.priority_breakdown.items():
            table.add_row(k, f"{v:.2f}")
        console.print(table)
        
    if explanation.confidence_breakdown:
        console.print("\n[bold]Confidence Breakdown[/bold]")
        table = Table(show_header=False, box=None)
        for k, v in explanation.confidence_breakdown.items():
            table.add_row(k, f"{v:.2f}")
        console.print(table)
        
    if explanation.manual_validation:
        console.print("\n[bold]Manual Validation Recommended[/bold]")
        console.print(explanation.manual_validation)

@app.command("graph")
def explain_graph(inv_id: str, mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Show the explanation graph."""
    explanation = _get_explanation(inv_id, mission_id)
    graph = explanation.explanation_graph
    
    console.print(f"[bold cyan]Explanation Graph for {explanation.title}[/bold cyan]\n")
    console.print(f"Nodes: {len(graph.nodes)}")
    console.print(f"Edges: {len(graph.edges)}\n")
    
    table = Table(title="Graph Edges")
    table.add_column("Source Node")
    table.add_column("Relationship", style="magenta")
    table.add_column("Target Node")
    
    # Helper to get node label
    def get_label(nid: str):
        for n in graph.nodes:
            if n.id == nid:
                return f"[{n.node_type}] {n.label}"
        return nid
        
    for edge in graph.edges:
        table.add_row(get_label(edge.source), edge.relationship, get_label(edge.target))
        
    console.print(table)

@app.command("timeline")
def explain_timeline(inv_id: str, mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Show the chronological timeline of events."""
    explanation = _get_explanation(inv_id, mission_id)
    
    console.print(f"[bold cyan]Timeline for {explanation.title}[/bold cyan]\n")
    
    table = Table(show_header=True)
    table.add_column("Timestamp", style="green")
    table.add_column("Event Type", style="blue")
    table.add_column("Description")
    
    for event in explanation.timeline:
        ts = event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
        table.add_row(ts, event.event_type, event.description)
        
    console.print(table)

@app.command("export")
def explain_export(
    inv_id: str, 
    format: str = typer.Option("json", "--format", "-f", help="Export format: json, markdown, html, graph"),
    mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")
):
    """Export the explanation in various formats."""
    explanation = _get_explanation(inv_id, mission_id)
    exporter = ExplanationExporter()
    
    if format == "json":
        out = exporter.to_json(explanation)
    elif format == "markdown":
        out = exporter.to_markdown(explanation)
    elif format == "html":
        out = exporter.to_html(explanation)
    elif format == "graph":
        out = exporter.to_graph_json(explanation)
    else:
        console.print(f"[red]Unsupported format '{format}'.[/red]")
        raise typer.Exit(1)
        
    console.print(out)
