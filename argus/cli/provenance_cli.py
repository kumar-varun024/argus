import typer
import json
from rich.console import Console
from rich.table import Table

from argus.provenance.engine import provenance_engine

app = typer.Typer(help="Manage and analyze Evidence Provenance")
console = Console()

@app.command()
def explain(artifact_id: str):
    """Outputs a human-readable text trace explaining the given artifact's lineage."""
    console.print(f"\n[bold cyan]Provenance Trace for:[/bold cyan] {artifact_id}\n")
    explanation = provenance_engine.explain(artifact_id)
    console.print(explanation)
    console.print("\n")

@app.command()
def trace(artifact_id: str):
    """Outputs a structured JSON of the provenance graph for an artifact."""
    data = provenance_engine.trace(artifact_id)
    console.print(json.dumps(data, indent=2))

@app.command()
def stats():
    """Displays the total number of traced artifacts, missing links, and overall provenance health."""
    stats_data = provenance_engine.get_stats()
    
    table = Table(title="Provenance Health Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="magenta")
    
    table.add_row("Total Artifacts Tracked", str(stats_data["total_artifacts"]))
    
    unsupported = stats_data["unsupported_artifacts"]
    unsupported_style = "red" if unsupported > 0 else "green"
    table.add_row("Unsupported/Black Box Artifacts", f"[{unsupported_style}]{unsupported}[/{unsupported_style}]")
    
    health_pct = 100.0
    if stats_data["total_artifacts"] > 0:
        health_pct = ((stats_data["total_artifacts"] - unsupported) / stats_data["total_artifacts"]) * 100
        
    health_style = "green" if health_pct == 100.0 else "yellow"
    table.add_row("Overall Provenance Health", f"[{health_style}]{health_pct:.2f}%[/{health_style}]")
    
    console.print(table)
