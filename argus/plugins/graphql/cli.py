import typer
from rich.console import Console

from argus.plugins.graphql.agent import GraphQLSpecialist

app = typer.Typer(help="Manage GraphQL Intelligence")
console = Console()

@app.command()
def discover(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Discover GraphQL endpoints."""
    specialist = GraphQLSpecialist()
    
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
        mission.endpoints = [{"url": "/graphql", "method": "POST"}]
        mission.evidence.add(Evidence(category="JavaScript", value="ApolloClient", source="/static/main.js"))
    
    specialist.discover(mission)
    
    endpoints = getattr(mission, "graphql", None)
    if endpoints and endpoints.endpoints:
        console.print("\n[bold green]Discovered GraphQL Endpoints[/bold green]\n")
        
        for ep in endpoints.endpoints:
            console.print(f"• [cyan]{ep.url}[/cyan]")
            console.print(f"Confidence: {ep.confidence:.2f}")
            console.print("\nEvidence:")
            for ev in ep.evidence:
                console.print(f"[dim]{ev.source}[/dim] - {ev.category}")
            console.print()
    else:
        console.print("[yellow]No GraphQL endpoints discovered.[/yellow]")

@app.command()
def schema():
    """Display GraphQL schemas."""
    console.print("[cyan]Displaying GraphQL schemas (Placeholder)...[/cyan]")

@app.command()
def graph():
    """Display GraphQL relationship graph."""
    console.print("[cyan]Displaying GraphQL relationship graph (Placeholder)...[/cyan]")

@app.command()
def explain():
    """Explain a GraphQL finding."""
    console.print("[cyan]Explaining GraphQL finding (Placeholder)...[/cyan]")

@app.command()
def investigations():
    """List GraphQL investigations."""
    console.print("[cyan]Listing GraphQL investigations (Placeholder)...[/cyan]")
