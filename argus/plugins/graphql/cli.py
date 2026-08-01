import typer
from rich.console import Console

from argus.plugins.graphql.agent import GraphQLSpecialist

app = typer.Typer(help="Manage GraphQL Intelligence")
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
        mission.endpoints = [{"url": "/graphql", "method": "POST"}]
        mission.evidence.add(Evidence(category="JavaScript", value="ApolloClient", source="/static/main.js"))
        mission.evidence.add(Evidence(category="HTTP Request", value="query { user { id } }", source="/graphql"))
        mission.evidence.add(Evidence(category="HTTP Request", value="mutation { updateUser(id: 1) { id } }", source="/graphql"))
        mission.evidence.add(Evidence(category="HTTP Response", value='{"data": {"__typename": "User"}}', source="/graphql"))
    return mission

@app.command()
def discover(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Discover GraphQL endpoints."""
    specialist = GraphQLSpecialist()
    mission = _get_or_mock_mission(mission_id)
    
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
def schema(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Display GraphQL schemas."""
    mission = _get_or_mock_mission(mission_id)
    specialist = GraphQLSpecialist()
    specialist.discover(mission)
    
    graphql = getattr(mission, "graphql", None)
    if graphql and graphql.schemas:
        console.print("\n[bold green]Schema[/bold green]\n")
        
        objects_count = len(graphql.types)
        queries_count = sum(1 for op in graphql.operations if op.operation_type == "Query")
        mutations_count = sum(1 for op in graphql.operations if op.operation_type == "Mutation")
        subscriptions_count = sum(1 for op in graphql.operations if op.operation_type == "Subscription")
        enums_count = len(graphql.enums)
        interfaces_count = len(graphql.interfaces)
        
        console.print(f"Objects:\n{objects_count}\n")
        console.print(f"Queries:\n{queries_count}\n")
        console.print(f"Mutations:\n{mutations_count}\n")
        console.print(f"Subscriptions:\n{subscriptions_count}\n")
        console.print(f"Enums:\n{enums_count}\n")
        console.print(f"Interfaces:\n{interfaces_count}\n")
    else:
        console.print("[yellow]No GraphQL schemas discovered.[/yellow]")

@app.command()
def types(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Display GraphQL types."""
    mission = _get_or_mock_mission(mission_id)
    specialist = GraphQLSpecialist()
    specialist.discover(mission)
    
    graphql = getattr(mission, "graphql", None)
    if graphql and graphql.types:
        console.print("\n[bold green]GraphQL Types[/bold green]\n")
        for t_name, t_obj in graphql.types.items():
            console.print(f"• [cyan]{t_name}[/cyan] ({t_obj.kind})")
    else:
        console.print("[yellow]No GraphQL types discovered.[/yellow]")

@app.command()
def operations(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Display GraphQL operations."""
    mission = _get_or_mock_mission(mission_id)
    specialist = GraphQLSpecialist()
    specialist.discover(mission)
    
    graphql = getattr(mission, "graphql", None)
    if graphql and graphql.operations:
        console.print("\n[bold green]GraphQL Operations[/bold green]\n")
        for op in graphql.operations:
            console.print(f"• [cyan]{op.name}[/cyan] ({op.operation_type})")
    else:
        console.print("[yellow]No GraphQL operations discovered.[/yellow]")

@app.command()
def relationships(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Display GraphQL relationships."""
    mission = _get_or_mock_mission(mission_id)
    specialist = GraphQLSpecialist()
    specialist.discover(mission)
    
    graphql = getattr(mission, "graphql", None)
    if graphql and graphql.relationships:
        console.print("\n[bold green]Relationships[/bold green]\n")
        for rel in graphql.relationships:
            console.print(f"• [cyan]{rel.parent}[/cyan] [bold]{rel.type}[/bold] [cyan]{rel.child}[/cyan]")
    else:
        console.print("[yellow]No GraphQL relationships discovered.[/yellow]")

@app.command()
def workflows(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Display GraphQL workflows."""
    mission = _get_or_mock_mission(mission_id)
    specialist = GraphQLSpecialist()
    specialist.discover(mission)
    
    graphql = getattr(mission, "graphql", None)
    if graphql and graphql.workflows:
        console.print("\n[bold green]Workflows[/bold green]\n")
        for wf in graphql.workflows:
            steps = " [bold]↓[/bold] ".join([f"[cyan]{node.name}[/cyan]" for node in wf.states])
            console.print(f"[bold]{wf.name}[/bold]\n{steps}\n")
    else:
        console.print("[yellow]No GraphQL workflows discovered.[/yellow]")

@app.command()
def business_objects(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """Display GraphQL business objects."""
    mission = _get_or_mock_mission(mission_id)
    specialist = GraphQLSpecialist()
    specialist.discover(mission)
    
    graphql = getattr(mission, "graphql", None)
    if graphql and graphql.business_objects:
        console.print("\n[bold green]Business Objects[/bold green]\n")
        for bo in graphql.business_objects:
            console.print(f"• [cyan]{bo.name}[/cyan]")
    else:
        console.print("[yellow]No GraphQL business objects discovered.[/yellow]")

@app.command()
def investigations(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """List GraphQL investigations."""
    mission = _get_or_mock_mission(mission_id)
    specialist = GraphQLSpecialist()
    specialist.discover(mission)
    specialist.generate_investigations(mission)
    
    graphql = getattr(mission, "graphql", None)
    if graphql and graphql.investigations:
        console.print("\n[bold green]Investigations[/bold green]\n")
        for inv in graphql.investigations:
            console.print(f"[bold]{inv.title}[/bold] (ID: {inv.id})")
            console.print(f"Priority: [magenta]{inv.priority}[/magenta] | Confidence: {inv.confidence:.2f}")
            console.print(f"{inv.reasoning}\n")
    else:
        console.print("[yellow]No GraphQL investigations generated.[/yellow]")

@app.command()
def explain(investigation_id: str):
    """Explain a GraphQL finding."""
    # Since we don't have persistent state here easily without full DB, 
    # we'd normally query it. For CLI demo we mock it if not found.
    mission = _get_or_mock_mission()
    specialist = GraphQLSpecialist()
    specialist.discover(mission)
    specialist.generate_investigations(mission)
    
    graphql = getattr(mission, "graphql", None)
    if graphql and graphql.investigations:
        for inv in graphql.investigations:
            if inv.id == investigation_id or investigation_id == "mock":
                console.print(f"\n[bold green]Investigation: {inv.title}[/bold green]\n")
                console.print(f"[bold]Priority:[/bold] {inv.priority}")
                console.print(f"[bold]Confidence:[/bold] {inv.confidence * 100:.0f}%")
                console.print(f"[bold]Reason:[/bold]\n{inv.reasoning}\n")
                
                console.print("[bold]Evidence:[/bold]")
                for ev in inv.evidence:
                    console.print(f"✓ {ev}")
                
                if inv.business_objects:
                    console.print(f"\n[bold]Business Objects:[/bold] {', '.join(inv.business_objects)}")
                    
                console.print(f"\n[bold]Manual Validation:[/bold]\n{inv.manual_validation_guidance}\n")
                return
                
    console.print(f"[yellow]Investigation {investigation_id} not found.[/yellow]")

@app.command()
def priority(mission_id: str = typer.Option(None, "--mission", "-m", help="Mission ID")):
    """List investigations by priority."""
    mission = _get_or_mock_mission(mission_id)
    specialist = GraphQLSpecialist()
    specialist.discover(mission)
    specialist.generate_investigations(mission)
    
    graphql = getattr(mission, "graphql", None)
    if graphql and hasattr(graphql, "priority_queue") and graphql.priority_queue:
        console.print("\n[bold green]Priority Queue[/bold green]\n")
        for inv in graphql.priority_queue:
            console.print(f"[{inv.priority}] {inv.title} ({inv.confidence:.2f})")
    else:
        console.print("[yellow]No GraphQL investigations in priority queue.[/yellow]")
