import typer
import webbrowser
from rich.console import Console
from rich.panel import Panel

app = typer.Typer(help="Manage the Argus Multimodal Conversational Workspace.")
console = Console()

@app.command()
def start(
    host: str = typer.Option("127.0.0.1", "--host", help="Host interface to bind to."),
    port: int = typer.Option(8000, "--port", help="Port to run the workspace on."),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not automatically open the browser.")
):
    """Starts the conversational AI workspace web server."""
    from argus.workspace.web.app import start_server
    
    url = f"http://{host}:{port}"
    console.print(f"[bold green]Starting Argus Workspace at:[/bold green] {url}")
    
    if not no_browser:
        console.print("[cyan]Opening browser...[/cyan]")
        webbrowser.open(url)
        
    start_server(host=host, port=port)

@app.command(name="context-inspect")
def context_inspect(
    conversation_id: str = typer.Argument(..., help="The ID of the conversation to inspect."),
):
    """Debugs the Research Context Engine assembly for a specific conversation."""
    from argus.workspace.repository import ConversationRepository
    from argus.workspace.context.engine import ResearchContextEngine
    from argus.workspace.context.models import ContextQuery
    
    repo = ConversationRepository()
    conv = repo.get(conversation_id)
    
    if not conv:
        console.print(f"[bold red]Error:[/bold red] Conversation {conversation_id} not found.")
        raise typer.Exit(1)
        
    latest_msg = conv.messages[-1] if conv.messages else None
    query_text = latest_msg.text if latest_msg else ""
    
    query = ContextQuery(
        conversation_id=conv.conversation_id,
        query=query_text,
        mission_id=conv.mission_id,
        project_id=conv.project_id
    )
    
    engine = ResearchContextEngine()
    
    console.print(Panel(f"Query: {query_text}\nMission: {conv.mission_id}", title="Context Query"))
    
    # 1. Retrieve raw sources
    raw_sources = engine._retrieve_sources(query)
    
    # 2. Filter
    allowed_sources = engine.policy.apply(query, raw_sources)
    excluded = len(raw_sources) - len(allowed_sources)
    
    # 3. Rank
    ranked_sources = engine.ranker.rank(query, allowed_sources)
    
    console.print(f"[bold cyan]Retrieved:[/bold cyan] {len(raw_sources)} | [bold yellow]Filtered:[/bold yellow] {excluded} | [bold green]Ranked:[/bold green] {len(ranked_sources)}")
    
    for s in ranked_sources:
        console.print(f"- [bold]{s.relevance_score}[/bold] | {s.semantic_status} | {s.title} ({s.relevance_reason})")
        
    # Assemble
    final_context = engine.resolve_context(query)
    console.print("\n[bold]Final Assembled Context:[/bold]")
    console.print(Panel(final_context))

