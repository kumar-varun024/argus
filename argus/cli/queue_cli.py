import typer
from rich.console import Console
from rich.panel import Panel

from argus.ai.models import ResearchCard, ResearchCardPriority, ResearchCardCategory
from argus.reporting.queue import ResearchQueue

app = typer.Typer(help="Manage Investigation Queue")
console = Console()

@app.command()
def list(mission_id: str = typer.Argument(default="dummy", help="Mission ID to view queue for")):
    """List prioritized investigation tasks for a mission"""
    
    # In a real scenario, we would load the mission by ID.
    # For now, we instantiate a mock queue to demonstrate the rendering.
    queue = ResearchQueue()
    
    if mission_id == "dummy":
        # Mock some data to show the CLI works
        card = ResearchCard(
            title="Organization Authorization",
            summary="Verify authorization boundaries for organization patching",
            category=ResearchCardCategory.AUTHORIZATION,
            priority=ResearchCardPriority.HIGH,
            business_object="Organization",
            authentication="OAuth2",
            related_endpoints=["PATCH /organizations/{id}"],
            related_evidence=["role management UI"],
            reasoning=[
                "The endpoint modifies Organization resources.",
                "Authorization boundaries exist.",
                "Manual authorization verification is recommended."
            ],
            recommended_manual_steps=[
                "Create two users with different roles.",
                "Attempt to update another organization.",
                "Observe HTTP status, Response body, Object ownership, Audit logs."
            ],
            confidence=0.85
        )
        queue.add(card)
        queue.sort_by_priority()
        
    console.print("\n[bold cyan]======================================================[/bold cyan]")
    console.print("[bold cyan]INVESTIGATION QUEUE[/bold cyan]")
    console.print("[bold cyan]======================================================[/bold cyan]\n")

    pending_cards = queue.pending()
    if not pending_cards:
        console.print("[yellow]No pending investigations in the queue.[/yellow]")
        return
        
    for card in pending_cards:
        color = "green"
        if card.priority == ResearchCardPriority.CRITICAL:
            color = "red"
        elif card.priority == ResearchCardPriority.HIGH:
            color = "yellow"
        elif card.priority == ResearchCardPriority.MEDIUM:
            color = "blue"
            
        console.print(f"[{color}][{card.priority.value.upper()}][/{color}]\n")
        console.print(f"[bold]{card.title}[/bold]\n")
        
        console.print("[bold]Reason:[/bold]")
        for reason in card.reasoning:
            console.print(f"- {reason}")
        console.print()
        
        console.print("[bold]Manual Verification:[/bold]")
        for step in card.recommended_manual_steps:
            console.print(f"- {step}")
        console.print()
        
        console.print(f"[bold]Confidence:[/bold] {card.confidence}")
        
        if card.related_evidence:
            console.print("\n[bold]Evidence:[/bold]")
            for ev in card.related_evidence:
                console.print(f"- {ev}")
                
        console.print("\n" + "-"*54 + "\n")
