import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from argus.knowledge.manager import KnowledgeManager
from argus.knowledge.models import KnowledgeCategory

app = typer.Typer(help="Manage Argus Knowledge Base")
console = Console()
manager = KnowledgeManager()

@app.command()
def search(keyword: str):
    """Search knowledge base by keyword"""
    results = manager.search(keyword=keyword)
    if not results:
        console.print("[yellow]No knowledge entries found.[/yellow]")
        return
        
    table = Table(title=f"Search Results for '{keyword}'")
    table.add_column("ID", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Title")
    
    for entry in results:
        table.add_row(entry.id[:8], entry.category.value, entry.title)
        
    console.print(table)

@app.command()
def show(entry_id: str):
    """Show details of a specific knowledge entry"""
    # Simple prefix search for convenience
    entry = None
    for k, v in manager._entries.items():
        if k.startswith(entry_id):
            entry = v
            break
            
    if not entry:
        console.print(f"[red]Entry {entry_id} not found.[/red]")
        return
        
    content = f"[bold]Title:[/bold] {entry.title}\n"
    content += f"[bold]Category:[/bold] {entry.category.value}\n"
    content += f"[bold]Tags:[/bold] {', '.join(entry.tags)}\n\n"
    content += f"[bold]Description:[/bold]\n{entry.description}"
    
    console.print(Panel(content, title=f"Knowledge Entry: {entry.id}", border_style="green"))

@app.command()
def list(category: str):
    """List knowledge entries by category"""
    results = manager.filter_by_category(category)
    if not results:
        console.print(f"[yellow]No entries found for category '{category}'.[/yellow]")
        return
        
    table = Table(title=f"Knowledge Base: {category}")
    table.add_column("ID", style="cyan")
    table.add_column("Title")
    
    for entry in results:
        table.add_row(entry.id[:8], entry.title)
        
    console.print(table)

@app.command()
def stats():
    """Show statistics about the knowledge base"""
    total = len(manager._entries)
    
    counts = {}
    for entry in manager._entries.values():
        counts[entry.category.value] = counts.get(entry.category.value, 0) + 1
        
    table = Table(title="Knowledge Base Stats")
    table.add_column("Category", style="magenta")
    table.add_column("Count", justify="right")
    
    for cat, count in sorted(counts.items()):
        table.add_row(cat, str(count))
        
    table.add_row("[bold]Total[/bold]", f"[bold]{total}[/bold]")
    console.print(table)
