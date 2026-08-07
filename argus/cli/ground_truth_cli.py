import typer
from rich.console import Console
from rich.table import Table
from argus.benchmark.framework import benchmark_framework

app = typer.Typer(help="Manage Benchmark Ground Truth")
console = Console()

@app.command()
def show(dataset_id: str):
    """Shows the ground truth expectations for a dataset."""
    dataset = benchmark_framework.dataset_manager.get_dataset(dataset_id)
    if not dataset:
        console.print(f"[red]Dataset {dataset_id} not found.[/red]")
        return
        
    console.print(f"[bold cyan]Ground Truth for Dataset:[/bold cyan] {dataset.id}")
    table = Table(title="Expectations")
    table.add_column("Category", style="cyan")
    table.add_column("Expected Count")
    
    gt = dataset.ground_truth
    for k, v in gt.items():
        if isinstance(v, list) and len(v) > 0:
            table.add_row(k, str(len(v)))
            
    console.print(table)

@app.command()
def matches(benchmark_id: str):
    """Displays matches from the last benchmark run (mock)."""
    console.print(f"Run `argus benchmark run {benchmark_id}` to see actual matches during evaluation.")

@app.command()
def misses(benchmark_id: str):
    """Displays misses from the last benchmark run (mock)."""
    console.print(f"Run `argus benchmark run {benchmark_id}` to see actual misses during evaluation.")
