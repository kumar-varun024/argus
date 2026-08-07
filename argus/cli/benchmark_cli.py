import typer
import json
from rich.console import Console
from rich.table import Table

from argus.benchmark.framework import benchmark_framework

app = typer.Typer(help="Manage and Run Argus Benchmarks")
console = Console()

@app.command()
def list():
    """Lists all registered benchmarks."""
    benchmarks = benchmark_framework.list_benchmarks()
    if not benchmarks:
        console.print("[yellow]No benchmarks found.[/yellow]")
        return
        
    table = Table(title="Argus Benchmarks")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Target")
    
    for b in benchmarks:
        table.add_row(b.id, b.name, b.category, b.target)
        
    console.print(table)

@app.command()
def run(benchmark_id: str):
    """Runs a specific benchmark."""
    try:
        console.print(f"[bold cyan]Starting Benchmark:[/bold cyan] {benchmark_id}")
        result = benchmark_framework.run_benchmark(benchmark_id)
        
        console.print("\n[bold green]Benchmark Completed[/bold green]")
        
        table = Table(title=f"Metrics: {benchmark_id}")
        table.add_column("Metric")
        table.add_column("Value")
        
        table.add_row("Investigation Recall", f"{result.metrics.investigation_recall:.2f}")
        table.add_row("Hypothesis Recall", f"{result.metrics.hypothesis_recall:.2f}")
        table.add_row("Correlation Recall", f"{result.metrics.correlation_recall:.2f}")
        table.add_row("Evidence Recall", f"{result.metrics.evidence_recall:.2f}")
        table.add_row("Technology Recall", f"{result.metrics.technology_recall:.2f}")
        table.add_row("Business Object Recall", f"{result.metrics.business_object_recall:.2f}")
        table.add_row("Execution Time (ms)", f"{result.metrics.total_execution_time_ms:.2f}")
        
        console.print(table)
        
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
    except Exception as e:
        console.print(f"[red]Benchmark Execution Failed:[/red] {e}")

@app.command()
def show(benchmark_id: str):
    """Shows details about a specific benchmark."""
    benchmark = benchmark_framework.registry.get(benchmark_id)
    if not benchmark:
        console.print(f"[red]Benchmark {benchmark_id} not found.[/red]")
        return
        
    console.print(f"[bold cyan]Benchmark Details:[/bold cyan] {benchmark.id}")
    console.print(f"[bold]Name:[/bold] {benchmark.name}")
    console.print(f"[bold]Description:[/bold] {benchmark.description}")
    console.print(f"[bold]Category:[/bold] {benchmark.category}")
    console.print(f"[bold]Target:[/bold] {benchmark.target}")

@app.command()
def metrics(benchmark_id: str):
    """Shows raw metrics logic and values for a benchmark."""
    # Placeholder for a command that would pull from a saved run or re-run
    console.print(f"[yellow]Metrics tracking for {benchmark_id}.[/yellow] Run the benchmark first to generate metrics.")

@app.command()
def score(benchmark_id: str):
    """Shows the normalized scorecard for a benchmark."""
    # Placeholder to show scores. In a real scenario we'd query the registry or DB for the last run
    console.print(f"[yellow]Scorecard for {benchmark_id}.[/yellow] Run the benchmark first to generate scores.")

@app.command()
def coverage(benchmark_id: str):
    """Shows coverage reports against ground truth."""
    console.print(f"[yellow]Coverage for {benchmark_id}.[/yellow] Run the benchmark first to generate coverage.")

@app.command()
def performance(benchmark_id: str):
    """Shows mission profiling and performance results."""
    console.print(f"[yellow]Performance for {benchmark_id}.[/yellow] Run the benchmark first to generate performance data.")

from argus.cli.dataset_cli import app as dataset_app
app.add_typer(dataset_app, name="datasets")

from argus.cli.ground_truth_cli import app as gt_app
app.add_typer(gt_app, name="ground-truth")
