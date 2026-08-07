import typer
from rich.console import Console
from rich.table import Table
from argus.benchmark.framework import benchmark_framework

app = typer.Typer(help="Manage Benchmark Datasets")
console = Console()

@app.command()
def list():
    """Lists all registered datasets."""
    datasets = benchmark_framework.dataset_manager.list_datasets()
    if not datasets:
        console.print("[yellow]No datasets found.[/yellow]")
        return
        
    table = Table(title="Benchmark Datasets")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Target")
    
    for ds in datasets:
        table.add_row(ds.id, ds.name, ds.version, ds.target)
        
    console.print(table)

@app.command()
def show(dataset_id: str):
    """Shows details for a specific dataset."""
    dataset = benchmark_framework.dataset_manager.get_dataset(dataset_id)
    if not dataset:
        console.print(f"[red]Dataset {dataset_id} not found.[/red]")
        return
        
    console.print(f"[bold cyan]Dataset:[/bold cyan] {dataset.id}")
    console.print(f"[bold]Name:[/bold] {dataset.name}")
    console.print(f"[bold]Version:[/bold] {dataset.version}")
    console.print(f"[bold]Target:[/bold] {dataset.target}")
    console.print(f"[bold]Description:[/bold] {dataset.description}")

@app.command()
def validate(path: str):
    """Validates a dataset directory without importing it."""
    from argus.benchmark.datasets.validator import DatasetValidator
    valid, msg = DatasetValidator.validate_directory(path)
    if not valid:
        console.print(f"[red]Invalid dataset directory:[/red] {msg}")
    else:
        console.print("[green]Dataset directory structure is valid.[/green]")
        # Full validation
        try:
            from argus.benchmark.datasets.loader import DatasetLoader
            DatasetLoader.load(path)
            console.print("[green]Dataset schemas and content are fully valid.[/green]")
        except Exception as e:
            console.print(f"[red]Schema validation failed:[/red] {e}")

@app.command(name="import")
def import_dataset(path: str):
    """Imports a dataset and registers it as a runnable benchmark."""
    try:
        ds = benchmark_framework.dataset_manager.import_dataset(path)
        benchmark = benchmark_framework.register_dataset_as_benchmark(ds)
        console.print(f"[green]Successfully imported dataset '{ds.name}' and registered as benchmark '{benchmark.id}'.[/green]")
    except Exception as e:
        console.print(f"[red]Failed to import dataset:[/red] {e}")
