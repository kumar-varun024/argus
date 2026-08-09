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
def run(
    dataset_or_id: str = typer.Argument(None, help="The benchmark ID or dataset to run"),
    suite: bool = typer.Option(False, "--suite", help="Run the entire benchmark suite"),
    parallel: bool = typer.Option(False, "--parallel", help="Run benchmarks in parallel"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate execution without running missions")
):
    """Runs a benchmark, a dataset, or the entire suite."""
    try:
        if suite:
            console.print("[bold cyan]Starting Benchmark Suite...[/bold cyan]")
            results = benchmark_framework.runner.run_suite(parallel=parallel, dry_run=dry_run)
            for res in results:
                console.print(f"[green]Completed:[/green] {res.benchmark_id} - Score: {res.score.overall_score if res.score else 'N/A'}")
            return

        if not dataset_or_id:
            console.print("[red]Must provide a benchmark ID or use --suite.[/red]")
            return

        console.print(f"[bold cyan]Starting Benchmark:[/bold cyan] {dataset_or_id}")
        result = benchmark_framework.run_benchmark(dataset_or_id, dry_run=dry_run)
        
        console.print("\n[bold green]Benchmark Evaluation Completed[/bold green]")
        
        table = Table(title=f"Evaluation: {dataset_or_id}")
        table.add_column("Category")
        table.add_column("Score")
        
        if result.score:
            table.add_row("Overall Score", f"{result.score.overall_score:.2f}")
            table.add_row("Coverage", f"{result.coverage.api_coverage if result.coverage else 0:.2f}")
            table.add_row("Quality", f"{result.quality.investigation_quality if result.quality else 0:.2f}")
        
        table.add_row("Runtime (ms)", f"{result.runtime:.2f}")
        
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

@app.command()
def history(benchmark_id: str):
    """Shows trend analysis and execution history for a benchmark."""
    trend = benchmark_framework.runner.get_trend(benchmark_id)
    if "status" in trend and trend["status"] == "No history available":
        console.print(f"[yellow]No history available for {benchmark_id}.[/yellow]")
        return
        
    console.print(f"[bold cyan]History for {benchmark_id}[/bold cyan]")
    table = Table()
    table.add_column("Metric")
    table.add_column("Value")
    for k, v in trend.items():
        table.add_row(k.replace("_", " ").title(), str(v))
    console.print(table)

@app.command()
def rerun(benchmark_id: str):
    """Reruns the most recently executed benchmark."""
    # Simple alias for run. Could be extended to grab the last from history.
    console.print(f"[bold cyan]Rerunning...[/bold cyan]")
    run(dataset_or_id=benchmark_id)

@app.command()
def status():
    """Shows the status of the evaluation runner registry."""
    status_dict = benchmark_framework.runner.get_status()
    console.print("[bold cyan]Runner Status[/bold cyan]")
    for k, v in status_dict.items():
        console.print(f"{k.replace('_', ' ').title()}: {v}")

@app.command()
def report(
    evaluation_id: str,
    format: str = typer.Option("markdown", "--format", help="Output format (json, markdown, html, pdf)"),
    compare: str = typer.Option(None, "--compare", help="Compare with another evaluation ID")
):
    """Generates a reproducible benchmark report for an evaluation."""
    from argus.benchmark.reports.generator import ReportGenerator
    from argus.benchmark.reports.json import JSONRenderer
    from argus.benchmark.reports.markdown import MarkdownRenderer
    from argus.benchmark.reports.html import HTMLRenderer
    from argus.benchmark.reports.pdf import PDFRenderer
    import os
    
    # 1. Fetch EvaluationResult from Registry
    result = benchmark_framework.runner.registry.get(evaluation_id)
    if not result:
        console.print(f"[red]Evaluation {evaluation_id} not found in registry.[/red]")
        return
        
    # 2. Fetch history if needed
    history = benchmark_framework.runner.get_history(result.benchmark_id)
    
    # 3. Generate Report Model
    benchmark_report = ReportGenerator.generate(result, previous_results=history)
    
    # 4. Render
    format = format.lower()
    if format == "json":
        output = JSONRenderer().render(benchmark_report)
        ext = "json"
        is_binary = False
    elif format == "html":
        output = HTMLRenderer().render(benchmark_report)
        ext = "html"
        is_binary = False
    elif format == "pdf":
        output = PDFRenderer().render(benchmark_report)
        ext = "pdf"
        is_binary = True
    else:
        output = MarkdownRenderer().render(benchmark_report)
        ext = "md"
        is_binary = False
        
    # 5. Save Artifact
    os.makedirs(".argus/reports", exist_ok=True)
    filename = f".argus/reports/report_{evaluation_id}.{ext}"
    
    if is_binary:
        with open(filename, "wb") as f:
            f.write(output)
    else:
        with open(filename, "w") as f:
            f.write(output)
            
    console.print(f"[bold green]Report generated successfully at:[/bold green] {filename}")

@app.command()
def leaderboard(
    dataset: str = typer.Option(None, "--dataset", help="Filter by dataset ID"),
    version: str = typer.Option(None, "--version", help="Filter by Argus version")
):
    """Shows the benchmark leaderboard."""
    from argus.benchmark.leaderboard.leaderboard import Leaderboard
    lb = Leaderboard()
    entries = lb.get_entries(dataset_id=dataset, argus_version=version)
    
    console.print("[bold cyan]Argus Benchmark Leaderboard[/bold cyan]")
    table = Table()
    table.add_column("ID")
    table.add_column("Dataset")
    table.add_column("Score")
    table.add_column("Argus Version")
    table.add_column("Commit")
    
    for e in entries:
        table.add_row(e.id[:8], e.dataset_id, f"{e.overall_score:.2f}", e.argus_version, e.commit_sha[:7])
    console.print(table)

@app.command()
def baseline(dataset_id: str):
    """Resolves and shows the current baseline for a dataset."""
    from argus.benchmark.leaderboard.leaderboard import Leaderboard
    from argus.benchmark.leaderboard.baseline import BaselineResolver
    lb = Leaderboard()
    resolver = BaselineResolver(lb)
    base = resolver.resolve(dataset_id)
    
    if base:
        console.print(f"[bold green]Current Baseline for {dataset_id}:[/bold green] {base.id} (Score: {base.overall_score:.2f})")
    else:
        console.print(f"[yellow]No baseline found for dataset {dataset_id}.[/yellow]")

@app.command()
def compare(baseline_id: str, current_id: str):
    """Compares two benchmark runs directly."""
    from argus.benchmark.leaderboard.leaderboard import Leaderboard
    from argus.benchmark.leaderboard.regression import RegressionDetector
    lb = Leaderboard()
    base = lb.get_by_id(baseline_id)
    curr = lb.get_by_id(current_id)
    
    if not base or not curr:
        console.print("[red]Could not find specified IDs in leaderboard.[/red]")
        return
        
    report = RegressionDetector.detect(base, curr)
    console.print(f"[bold]Comparison Status:[/bold] {report.overall_status.value}")
    
    for imp in report.improvements:
        console.print(f"[green]↑ {imp.metric_name}: +{abs(imp.percentage_difference):.2f}%[/green]")
    for reg in report.regressions:
        console.print(f"[red]↓ {reg.metric_name}: -{abs(reg.percentage_difference):.2f}%[/red]")

@app.command()
def regression(
    baseline_id: str = typer.Option(None, "--baseline", help="Baseline ID"),
    current_id: str = typer.Option(None, "--current", help="Current ID"),
    dataset: str = typer.Option(None, "--dataset", help="Dataset ID (if baseline_id is not provided)"),
    fail_on_regression: bool = typer.Option(False, "--fail-on-regression", help="Exit 1 if regression detected")
):
    """Detects regressions and outputs CI-compatible results."""
    from argus.benchmark.leaderboard.leaderboard import Leaderboard
    from argus.benchmark.leaderboard.baseline import BaselineResolver
    from argus.benchmark.leaderboard.regression import RegressionDetector
    from argus.benchmark.leaderboard.ci import CIIntegration
    
    lb = Leaderboard()
    
    curr = lb.get_by_id(current_id) if current_id else (lb.get_entries(dataset_id=dataset)[0] if dataset and lb.get_entries(dataset_id=dataset) else None)
    
    if not curr:
        console.print("[red]Could not resolve current run.[/red]")
        raise typer.Exit(code=1)
        
    resolver = BaselineResolver(lb)
    base = resolver.resolve(dataset_id=curr.dataset_id, baseline_id=baseline_id)
    
    if not base:
        console.print("[yellow]No baseline found to compare against. Assuming success.[/yellow]")
        raise typer.Exit(code=0)
        
    report = RegressionDetector.detect(base, curr)
    CIIntegration.handle_regression_exit(report, fail_on_regression=fail_on_regression)

from argus.cli.dataset_cli import app as dataset_app
app.add_typer(dataset_app, name="datasets")

from argus.cli.ground_truth_cli import app as gt_app
app.add_typer(gt_app, name="ground-truth")
