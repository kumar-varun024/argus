import typer
import json
from argus.performance.metrics import metrics
from argus.performance.benchmark import suite
from argus.performance.cache import (
    observation_cache, correlation_cache, evidence_cache, clear_all_caches
)
from argus.performance.profiling import profile

app = typer.Typer(help="Performance and Optimization commands.")

@app.command("benchmark")
def run_benchmark(size: str = typer.Option("all", help="Size of benchmark: small, medium, large, very_large, all")):
    """Run performance benchmarks and report metrics."""
    typer.echo(f"Running benchmarks for size: {size}")
    if size == "small":
        suite.run_small()
    elif size == "medium":
        suite.run_medium()
    elif size == "large":
        suite.run_large()
    elif size == "very_large":
        suite.run_very_large()
    else:
        suite.run_all()
    
    summary = metrics.get_summary()
    typer.echo("Benchmark Summary:")
    typer.echo(json.dumps(summary, indent=2))

@app.command("metrics")
def show_metrics():
    """Display currently collected performance metrics."""
    typer.echo("Current Metrics:")
    typer.echo(json.dumps(metrics.get_summary(), indent=2))

@app.command("profile")
def run_profile(script_path: str):
    """Run a specific python script under the performance profiler."""
    typer.echo(f"Profiling script: {script_path}")
    import importlib.util
    import sys
    
    metrics.clear()
    spec = importlib.util.spec_from_file_location("profiled_script", script_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["profiled_script"] = module
    
    @profile(name="script_execution")
    def execute():
        spec.loader.exec_module(module)
        
    execute()
    typer.echo("Profiling Results:")
    typer.echo(json.dumps(metrics.get_summary(), indent=2))

@app.command("cache")
def manage_cache(action: str = typer.Argument(..., help="Action: status, clear")):
    """Manage the internal performance caches."""
    if action == "status":
        typer.echo("Cache Status:")
        typer.echo(f"Observation Cache: {len(observation_cache._cache)} items (max {observation_cache.max_size})")
        typer.echo(f"Correlation Cache: {len(correlation_cache._cache)} items (max {correlation_cache.max_size})")
        typer.echo(f"Evidence Cache: {len(evidence_cache._cache)} items (max {evidence_cache.max_size})")
    elif action == "clear":
        clear_all_caches()
        typer.echo("All caches cleared.")
    else:
        typer.echo("Unknown action. Use 'status' or 'clear'.")
