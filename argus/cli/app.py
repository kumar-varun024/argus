import typer

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from argus.core.mission import Mission
from argus.core.scheduler import Scheduler
from argus.planner import Planner
from argus.agents import ReconAgent
from argus.cli.knowledge import app as knowledge_app
from argus.cli.queue_cli import app as queue_app
from argus.cli.workflow_cli import app as workflow_app
from argus.cli.auth_cli import app as auth_app
from argus.cli.agent_cli import app as agent_app
from argus.cli.execution_cli import app as execution_app
from argus.cli.plugin_cli import app as plugin_app
from argus.cli.provenance_cli import app as provenance_app
from argus.cli.mission_cli import app as mission_app
from argus.cli.intelligence_cli import app as intelligence_app
from argus.cli.playbook_cli import app as playbook_app
from argus.cli.business_cli import app as business_app
from argus.cli.api_cli import app as api_app
from argus.cli.authn_cli import app as authn_app
from argus.cli.upload_cli import app as upload_app
from argus.plugins.graphql.cli import app as graphql_app
from argus.plugins.javascript.cli import app as javascript_app
from argus.correlation.cli import app as correlation_app
from argus.correlation.cli import correlations_app
from argus.cli.execution_cli import get_dummy_registry, get_dummy_plan
from argus.execution.engine import ExecutionEngine

app = typer.Typer(help="Argus - Autonomous Offensive Security Platform")
app.add_typer(knowledge_app, name="knowledge")
app.add_typer(queue_app, name="queue")
app.add_typer(workflow_app, name="workflow")
app.add_typer(auth_app, name="auth")
app.add_typer(agent_app, name="agent")
app.add_typer(execution_app, name="execution")
app.add_typer(plugin_app, name="plugin")
app.add_typer(provenance_app, name="provenance")
app.add_typer(mission_app, name="mission")
app.add_typer(intelligence_app, name="intelligence")
app.add_typer(playbook_app, name="playbooks")
app.add_typer(business_app, name="business")
app.add_typer(api_app, name="api")
app.add_typer(authn_app, name="authn")
app.add_typer(upload_app, name="upload")
app.add_typer(graphql_app, name="graphql")
app.add_typer(javascript_app, name="javascript")
app.add_typer(correlation_app, name="observations")
app.add_typer(correlations_app, name="correlations")

from argus.correlation.cli import evidence_app
app.add_typer(evidence_app, name="evidence")

from argus.cli.investigation_cli import investigations_app
app.add_typer(investigations_app, name="investigations")

console = Console()


@app.command()
def execute(plan_id: str = typer.Argument(default="dummy")):
    """Execute a deterministic investigation plan."""
    registry = get_dummy_registry()
    engine = ExecutionEngine(registry)
    plan = get_dummy_plan()
    mission = Mission("test")
    
    console.print(f"\n[bold green]Executing Plan: {plan.title}[/bold green]\n")
    
    result = engine.execute_plan(plan, mission)
    
    table = Table(title="Execution Steps")
    table.add_column("Order")
    table.add_column("Agent")
    table.add_column("Status")
    table.add_column("Time (ms)")
    
    for sr in result.step_results:
        table.add_row(str(sr.step_order), sr.agent, str(sr.status), f"{sr.execution_time_ms:.2f}")
        
    console.print(table)
    console.print(f"\n[bold]Plan Final Status:[/bold] {result.status}")
    console.print(f"[bold]Total Time:[/bold] {result.total_execution_time_ms:.2f} ms\n")

@app.command()
def explain(artifact_id: str):
    """Outputs a human-readable text trace explaining the given artifact's lineage."""
    from argus.provenance.engine import provenance_engine
    console.print(f"\n[bold cyan]Provenance Trace for:[/bold cyan] {artifact_id}\n")
    console.print(provenance_engine.explain(artifact_id))
    console.print("\n")

@app.command()
def trace(artifact_id: str):
    """Outputs a structured JSON of the provenance graph for an artifact."""
    import json
    from argus.provenance.engine import provenance_engine
    data = provenance_engine.trace(artifact_id)
    console.print(json.dumps(data, indent=2))


@app.command()
def version():
    console.print("Argus v0.1.0-alpha")


if __name__ == "__main__":
    app()
