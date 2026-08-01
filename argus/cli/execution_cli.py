import typer
from rich.console import Console
from rich.table import Table

from argus.execution.engine import ExecutionEngine
from argus.execution.plan import ExecutionPlan, ExecutionStep
from argus.agents.registry import AgentRegistry
from argus.agents.specialists import (
    GraphQLAgent, OAuthAgent, JavaScriptAgent,
    BusinessLogicAgent, RESTAPIAgent, FileUploadAgent
)
from argus.core.mission import Mission

app = typer.Typer(help="Manage and view Investigation Execution Engine status")
console = Console()

def get_dummy_registry():
    registry = AgentRegistry()
    registry.register(GraphQLAgent())
    registry.register(OAuthAgent())
    registry.register(JavaScriptAgent())
    registry.register(BusinessLogicAgent())
    registry.register(RESTAPIAgent())
    registry.register(FileUploadAgent())
    return registry

def get_dummy_plan():
    plan = ExecutionPlan(
        title="Mock Authentication Bypass Check",
        objective="Verify if authentication can be bypassed.",
    )
    plan.steps.append(ExecutionStep(order=1, agent="JavaScript Agent", action="Extract secrets"))
    plan.steps.append(ExecutionStep(order=2, agent="REST API Agent", action="Fuzz API keys"))
    return plan

@app.command()
def status(mission_id: str = typer.Argument(default="dummy")):
    """Displays current active execution state and pending steps."""
    console.print(f"\n[bold cyan]Execution Status for Mission: {mission_id}[/bold cyan]")
    # In a real system, we'd load the state from the DB.
    # We will just print a placeholder table
    table = Table()
    table.add_column("Plan ID")
    table.add_column("Status", style="green")
    table.add_column("Steps")
    
    table.add_row("plan-uuid-1234", "PENDING", "2")
    console.print(table)
    
@app.command()
def history(mission_id: str = typer.Argument(default="dummy")):
    """Displays past execution runs and their deterministic results."""
    console.print(f"\n[bold cyan]Execution History for Mission: {mission_id}[/bold cyan]")
    table = Table()
    table.add_column("Plan ID")
    table.add_column("End Time")
    table.add_column("Status", style="green")
    
    table.add_row("plan-uuid-0000", "2026-07-27T12:00:00", "COMPLETED")
    console.print(table)
