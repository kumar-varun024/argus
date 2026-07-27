import typer
from rich.console import Console
from rich.table import Table

from argus.agents.registry import AgentRegistry
from argus.agents.scheduler import AgentScheduler
from argus.agents.specialists import (
    GraphQLAgent, OAuthAgent, JavaScriptAgent,
    BusinessLogicAgent, RESTAPIAgent, FileUploadAgent
)
from argus.core.mission import Mission

app = typer.Typer(help="Manage and execute Argus Agents")
console = Console()

def get_populated_registry() -> AgentRegistry:
    registry = AgentRegistry()
    registry.register(GraphQLAgent())
    registry.register(OAuthAgent())
    registry.register(JavaScriptAgent())
    registry.register(BusinessLogicAgent())
    registry.register(RESTAPIAgent())
    registry.register(FileUploadAgent())
    return registry

@app.command()
def list():
    """Display registered agents, their dependencies, and execution order."""
    registry = get_populated_registry()
    try:
        order = registry.resolve_execution_order()
    except Exception as e:
        console.print(f"[bold red]Error resolving dependencies: {e}[/bold red]")
        return
        
    table = Table(title="Registered Agents (Execution Order)")
    table.add_column("Order", justify="right", style="cyan")
    table.add_column("Agent Name", style="magenta")
    table.add_column("Dependencies", style="green")
    table.add_column("Description")
    
    for idx, agent in enumerate(order, start=1):
        deps = ", ".join(agent.dependencies) if agent.dependencies else "None"
        table.add_row(str(idx), agent.name, deps, agent.description)
        
    console.print(table)

@app.command()
def run(mission_id: str = typer.Argument(default="dummy")):
    """Run the scheduler on a target mission."""
    registry = get_populated_registry()
    scheduler = AgentScheduler(registry)
    mission = Mission(target=mission_id)
    
    console.print(f"\n[bold green]Starting Agent Scheduler for Mission: {mission_id}[/bold green]\n")
    scheduler.run(mission)
    
    console.print("\n[bold cyan]Execution Summary[/bold cyan]")
    table = Table()
    table.add_column("Agent", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Duration (ms)", justify="right")
    table.add_column("Items Produced", justify="right")
    
    for agent_name, metric in mission.agent_metrics.items():
        status = mission.agent_health.get(agent_name, "Unknown")
        table.add_row(
            agent_name,
            str(status),
            f"{metric.execution_time_ms:.2f}",
            str(metric.items_produced)
        )
        
    console.print(table)

@app.command()
def show(agent_name: str):
    """Show details, description, and input requirements of a specific agent."""
    registry = get_populated_registry()
    agent = registry.get_agent(agent_name)
    if not agent:
        console.print(f"[yellow]Agent '{agent_name}' not found.[/yellow]")
        return
        
    console.print(f"\n[bold cyan]Agent:[/bold cyan] {agent.name}")
    console.print(f"[bold cyan]Description:[/bold cyan] {agent.description}")
    console.print(f"[bold cyan]Supported Inputs:[/bold cyan] {', '.join(agent.supported_inputs)}")
    console.print(f"[bold cyan]Dependencies:[/bold cyan] {', '.join(agent.dependencies) if agent.dependencies else 'None'}\n")
