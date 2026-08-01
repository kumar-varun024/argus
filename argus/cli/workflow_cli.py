import typer
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
import json
import dataclasses

from argus.workflows.models import Workflow, WorkflowStep

app = typer.Typer(help="Manage Workflows")
console = Console()

def get_dummy_workflows():
    wf = Workflow(
        name="Authentication", 
        description="User login and token generation",
        confidence=0.9,
    )
    wf.steps.append(WorkflowStep(title="POST /login", endpoint="/login", http_method="POST"))
    wf.business_objects.add("User")
    wf.authentication.add("None")
    wf.entry_points.append("/login")
    return [wf]

@app.command()
def list(mission_id: str = typer.Argument(default="dummy")):
    """List all identified workflows for a mission"""
    
    # Mock data for demonstration, normally would load from mission
    wfs = []
    if mission_id == "dummy":
        wfs = get_dummy_workflows()
        
    console.print("\n[bold cyan]======================================================[/bold cyan]")
    console.print("[bold cyan]WORKFLOWS[/bold cyan]")
    console.print("[bold cyan]======================================================[/bold cyan]\n")
    
    if not wfs:
        console.print("[yellow]No workflows found.[/yellow]")
        return
        
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Workflow")
    table.add_column("Confidence", justify="right")
    table.add_column("Business Objects")
    table.add_column("Number of Steps", justify="right")
    table.add_column("Authentication")
    table.add_column("Risk Score")
    table.add_column("Summary")
    
    for wf in wfs:
        table.add_row(
            wf.name,
            f"{wf.confidence:.2f}",
            ", ".join(wf.business_objects),
            str(len(wf.steps)),
            ", ".join(wf.authentication),
            wf.risk_score,
            wf.description
        )
        
    console.print(table)
    
@app.command()
def show(workflow_id: str):
    """Show details of a specific workflow"""
    wfs = get_dummy_workflows()
    wf = wfs[0] if wfs else None
    
    if not wf:
        console.print("[red]Workflow not found.[/red]")
        return
        
    console.print(f"\n[bold cyan]Workflow: {wf.name}[/bold cyan]")
    console.print(f"Description: {wf.description}")
    console.print(f"Risk Score: {wf.risk_score}")
    console.print(f"Confidence: {wf.confidence}")
    console.print("\n[bold]Steps:[/bold]")
    
    table = Table(show_header=True, header_style="bold green")
    table.add_column("Order", justify="right")
    table.add_column("Method")
    table.add_column("Endpoint")
    table.add_column("Role")
    table.add_column("State")
    
    for step in wf.steps:
        table.add_row(
            str(step.order),
            step.http_method,
            step.endpoint,
            step.required_role or "None",
            step.expected_state or "None"
        )
    console.print(table)

@app.command()
def graph(mission_id: str = typer.Argument(default="dummy")):
    """Render the dependency graph of workflows"""
    wfs = get_dummy_workflows() if mission_id == "dummy" else []
    if not wfs:
        console.print("[yellow]No workflows found.[/yellow]")
        return
        
    tree = Tree("[bold magenta]Workflow Dependency Graph[/bold magenta]")
    
    wf_by_id = {w.id: w for w in wfs}
    
    # Find roots (no incoming edges)
    # A workflow is a root if no other workflow lists it as a dependency
    # Oh wait, `dependencies` stores the parent ID.
    # So if `w.dependencies` is empty, it's a root.
    roots = [w for w in wfs if not w.dependencies]
    
    def build_tree(parent_node, wf):
        wf_node = parent_node.add(f"[cyan]{wf.name}[/cyan] ({len(wf.steps)} steps)")
        # Find children
        children = [w for w in wfs if wf.id in w.dependencies]
        for child in children:
            build_tree(wf_node, child)
            
    for root in roots:
        build_tree(tree, root)
        
    console.print(tree)

@app.command()
def export(mission_id: str = typer.Argument(default="dummy"), format: str = typer.Option("json", help="Export format")):
    """Export workflows"""
    wfs = get_dummy_workflows() if mission_id == "dummy" else []
    
    if format == "json":
        data = [dataclasses.asdict(w) for w in wfs]
        # Handle sets for JSON serialization
        for d in data:
            d['business_objects'] = list(d['business_objects'])
            d['authentication'] = list(d['authentication'])
            d['roles'] = list(d['roles'])
        console.print(json.dumps(data, indent=2))
    else:
        console.print(f"[red]Format {format} not supported.[/red]")

@app.command()
def analyze(mission_id: str):
    """Run the Business Logic Specialist to find investigation opportunities."""
    from argus.runtime.manager import mission_manager
    from argus.agents.business_logic.agent import BusinessLogicSpecialist
    
    try:
        if mission_id == "dummy":
            mission = __import__("argus.runtime.mission", fromlist=["Mission"]).Mission("dummy")
            mission.workflows = get_dummy_workflows()
        else:
            mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    console.print(f"[cyan]Running Business Logic Specialist on Mission {mission_id}...[/cyan]")
    specialist = BusinessLogicSpecialist()
    specialist.analyze(mission)
    
    if mission_id != "dummy":
        mission_manager.checkpointer.checkpoint(mission)
    
    console.print(f"[green]Analysis complete! Generated {len(mission.business_logic)} investigations.[/green]")

@app.command()
def states(mission_id: str):
    """Show extracted state machines for workflows."""
    from argus.runtime.manager import mission_manager
    
    try:
        if mission_id == "dummy":
            mission = __import__("argus.runtime.mission", fromlist=["Mission"]).Mission("dummy")
            mission.workflows = get_dummy_workflows()
            from argus.agents.business_logic.agent import BusinessLogicSpecialist
            BusinessLogicSpecialist().analyze(mission)
        else:
            mission = mission_manager.get_mission(mission_id)
    except Exception as e:
        console.print(f"[red]Error loading mission:[/red] {e}")
        return
        
    if not mission.state_machines:
        console.print("[yellow]No state machines found.[/yellow]")
        return
        
    for sm_id, sm in mission.state_machines.items():
        console.print(f"\n[bold cyan]State Machine: {sm.name}[/bold cyan]")
        states_str = " -> ".join([s.name for s in sm.states])
        console.print(f"[bold green]States:[/bold green] {states_str}")
        if sm.transitions:
            console.print("[bold]Transitions:[/bold]")
            for t in sm.transitions:
                console.print(f"  - {t['from']} -> {t['to']} ({t.get('action', 'unknown')})")

