import typer
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
import json

from argus.authorization.graph import AuthorizationGraph
from argus.authorization.models import AuthNodeType, AuthNode, AuthEdge
from argus.authorization.analyzer import AuthorizationAnalyzer

app = typer.Typer(help="Manage Authorization Graph")
console = Console()

def get_dummy_graph():
    # Return a mocked graph for the CLI dummy case
    graph = AuthorizationGraph()
    n1 = AuthNode(name="User", node_type=AuthNodeType.IDENTITY)
    n2 = AuthNode(name="Admin", node_type=AuthNodeType.ROLE)
    n3 = AuthNode(name="Project", node_type=AuthNodeType.PROJECT)
    graph.add_node(n1)
    graph.add_node(n2)
    graph.add_node(n3)
    return graph

@app.command()
def show(mission_id: str = typer.Argument(default="dummy")):
    """Show Authorization Graph details"""
    graph = get_dummy_graph() if mission_id == "dummy" else None
    
    if not graph:
        console.print("[yellow]No authorization graph found.[/yellow]")
        return
        
    console.print("\n[bold cyan]======================================================[/bold cyan]")
    console.print("[bold cyan]AUTHORIZATION GRAPH[/bold cyan]")
    console.print("[bold cyan]======================================================[/bold cyan]\n")
    
    analyzer = AuthorizationAnalyzer(graph)
    
    # Identities
    identities = graph.get_nodes_by_type(AuthNodeType.IDENTITY)
    if identities:
        console.print("[bold green]Identities:[/bold green] " + ", ".join(i.name for i in identities))
        
    # Roles
    roles = graph.get_nodes_by_type(AuthNodeType.ROLE)
    if roles:
        console.print("[bold green]Roles:[/bold green] " + ", ".join(r.name for r in roles))
        
    # Protected Resources
    resources = graph.get_nodes_by_type(AuthNodeType.PROTECTED_RESOURCE)
    if resources:
        console.print("[bold green]Protected Resources:[/bold green] " + ", ".join(r.name for r in resources))
        
    # Role Hierarchy
    hierarchy = analyzer.get_role_hierarchy()
    if hierarchy:
        console.print("\n[bold]Role Hierarchy:[/bold]")
        tree = Tree("Roles")
        def build_tree(parent_tree, parent_name):
            children = hierarchy.get(parent_name, [])
            for child in children:
                child_tree = parent_tree.add(child)
                build_tree(child_tree, child)
                
        # Find root roles
        all_children = set()
        for children in hierarchy.values():
            all_children.update(children)
        roots = set(hierarchy.keys()) - all_children
        for root in roots:
            rt = tree.add(f"[bold]{root}[/bold]")
            build_tree(rt, root)
        console.print(tree)
        
    # Ownership Chains
    chains = analyzer.get_ownership_chains()
    if chains:
        console.print("\n[bold]Ownership Chains:[/bold]")
        for chain in chains:
            console.print(" -> ".join(chain))
            
    # Authorization Boundaries
    boundaries = analyzer.get_authorization_boundaries()
    if boundaries:
        console.print("\n[bold]Likely Authorization Boundaries:[/bold]")
        console.print(", ".join(boundaries))
