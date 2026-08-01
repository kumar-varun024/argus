import os
import typer
from rich.console import Console
from rich.table import Table

from argus.plugins.manager import PluginManager

app = typer.Typer(help="Manage Argus Plugins")
console = Console()

def get_manager() -> PluginManager:
    plugin_dir = os.environ.get("ARGUS_PLUGIN_DIR", "plugins")
    if not os.path.exists(plugin_dir):
        os.makedirs(plugin_dir, exist_ok=True)
    manager = PluginManager(plugin_dir)
    manager.load_all()
    return manager

@app.command()
def list():
    """Display installed plugins, versions, and statuses."""
    manager = get_manager()
    plugins = manager.get_registered_plugins()
    
    table = Table(title="Installed Plugins")
    table.add_column("Name", style="magenta")
    table.add_column("Version", style="green")
    table.add_column("Author")
    table.add_column("Status")
    
    if not plugins:
        console.print("[yellow]No plugins installed.[/yellow]")
        return
        
    for plugin in plugins:
        # Assuming all loaded ones are Enabled for now. Future: read config to see if disabled.
        table.add_row(
            plugin.manifest.name,
            plugin.manifest.version,
            plugin.manifest.author,
            "Enabled"
        )
    console.print(table)

@app.command()
def install(path: str):
    """Install a plugin into the active plugin directory."""
    console.print(f"[green]Installing plugin from {path}...[/green]")
    console.print("Installation logic (copy/symlink) will go here.")

@app.command()
def remove(name: str):
    """Remove a plugin."""
    console.print(f"[red]Removing plugin {name}...[/red]")

@app.command()
def enable(name: str):
    """Enable a plugin."""
    console.print(f"[green]Enabling plugin {name}...[/green]")

@app.command()
def disable(name: str):
    """Disable a plugin."""
    console.print(f"[yellow]Disabling plugin {name}...[/yellow]")

@app.command()
def info(name: str):
    """Show metadata and requested permissions of a plugin."""
    manager = get_manager()
    for plugin in manager.get_registered_plugins():
        if plugin.manifest.name == name:
            console.print(f"\n[bold cyan]Plugin:[/bold cyan] {plugin.manifest.name}")
            console.print(f"[bold cyan]Version:[/bold cyan] {plugin.manifest.version}")
            console.print(f"[bold cyan]Author:[/bold cyan] {plugin.manifest.author}")
            console.print(f"[bold cyan]Description:[/bold cyan] {plugin.manifest.description}")
            console.print(f"[bold cyan]Dependencies:[/bold cyan] {', '.join(plugin.manifest.dependencies) if plugin.manifest.dependencies else 'None'}")
            console.print(f"[bold cyan]Permissions:[/bold cyan] {', '.join(plugin.manifest.permissions) if plugin.manifest.permissions else 'None'}\n")
            return
            
    console.print(f"[red]Plugin '{name}' not found.[/red]")
