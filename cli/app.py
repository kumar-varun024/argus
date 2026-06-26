import typer
from rich.console import Console
from rich.panel import Panel

from core.mission import Mission

app = typer.Typer(
    help="Argus - Autonomous Offensive Security Platform"
)

console = Console()


@app.command()
def assess(target: str):
    """
    Start a new security assessment.
    """

    mission = Mission(target=target)

    console.print(
        Panel.fit(
            f"[bold cyan]ARGUS[/bold cyan]\n\n"
            f"Mission ID : {mission.id}\n"
            f"Target     : {mission.target}\n"
            f"Status     : {mission.status}\n"
            f"Phase      : {mission.phase}",
            title="Mission Created",
        )
    )

    mission.start()

    console.print(f"[green]✓ Status : {mission.status}[/green]")
    console.print("[green]✓ Planner initialized[/green]")
    console.print("[green]✓ Event Bus initialized[/green]")
    console.print("[green]✓ Knowledge Graph initialized[/green]")
    console.print("[yellow]Waiting for Recon...[/yellow]")


@app.command()
def version():
    """
    Show Argus version.
    """
    console.print("Argus v0.1.0-alpha")


if __name__ == "__main__":
    app()
