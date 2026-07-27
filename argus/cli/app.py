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

app = typer.Typer(help="Argus - Autonomous Offensive Security Platform")
app.add_typer(knowledge_app, name="knowledge")
app.add_typer(queue_app, name="queue")
app.add_typer(workflow_app, name="workflow")
app.add_typer(auth_app, name="auth")
app.add_typer(agent_app, name="agent")

console = Console()


@app.command()
def assess(target: str):

    mission = Mission(target)

    planner = Planner()
    scheduler = Scheduler()

    plan = planner.build_plan(target)

    mission.start()

    console.print(
        Panel.fit(
            f"[bold cyan]ARGUS[/bold cyan]\n\n"
            f"Mission ID : {mission.id}\n"
            f"Target     : {mission.target}\n"
            f"Status     : {mission.status}",
            title="Mission",
        )
    )

    table = Table(title="Execution Plan")

    table.add_column("#", justify="right")
    table.add_column("Task")
    table.add_column("Description")

    for index, task in enumerate(scheduler.run(plan), start=1):
        table.add_row(
            str(index),
            task.name,
            task.description,
        )

    console.print(table)

    console.print("\n[bold green]Launching Recon Agent...[/bold green]\n")

    agent = ReconAgent()
    agent.run(mission)


@app.command()
def version():
    console.print("Argus v0.1.0-alpha")


if __name__ == "__main__":
    app()
