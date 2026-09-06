from typing import Optional, List
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
from argus.cli.tools_cli import app as tools_app
from argus.plugins.graphql.cli import app as graphql_app
from argus.plugins.javascript.cli import app as javascript_app
from argus.correlation.cli import app as correlation_app
from argus.correlation.cli import correlations_app
from argus.cli.benchmark_cli import app as benchmark_app
from argus.cli.workspace_cli import app as workspace_app
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
app.add_typer(tools_app, name="tools")
app.add_typer(graphql_app, name="graphql")
app.add_typer(javascript_app, name="javascript")
app.add_typer(correlation_app, name="observations")
app.add_typer(correlations_app, name="correlations")
app.add_typer(benchmark_app, name="benchmark")
app.add_typer(workspace_app, name="workspace")

from argus.correlation.cli import evidence_app
app.add_typer(evidence_app, name="evidence")

from argus.cli.investigation_cli import investigations_app
app.add_typer(investigations_app, name="investigations")

from argus.cli.explain_cli import app as explain_app
app.add_typer(explain_app, name="explain")

from argus.cli.performance_cli import app as performance_app
app.add_typer(performance_app)

from argus.cli.plan_cli import app as plan_app
app.add_typer(plan_app, name="plan")

from argus.cli.research_cli import app as research_app
app.add_typer(research_app, name="research")

from argus.cli.scheduler_cli import app as scheduler_app
app.add_typer(scheduler_app, name="scheduler")

from argus.cli.learning_cli import learning_app
app.add_typer(learning_app, name="learning")

from argus.cli.hypothesis_cli import hypothesis_app
app.add_typer(hypothesis_app, name="hypothesis")

from argus.cli.search_cli import search_app
app.add_typer(search_app, name="search")

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
def trace(artifact_id: str):
    """Outputs a structured JSON of the provenance graph for an artifact."""
    import json
    from argus.provenance.engine import provenance_engine
    data = provenance_engine.trace(artifact_id)
    console.print(json.dumps(data, indent=2))


@app.command("scan")
def scan(
    target: str = typer.Argument(..., help="Target URL, domain, or IP address to scan."),
    profile: str = typer.Option("full", "--profile", "-p", help="Scan profile: 'full', 'recon', 'vuln', 'quick'."),
    output: Optional[str] = typer.Option(None, "--output", "-o", "--output-dir", help="Output directory for reports (default: .argus/reports)."),
    threads: int = typer.Option(10, "--threads", "-t", help="Concurrency / worker threads."),
    timeout: Optional[int] = typer.Option(None, "--timeout", help="Scan timeout in seconds."),
    scope: Optional[List[str]] = typer.Option(None, "--scope", "-s", help="Additional in-scope domains/CIDRs."),
    workspace: str = typer.Option("default", "--workspace", "-w", help="Workspace identifier."),
    format: str = typer.Option("both", "--format", "-f", help="Report format ('both', 'markdown', 'json')."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose execution logs."),
):
    """
    Execute an automated end-to-end security assessment against a target.
    """
    import os
    import logging
    from argus.runtime.mission import Mission
    from argus.runtime.manager import mission_manager
    from argus.runtime.pipeline.dag import ScanDAG
    from argus.runtime.pipeline.scan_pipeline import ScanEngine
    from argus.runtime.pipeline.models import CollectorStatus

    if verbose:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger("argus").setLevel(logging.DEBUG)

    clean_target = (target or "").strip()
    if not clean_target:
        console.print("[bold red]Error:[/bold red] Target cannot be empty.")
        raise typer.Exit(code=1)

    effective_output_dir = output or ".argus/reports"

    # 1. Display Scan Banner
    console.print(
        Panel(
            f"[bold cyan]ARGUS Autonomous Offensive Security Scanner[/bold cyan]\n"
            f"[bold]Target:[/bold] [green]{clean_target}[/green] | "
            f"[bold]Profile:[/bold] [yellow]{profile.upper()}[/yellow] | "
            f"[bold]Workspace:[/bold] {workspace} | "
            f"[bold]Output:[/bold] {effective_output_dir}",
            title="⚡ ARGUS SCAN ENGINE",
            border_style="cyan",
            expand=False,
        )
    )

    # 2. Build DAG according to profile
    try:
        dag = ScanDAG.create_for_profile(profile)
    except Exception as e:
        console.print(f"[bold red]Failed to initialize ScanDAG for profile '{profile}':[/bold red] {e}")
        raise typer.Exit(code=1)

    # 3. Create and register Mission
    mission = Mission(target=clean_target, workspace=workspace)
    if scope:
        for s in scope:
            if s and s not in mission.scope:
                mission.scope.append(s)

    if threads:
        mission.configuration["threads"] = threads
    if timeout:
        mission.configuration["timeout"] = timeout

    mission_manager._active_missions[mission.id] = mission

    # 4. Execute ScanEngine
    engine = ScanEngine(dag=dag, output_dir=effective_output_dir)

    try:
        with console.status(f"[bold green]Running ARGUS Scan Engine DAG against {clean_target}...[/bold green]"):
            result = engine.run(mission)
    except Exception as exc:
        console.print(f"[bold red]Scan execution error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    # 5. Display Collector Execution Summary Table
    table = Table(title=f"Scan Execution Details ({len(result.collector_results)} tasks)", border_style="dim")
    table.add_column("Task / Collector", style="bold", no_wrap=True)
    table.add_column("Phase", style="dim")
    table.add_column("Status", justify="center")
    table.add_column("Evidence", justify="right")
    table.add_column("Duration", justify="right")

    for cr in result.collector_results:
        if cr.status == CollectorStatus.COMPLETED:
            status_style = "[bold green]COMPLETED[/bold green]"
        elif cr.status == CollectorStatus.SKIPPED:
            status_style = "[yellow]SKIPPED[/yellow]"
        elif cr.status == CollectorStatus.FAILED:
            status_style = "[bold red]FAILED[/bold red]"
        else:
            status_style = str(getattr(cr.status, "value", cr.status))

        task_obj = dag.get_task(cr.task_key or cr.tool_id)
        phase_str = task_obj.phase if task_obj else "recon"

        table.add_row(
            cr.name,
            phase_str,
            status_style,
            str(cr.evidence_count),
            f"{cr.duration_seconds:.2f}s",
        )

    console.print(table)

    # 6. Display Vulnerability Severity Summary
    sev = result.vulnerabilities_by_severity or {}
    crit_count = sev.get("critical", 0)
    high_count = sev.get("high", 0)
    med_count = sev.get("medium", 0)
    low_count = sev.get("low", 0)
    info_count = sev.get("info", 0)

    sev_text = (
        f"[bold red]CRITICAL: {crit_count}[/bold red] | "
        f"[bold bright_red]HIGH: {high_count}[/bold bright_red] | "
        f"[bold yellow]MEDIUM: {med_count}[/bold yellow] | "
        f"[bold blue]LOW: {low_count}[/bold blue] | "
        f"[bold cyan]INFO: {info_count}[/bold cyan]"
    )
    border_col = "red" if (crit_count + high_count) > 0 else ("yellow" if med_count > 0 else "green")
    console.print(Panel(sev_text, title="🎯 Vulnerability Breakdown", border_style=border_col))

    # 7. Display Generated Reports
    fmt_filter = (format or "both").lower().strip()
    displayed_reports = []
    if result.report_paths:
        for p in result.report_paths:
            if fmt_filter == "markdown" and not p.endswith(".md"):
                continue
            if fmt_filter == "json" and not p.endswith(".json"):
                continue
            displayed_reports.append(p)

    if displayed_reports:
        console.print("\n[bold green]📄 Generated Reports:[/bold green]")
        for path in displayed_reports:
            fmt_label = "Markdown" if path.endswith(".md") else "JSON" if path.endswith(".json") else "Report"
            console.print(f"  • [cyan]{fmt_label}:[/cyan] [underline]{path}[/underline]")
    elif result.report_paths:
        console.print("\n[bold green]📄 Generated Reports:[/bold green]")
        for path in result.report_paths:
            fmt_label = "Markdown" if path.endswith(".md") else "JSON" if path.endswith(".json") else "Report"
            console.print(f"  • [cyan]{fmt_label}:[/cyan] [underline]{path}[/underline]")
    else:
        console.print("\n[yellow]No reports were generated on disk.[/yellow]")

    # 8. Overall Status Summary
    duration_str = f"{result.duration_seconds:.2f}s"
    final_status_style = "green" if result.status == "COMPLETED" else "red"
    console.print(
        f"\n[bold]Scan ID:[/bold] {result.scan_id} | "
        f"[bold]Duration:[/bold] {duration_str} | "
        f"[bold]Total Evidence:[/bold] {result.total_evidence} | "
        f"[bold]Final Status:[/bold] [{final_status_style}]{result.status}[/{final_status_style}]\n"
    )

    if result.status == "FAILED":
        raise typer.Exit(code=1)


@app.command()
def version():
    console.print("Argus v0.1.0-alpha")


if __name__ == "__main__":
    app()
