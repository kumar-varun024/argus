"""
Learning & Feedback CLI.

Commands
--------
argus learning metrics         -- Compute and display MissionMetricsRecord.
argus learning history         -- List all historical LearningRecord snapshots.
argus learning recommendations -- Generate and show advisory recommendations.
argus learning feedback        -- Submit researcher feedback for an artifact.
"""
import typer
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from argus.learning.engine import LearningEngine
from argus.learning.models import FeedbackTag, FeedbackTargetType
from argus.learning.registry import LearningRegistry

learning_app = typer.Typer(help="Learning & Feedback Engine — research improvement tools.")
console = Console()


def _get_engine() -> LearningEngine:
    """Return a fresh engine wired to the global persistent registry."""
    from argus.learning.registry import learning_registry
    from argus.learning.metrics import MissionMetricsCalculator
    from argus.learning.patterns import PatternDiscovery
    from argus.learning.recommendations import RecommendationEngine
    from argus.learning.history import MissionHistoryStore
    from argus.learning.feedback import FeedbackCollector
    return LearningEngine(
        registry=learning_registry,
        metrics_calculator=MissionMetricsCalculator(),
        pattern_discovery=PatternDiscovery(),
        recommendation_engine=RecommendationEngine(),
        history_store=MissionHistoryStore(learning_registry),
        feedback_collector=FeedbackCollector(learning_registry),
    )


def _get_mission(mission_id: Optional[str]):
    """Resolve a mission from the manager or return a demo mission."""
    if mission_id:
        try:
            from argus.runtime.manager import mission_manager
            return mission_manager.get_mission(mission_id)
        except Exception:
            pass
    from argus.runtime.mission import Mission
    return Mission(target="cli_demo")


# ---------------------------------------------------------------------------
# argus learning metrics
# ---------------------------------------------------------------------------

@learning_app.command("metrics")
def show_metrics(
    mission_id: Optional[str] = typer.Option(None, "--mission", "-m", help="Mission ID"),
):
    """Compute and display mission performance metrics."""
    mission = _get_mission(mission_id)
    engine = _get_engine()

    from argus.learning.metrics import MissionMetricsCalculator
    calc = MissionMetricsCalculator()
    record = calc.calculate(mission)

    console.print(Panel.fit(
        f"[bold cyan]Mission Metrics[/bold cyan]\n"
        f"[dim]Mission:[/dim] {record.mission_id}",
        border_style="blue"
    ))

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold green")
    table.add_column("Value", style="white")

    table.add_row("Coverage", f"{record.coverage_pct:.0%}")
    table.add_row("Execution Time", f"{record.execution_time_seconds:.1f}s")
    table.add_row("Investigations", str(record.investigation_count))
    table.add_row("Hypotheses", str(record.hypothesis_count))
    table.add_row("Validated Hypotheses", str(record.validated_hypotheses))
    table.add_row("Rejected Hypotheses", str(record.rejected_hypotheses))
    table.add_row("Evidence Quality", f"{record.evidence_quality:.0%}")
    table.add_row("Graph Completeness", f"{record.graph_completeness:.0%}")
    table.add_row("Task Completion Rate", f"{record.task_completion_rate:.0%}")
    table.add_row("Failed Tasks", str(record.failed_task_count))

    console.print(table)

    if record.plugin_usage:
        ptable = Table(title="Plugin Usage", show_header=True)
        ptable.add_column("Plugin", style="cyan")
        ptable.add_column("Invocations", justify="right")
        ptable.add_column("Observations", justify="right")
        ptable.add_column("Validated", justify="right")
        ptable.add_column("Value Rate", justify="right")
        for stat in record.plugin_usage.values():
            ptable.add_row(
                stat.plugin_name,
                str(stat.invocations),
                str(stat.total_observations),
                str(stat.validated_investigations),
                f"{stat.value_rate:.0%}",
            )
        console.print(ptable)


# ---------------------------------------------------------------------------
# argus learning history
# ---------------------------------------------------------------------------

@learning_app.command("history")
def show_history():
    """List all historical LearningRecord snapshots from previous missions."""
    from argus.learning.registry import learning_registry
    records = learning_registry.get_all_records()

    if not records:
        console.print("[yellow]No learning history found.[/yellow]")
        console.print("[dim]Run 'argus learning metrics' after a mission completes to record it.[/dim]")
        return

    table = Table(title="Mission Learning History")
    table.add_column("Mission ID", style="cyan")
    table.add_column("Recorded At", style="dim")
    table.add_column("Validated", justify="right", style="green")
    table.add_column("Rejected", justify="right", style="red")
    table.add_column("Tasks OK", justify="right")
    table.add_column("Tasks Failed", justify="right", style="red")
    table.add_column("Inv. Quality", justify="right")

    for rec in sorted(records, key=lambda r: r.timestamp, reverse=True):
        table.add_row(
            rec.mission_id[:16] + "…" if len(rec.mission_id) > 16 else rec.mission_id,
            rec.timestamp[:19],
            str(len(rec.validated_hypotheses)),
            str(len(rec.rejected_hypotheses)),
            str(len(rec.completed_tasks)),
            str(len(rec.failed_tasks)),
            f"{rec.investigation_quality:.0%}",
        )

    console.print(table)
    console.print(f"\n[dim]Total records: {len(records)}[/dim]")


# ---------------------------------------------------------------------------
# argus learning recommendations
# ---------------------------------------------------------------------------

@learning_app.command("recommendations")
def show_recommendations(
    mission_id: Optional[str] = typer.Option(None, "--mission", "-m", help="Mission ID to store recommendations on"),
):
    """Discover patterns and generate advisory recommendations for the planner."""
    mission = _get_mission(mission_id) if mission_id else None
    engine = _get_engine()

    recommendations = engine.generate_recommendations(mission=mission)

    if not recommendations:
        console.print("[yellow]No recommendations generated.[/yellow]")
        console.print("[dim]At least 2 completed missions are required for pattern discovery.[/dim]")
        return

    console.print(Panel.fit(
        "[bold cyan]Research Recommendations[/bold cyan]\n"
        "[yellow]⚠ All recommendations require Planner approval before action.[/yellow]",
        border_style="yellow"
    ))

    _priority_color = {"High": "red", "Medium": "yellow", "Low": "green"}

    for i, rec in enumerate(recommendations, 1):
        color = _priority_color.get(rec.priority.value, "white")
        console.print(
            f"\n[bold]{i}. {rec.title}[/bold]  "
            f"[{color}][{rec.priority.value}][/{color}]"
        )
        console.print(f"   {rec.description}")
        console.print(f"   [dim]Rationale: {rec.rationale}[/dim]")
        if rec.source_pattern_ids:
            console.print(f"   [dim]Source patterns: {', '.join(rec.source_pattern_ids[:3])}[/dim]")
        console.print(f"   [dim]Requires planner approval: {rec.requires_planner_approval}[/dim]")

    console.print(f"\n[dim]{len(recommendations)} recommendation(s) generated.[/dim]")


# ---------------------------------------------------------------------------
# argus learning feedback
# ---------------------------------------------------------------------------

@learning_app.command("feedback")
def submit_feedback(
    target_id: str = typer.Argument(..., help="UUID of the investigation, hypothesis, or task"),
    tag: FeedbackTag = typer.Option(..., "--tag", "-t", help="Feedback tag"),
    target_type: FeedbackTargetType = typer.Option(
        FeedbackTargetType.INVESTIGATION, "--type", help="Target type"
    ),
    comment: str = typer.Option("", "--comment", "-c", help="Optional comment"),
    researcher: str = typer.Option("cli", "--researcher", "-r", help="Researcher identifier"),
    mission_id: Optional[str] = typer.Option(None, "--mission", "-m", help="Mission ID"),
):
    """Submit structured researcher feedback for an investigation, hypothesis, or task."""
    mission = _get_mission(mission_id)
    engine = _get_engine()

    entry = engine.feedback.submit(
        mission=mission,
        target_id=target_id,
        target_type=target_type,
        tag=tag,
        comment=comment,
        researcher=researcher,
    )

    console.print(
        f"[green]✓ Feedback submitted[/green] — "
        f"tag=[bold]{entry.tag.value}[/bold] "
        f"on {entry.target_type.value} [cyan]{entry.target_id[:16]}…[/cyan]"
    )
    if comment:
        console.print(f"  Comment: {comment}")
