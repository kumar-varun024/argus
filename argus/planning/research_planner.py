"""
Research Planner.

Continuously evaluates the current mission state and determines the next
best research actions. Unlike the Mission Planner (which creates the initial
strategy), the Research Planner adapts as new observations, evidence, and
investigations are produced.

The Research Planner NEVER executes tools or specialists.
It NEVER exploits systems.
It NEVER bypasses Mission Scope or Policy.
It only generates ResearchTask objects.
"""
import logging
from typing import List, Any
from argus.planning.models import ResearchTask, CoverageReport
from argus.planning.gap_analysis import GapAnalyzer
from argus.planning.coverage import CoverageTracker
from argus.planning.task_generator import TaskGenerator
from argus.planning.decision_engine import DecisionEngine

logger = logging.getLogger(__name__)


class ResearchPlanner:
    """
    Evaluates mission state and produces a prioritized research queue.

    Orchestrates:
      1. Coverage computation
      2. Gap analysis
      3. Task generation from gaps
      4. Priority scoring and dependency filtering
      5. Mission storage updates
    """

    def __init__(self, mission: Any):
        self.mission = mission
        self.coverage_tracker = CoverageTracker(mission)
        self.gap_analyzer = GapAnalyzer(mission)
        self.task_generator = TaskGenerator(mission)
        self.decision_engine = DecisionEngine(mission)

    def plan(self) -> List[ResearchTask]:
        """Run a full planning cycle and return the prioritized research queue."""

        # 1. Compute current coverage
        coverage = self.coverage_tracker.compute()
        logger.info("Coverage computed: overall=%.2f, gaps=%d",
                     coverage.overall_coverage, len(coverage.gaps))

        # 2. Gap analysis (already embedded in coverage report)
        gaps = coverage.gaps
        for gap in gaps:
            logger.info("Gap identified: area=%s, severity=%.2f", gap.area, gap.severity)

        # 3. Generate tasks from gaps
        tasks = self.task_generator.from_gaps(gaps)
        logger.info("Tasks generated: %d", len(tasks))

        # 4. Filter by scope/policy, then prioritize
        tasks = self.decision_engine.filter_by_scope(tasks)
        tasks = self.decision_engine.prioritize(tasks, coverage)

        for task in tasks:
            logger.info("Task created: title=%s, priority=%.2f", task.title, task.priority)

        # 5. Store into mission
        if hasattr(self.mission, 'research_tasks'):
            self.mission.research_tasks = tasks
        if hasattr(self.mission, 'research_queue'):
            self.mission.research_queue = [t.id for t in tasks]
        if hasattr(self.mission, 'coverage'):
            self.mission.coverage = coverage.model_dump()
        if hasattr(self.mission, 'coverage_gaps'):
            self.mission.coverage_gaps = [g.model_dump() for g in gaps]

        return tasks

    def get_coverage(self) -> CoverageReport:
        """Return the current coverage report without generating tasks."""
        return self.coverage_tracker.compute()

    def get_next_task(self) -> ResearchTask | None:
        """Return the highest-priority pending task, or None if the queue is empty."""
        tasks = getattr(self.mission, 'research_tasks', [])
        pending = [t for t in tasks if t.status == "PENDING"]
        if pending:
            return pending[0]
        return None
