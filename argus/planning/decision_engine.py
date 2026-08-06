"""
Decision Engine.

Prioritizes and filters generated ResearchTasks based on mission objectives,
evidence quality, coverage gaps, and dependency readiness.
"""
from typing import List, Any
from argus.planning.models import ResearchTask, CoverageReport


class DecisionEngine:
    """Prioritizes, filters, and orders research tasks for the mission."""

    def __init__(self, mission: Any):
        self.mission = mission

    def prioritize(self, tasks: List[ResearchTask], coverage: CoverageReport) -> List[ResearchTask]:
        """Score and sort tasks by priority, respecting dependencies and policy."""
        scored_tasks = []

        for task in tasks:
            score = self._compute_priority(task, coverage)
            task.priority = score
            scored_tasks.append(task)

        # Sort descending by priority (highest priority first)
        scored_tasks.sort(key=lambda t: t.priority, reverse=True)
        return scored_tasks

    def _compute_priority(self, task: ResearchTask, coverage: CoverageReport) -> float:
        """Compute a composite priority score for a task."""
        score = 0.0

        # Base: the gap severity that created this task
        score += task.priority * 0.4

        # Coverage weight: lower coverage areas get higher priority
        coverage_factor = 1.0 - coverage.overall_coverage
        score += coverage_factor * 0.3

        # Dependency readiness: penalize tasks whose dependencies aren't met
        if task.dependencies:
            dep_penalty = 0.1 * len(task.dependencies)
            score -= dep_penalty

        # Confidence boost
        score += task.confidence * 0.1

        # Mission policy constraints (e.g. "no_graphql" in policy disables GraphQL tasks)
        policy = getattr(self.mission, 'policy', {})
        disabled = policy.get('disabled_categories', [])
        if task.category.value in disabled:
            score = 0.0

        return max(0.0, min(1.0, score))

    def filter_by_scope(self, tasks: List[ResearchTask]) -> List[ResearchTask]:
        """Remove tasks that fall outside mission scope or violate policy."""
        policy = getattr(self.mission, 'policy', {})
        disabled = set(policy.get('disabled_categories', []))

        return [t for t in tasks if t.category.value not in disabled]
