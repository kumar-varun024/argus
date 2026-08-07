"""
Learning & Feedback Engine — Domain Models.

Defines the core data structures for feedback collection, mission metrics,
pattern discovery, and research recommendations.

This module does NOT train AI models, modify prompts, or alter mission policy.
All recommendations require explicit planner approval.
"""
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Feedback
# ---------------------------------------------------------------------------

class FeedbackTag(str, Enum):
    """Structured researcher feedback categories."""
    USEFUL_INVESTIGATION = "UsefulInvestigation"
    FALSE_POSITIVE = "FalsePositive"
    LOW_PRIORITY = "LowPriority"
    HIGH_VALUE = "HighValue"
    DUPLICATE = "Duplicate"
    NEEDS_IMPROVEMENT = "NeedsImprovement"


class FeedbackTargetType(str, Enum):
    """Type of the artifact the feedback is attached to."""
    INVESTIGATION = "investigation"
    HYPOTHESIS = "hypothesis"
    TASK = "task"
    PLUGIN = "plugin"


class FeedbackEntry(BaseModel):
    """A single piece of structured researcher feedback."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    mission_id: str
    target_id: str
    target_type: FeedbackTargetType
    tag: FeedbackTag
    comment: str = ""
    researcher: str = "unknown"
    created_at: str = Field(default_factory=_utc_now)


# ---------------------------------------------------------------------------
# Plugin & Heuristic Usage Statistics
# ---------------------------------------------------------------------------

class PluginUsageStat(BaseModel):
    """Performance statistics for a single plugin across a mission."""
    plugin_id: str
    plugin_name: str
    invocations: int = 0
    avg_confidence: float = Field(0.0, ge=0.0, le=1.0)
    total_observations: int = 0
    validated_investigations: int = 0
    rejected_investigations: int = 0

    @property
    def value_rate(self) -> float:
        """Ratio of validated investigations to total invocations."""
        if self.invocations == 0:
            return 0.0
        return self.validated_investigations / self.invocations


class HeuristicUsageStat(BaseModel):
    """Performance statistics for a heuristic rule."""
    heuristic_id: str
    category: str
    true_positives: int = 0
    false_positives: int = 0

    @property
    def noise_rate(self) -> float:
        total = self.true_positives + self.false_positives
        if total == 0:
            return 0.0
        return self.false_positives / total


# ---------------------------------------------------------------------------
# Mission Metrics
# ---------------------------------------------------------------------------

class MissionMetricsRecord(BaseModel):
    """Complete performance snapshot of a mission."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    mission_id: str
    target: str = ""
    computed_at: str = Field(default_factory=_utc_now)

    # Coverage
    coverage_pct: float = Field(0.0, ge=0.0, le=1.0)

    # Execution
    execution_time_seconds: float = 0.0

    # Investigations & Hypotheses
    investigation_count: int = 0
    hypothesis_count: int = 0
    validated_hypotheses: int = 0
    rejected_hypotheses: int = 0

    # Evidence & Graph
    evidence_quality: float = Field(0.0, ge=0.0, le=1.0)
    graph_completeness: float = Field(0.0, ge=0.0, le=1.0)

    # Plugin Performance
    plugin_usage: Dict[str, PluginUsageStat] = Field(default_factory=dict)

    # Task Execution
    task_completion_rate: float = Field(0.0, ge=0.0, le=1.0)
    failed_task_count: int = 0

    metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Learning Record
# ---------------------------------------------------------------------------

class LearningRecord(BaseModel):
    """Per-mission learning snapshot captured after mission completion."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    mission_id: str
    timestamp: str = Field(default_factory=_utc_now)

    # Hypothesis outcomes
    validated_hypotheses: List[str] = Field(default_factory=list)
    rejected_hypotheses: List[str] = Field(default_factory=list)

    # Task outcomes
    completed_tasks: List[str] = Field(default_factory=list)
    failed_tasks: List[str] = Field(default_factory=list)

    # Specialist & heuristic performance
    plugin_usage: Dict[str, PluginUsageStat] = Field(default_factory=dict)
    heuristic_usage: Dict[str, HeuristicUsageStat] = Field(default_factory=dict)

    # Quality summary
    investigation_quality: float = Field(0.0, ge=0.0, le=1.0)

    # Feedback submitted during this mission
    feedback: List[FeedbackEntry] = Field(default_factory=list)

    # Full metrics snapshot
    metrics: Optional[MissionMetricsRecord] = None

    metadata: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

class DiscoveredPattern(BaseModel):
    """A reusable research pattern identified from historical mission data."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    category: str = ""
    strength: float = Field(0.0, ge=0.0, le=1.0)
    sample_mission_ids: List[str] = Field(default_factory=list)
    discovered_at: str = Field(default_factory=_utc_now)


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

class RecommendationPriority(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class Recommendation(BaseModel):
    """
    An advisory recommendation for the Mission Planner.

    ALWAYS requires planner approval before any action is taken.
    The Learning Engine NEVER auto-modifies execution plans or mission policy.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    rationale: str
    category: str = ""
    priority: RecommendationPriority = RecommendationPriority.MEDIUM
    source_pattern_ids: List[str] = Field(default_factory=list)
    requires_planner_approval: bool = True   # Always True — immutable by design
    created_at: str = Field(default_factory=_utc_now)
