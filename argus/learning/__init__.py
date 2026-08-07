"""
argus.learning — Learning & Feedback Engine

Public API
----------
LearningEngine          Central orchestrator
LearningRecord          Per-mission learning snapshot
MissionMetricsRecord    Full mission performance record
FeedbackEntry           Single piece of researcher feedback
FeedbackTag             Structured feedback categories
FeedbackTargetType      Type discriminator (investigation/hypothesis/task/plugin)
DiscoveredPattern       Reusable research pattern from history
Recommendation          Advisory recommendation for the planner
RecommendationPriority  Low / Medium / High
PluginUsageStat         Per-plugin performance statistics
HeuristicUsageStat      Per-heuristic performance statistics
LearningRegistry        In-memory + file-backed store
FeedbackCollector       Receives and validates researcher feedback
FeedbackSummarizer      Aggregates feedback statistics
MissionMetricsCalculator Derives metrics from a Mission object
PatternDiscovery        Deterministic pattern detection from history
RecommendationEngine    Maps patterns to advisory recommendations
MissionHistoryStore     Extracts and persists mission LearningRecords
learning_engine         Global singleton LearningEngine
learning_registry       Global singleton LearningRegistry
"""
from argus.learning.models import (
    FeedbackEntry,
    FeedbackTag,
    FeedbackTargetType,
    HeuristicUsageStat,
    LearningRecord,
    MissionMetricsRecord,
    PluginUsageStat,
    DiscoveredPattern,
    Recommendation,
    RecommendationPriority,
)
from argus.learning.registry import LearningRegistry, learning_registry
from argus.learning.feedback import FeedbackCollector, FeedbackSummarizer
from argus.learning.metrics import MissionMetricsCalculator
from argus.learning.patterns import PatternDiscovery
from argus.learning.recommendations import RecommendationEngine
from argus.learning.history import MissionHistoryStore
from argus.learning.engine import LearningEngine, learning_engine

__all__ = [
    "FeedbackEntry",
    "FeedbackTag",
    "FeedbackTargetType",
    "HeuristicUsageStat",
    "LearningRecord",
    "MissionMetricsRecord",
    "PluginUsageStat",
    "DiscoveredPattern",
    "Recommendation",
    "RecommendationPriority",
    "LearningRegistry",
    "learning_registry",
    "FeedbackCollector",
    "FeedbackSummarizer",
    "MissionMetricsCalculator",
    "PatternDiscovery",
    "RecommendationEngine",
    "MissionHistoryStore",
    "LearningEngine",
    "learning_engine",
]
