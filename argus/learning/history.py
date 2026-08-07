"""
Mission History Store.

Persists and retrieves mission-level LearningRecord snapshots.
Wraps the LearningRegistry file I/O and provides mission-oriented helpers
to extract a LearningRecord from a completed Mission object.
"""
import logging
from typing import Any, List, Optional

from argus.learning.models import (
    FeedbackEntry,
    LearningRecord,
    PluginUsageStat,
)
from argus.learning.registry import LearningRegistry

logger = logging.getLogger(__name__)


class MissionHistoryStore:
    """
    Creates, persists, and retrieves LearningRecord snapshots for missions.

    Usage
    -----
    After a mission completes::

        store = MissionHistoryStore(registry)
        record = store.record_mission(mission)  # extract + persist
    """

    def __init__(self, registry: LearningRegistry):
        self._registry = registry

    def record_mission(self, mission: Any) -> LearningRecord:
        """
        Extract a complete LearningRecord from the given Mission and persist it.

        Parameters
        ----------
        mission : The Mission object after completion.

        Returns
        -------
        The stored LearningRecord.
        """
        mission_id = str(getattr(mission, "id", "unknown"))

        record = LearningRecord(mission_id=mission_id)

        # Hypothesis outcomes
        record.validated_hypotheses = self._extract_hypothesis_ids(mission, "Validated")
        record.rejected_hypotheses = self._extract_hypothesis_ids(mission, "Rejected")

        # Task outcomes
        record.completed_tasks, record.failed_tasks = self._extract_task_ids(mission)

        # Plugin usage from execution_metrics
        record.plugin_usage = self._extract_plugin_usage(mission)

        # Feedback collected during this mission
        raw_feedback = getattr(mission, "feedback", []) or []
        record.feedback = [
            f for f in raw_feedback if isinstance(f, FeedbackEntry)
        ]

        # Investigation quality — average confidence across all investigations
        record.investigation_quality = self._investigation_quality(mission)

        # Attach metrics record if already computed
        learning = getattr(mission, "learning", None)
        if learning is not None and hasattr(learning, "metrics"):
            record.metrics = learning.metrics

        self._registry.add_record(record)
        logger.info(
            f"History: Mission {mission_id} recorded — "
            f"validated={len(record.validated_hypotheses)}, "
            f"rejected={len(record.rejected_hypotheses)}, "
            f"tasks_ok={len(record.completed_tasks)}, "
            f"tasks_fail={len(record.failed_tasks)}"
        )
        return record

    def get_record(self, mission_id: str) -> Optional[LearningRecord]:
        """Retrieve the LearningRecord for a given mission_id."""
        return self._registry.get_record(mission_id)

    def get_all_records(self) -> List[LearningRecord]:
        """Return all persisted LearningRecord objects."""
        return self._registry.get_all_records()

    # ------------------------------------------------------------------
    # Private extraction helpers
    # ------------------------------------------------------------------

    def _extract_hypothesis_ids(self, mission: Any, status_value: str) -> List[str]:
        reg = getattr(mission, "hypotheses", None)
        if reg is None:
            return []
        hypotheses = reg.get_all() if hasattr(reg, "get_all") else (
            reg if isinstance(reg, list) else []
        )
        result = []
        for h in hypotheses:
            s = getattr(h, "status", None)
            s_val = getattr(s, "value", str(s)) if s is not None else ""
            if status_value in s_val:
                result.append(str(getattr(h, "id", "")))
        return result

    def _extract_task_ids(self, mission: Any) -> tuple[List[str], List[str]]:
        history = getattr(mission, "execution_history", []) or []
        completed: List[str] = []
        failed: List[str] = []
        for entry in history:
            eid = str(
                entry.get("id", "") if isinstance(entry, dict)
                else getattr(entry, "id", "")
            )
            status = (
                entry.get("status", "") if isinstance(entry, dict)
                else str(getattr(entry, "status", ""))
            ).upper()
            if "COMPLETED" in status or "SUCCEEDED" in status:
                completed.append(eid)
            elif "FAILED" in status or "ERROR" in status:
                failed.append(eid)
        return completed, failed

    def _extract_plugin_usage(self, mission: Any) -> dict:
        exec_metrics = getattr(mission, "execution_metrics", {}) or {}
        stats = {}
        for tool_id, info in exec_metrics.items():
            if not isinstance(info, dict):
                continue
            stats[tool_id] = PluginUsageStat(
                plugin_id=tool_id,
                plugin_name=info.get("tool_name", tool_id),
                invocations=info.get("invocations", 1),
                avg_confidence=info.get("avg_confidence", 0.0),
                total_observations=info.get("total_observations", 0),
                validated_investigations=info.get("validated_investigations", 0),
                rejected_investigations=info.get("rejected_investigations", 0),
            )
        return stats

    def _investigation_quality(self, mission: Any) -> float:
        reg = getattr(mission, "investigations", None)
        if reg is None:
            return 0.0
        invs = reg.get_all() if hasattr(reg, "get_all") else (
            reg if isinstance(reg, list) else []
        )
        if not invs:
            return 0.0
        confidences = [getattr(i, "confidence", 0.0) for i in invs]
        return sum(confidences) / len(confidences)
