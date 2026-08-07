"""
Mission Metrics Calculator.

Derives a MissionMetricsRecord from a completed Mission object.
All values are computed deterministically from existing mission data.
No AI inference is performed.
"""
import logging
from typing import Any

from argus.learning.models import MissionMetricsRecord, PluginUsageStat

logger = logging.getLogger(__name__)


class MissionMetricsCalculator:
    """
    Computes a MissionMetricsRecord from a Mission object.

    Designed to be tolerant of missing or partial mission state — all
    attribute accesses use safe getattr / hasattr guards so the calculator
    works regardless of which engines have been initialised.
    """

    def calculate(self, mission: Any) -> MissionMetricsRecord:
        """
        Build and return a full MissionMetricsRecord for the given mission.
        """
        mission_id = str(getattr(mission, "id", "unknown"))
        target = str(getattr(mission, "target", ""))

        record = MissionMetricsRecord(
            mission_id=mission_id,
            target=target,
        )

        record.coverage_pct = self._coverage(mission)
        record.execution_time_seconds = self._execution_time(mission)
        record.investigation_count = self._investigation_count(mission)
        record.hypothesis_count = self._hypothesis_count(mission)
        record.validated_hypotheses, record.rejected_hypotheses = self._hypothesis_outcomes(mission)
        record.evidence_quality = self._evidence_quality(mission)
        record.graph_completeness = self._graph_completeness(mission)
        record.plugin_usage = self._plugin_usage(mission)
        record.task_completion_rate, record.failed_task_count = self._task_stats(mission)

        logger.info(
            f"Metrics updated for mission {mission_id}: "
            f"coverage={record.coverage_pct:.2f}, "
            f"investigations={record.investigation_count}, "
            f"hypotheses={record.hypothesis_count}"
        )
        return record

    # ------------------------------------------------------------------
    # Individual metric extractors
    # ------------------------------------------------------------------

    def _coverage(self, mission: Any) -> float:
        coverage = getattr(mission, "coverage", None)
        if isinstance(coverage, dict):
            return float(coverage.get("overall_coverage", 0.0))
        if hasattr(coverage, "overall_coverage"):
            return float(coverage.overall_coverage)
        return 0.0

    def _execution_time(self, mission: Any) -> float:
        metrics = getattr(mission, "metrics", {}) or {}
        if isinstance(metrics, dict):
            durations = metrics.get("durations", {})
            return float(durations.get("total_execution_time", 0.0))
        return 0.0

    def _investigation_count(self, mission: Any) -> int:
        reg = getattr(mission, "investigations", None)
        if reg and hasattr(reg, "get_all"):
            return len(reg.get_all())
        investigations = getattr(mission, "investigations", [])
        if isinstance(investigations, list):
            return len(investigations)
        return 0

    def _hypothesis_count(self, mission: Any) -> int:
        reg = getattr(mission, "hypotheses", None)
        if reg is None:
            return 0
        if hasattr(reg, "get_all"):
            return len(reg.get_all())
        if isinstance(reg, list):
            return len(reg)
        return 0

    def _hypothesis_outcomes(self, mission: Any) -> tuple[int, int]:
        """Return (validated_count, rejected_count)."""
        reg = getattr(mission, "hypotheses", None)
        if reg is None:
            return 0, 0
        if hasattr(reg, "get_all"):
            hypotheses = reg.get_all()
        elif isinstance(reg, list):
            hypotheses = reg
        else:
            return 0, 0

        validated = 0
        rejected = 0
        for h in hypotheses:
            status_val = ""
            status = getattr(h, "status", None)
            if status is not None:
                status_val = getattr(status, "value", str(status))
            if "Validated" in status_val or status_val == "Validated":
                validated += 1
            elif "Rejected" in status_val or status_val == "Rejected":
                rejected += 1
        return validated, rejected

    def _evidence_quality(self, mission: Any) -> float:
        """Average confidence across all evidence bundles."""
        reg = getattr(mission, "evidence_bundles", None)
        if reg is None:
            return 0.0
        if hasattr(reg, "get_all"):
            bundles = reg.get_all()
        elif isinstance(reg, list):
            bundles = reg
        else:
            return 0.0

        if not bundles:
            return 0.0
        confidences = [getattr(b, "confidence", 0.0) for b in bundles]
        return sum(confidences) / len(confidences)

    def _graph_completeness(self, mission: Any) -> float:
        """
        Ratio of edges to nodes in the correlation graph.
        Returns 0.0 when the graph is empty or unavailable.
        """
        graph = getattr(mission, "correlation_graph", None)
        if graph is None:
            return 0.0
        nodes = 0
        edges = 0
        if hasattr(graph, "nodes"):
            n = graph.nodes
            nodes = len(n) if hasattr(n, "__len__") else 0
        if hasattr(graph, "edges"):
            e = graph.edges
            edges = len(e) if hasattr(e, "__len__") else 0
        if nodes == 0:
            return 0.0
        return min(edges / nodes, 1.0)

    def _plugin_usage(self, mission: Any) -> dict:
        """
        Derive plugin usage stats from execution_metrics or execution_history.
        Returns a dict of plugin_id → PluginUsageStat.
        """
        stats: dict = {}
        exec_metrics = getattr(mission, "execution_metrics", {}) or {}
        for tool_id, info in exec_metrics.items():
            if not isinstance(info, dict):
                continue
            stat = PluginUsageStat(
                plugin_id=tool_id,
                plugin_name=info.get("tool_name", tool_id),
                invocations=info.get("invocations", 1),
                avg_confidence=info.get("avg_confidence", 0.0),
                total_observations=info.get("total_observations", 0),
                validated_investigations=info.get("validated_investigations", 0),
                rejected_investigations=info.get("rejected_investigations", 0),
            )
            stats[tool_id] = stat
        return stats

    def _task_stats(self, mission: Any) -> tuple[float, int]:
        """Return (completion_rate, failed_count)."""
        history = getattr(mission, "execution_history", []) or []
        if not history:
            return 0.0, 0

        completed = 0
        failed = 0
        for entry in history:
            if isinstance(entry, dict):
                status = entry.get("status", "")
            else:
                status = str(getattr(entry, "status", ""))
            status_upper = status.upper()
            if "COMPLETED" in status_upper or "SUCCEEDED" in status_upper:
                completed += 1
            elif "FAILED" in status_upper or "ERROR" in status_upper:
                failed += 1

        total = completed + failed
        rate = completed / total if total > 0 else 0.0
        return rate, failed
