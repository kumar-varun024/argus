from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any


class CollectorStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class CollectorResult:
    tool_id: str
    task_title: str
    status: CollectorStatus
    evidence_count: int = 0
    duration_ms: float = 0.0
    error: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    task_key: Optional[str] = None

    @property
    def key(self) -> str:
        return self.task_key or self.tool_id

    @property
    def name(self) -> str:
        return self.task_title or self.tool_id

    @property
    def duration_seconds(self) -> float:
        return self.duration_ms / 1000.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_key": self.task_key,
            "tool_id": self.tool_id,
            "task_title": self.task_title,
            "name": self.name,
            "status": self.status.value if isinstance(self.status, CollectorStatus) else str(self.status),
            "evidence_count": self.evidence_count,
            "duration_ms": self.duration_ms,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }


@dataclass
class ScanResult:
    scan_id: str
    target: str
    status: str
    start_time: str
    end_time: str
    duration_seconds: float
    collectors_total: int
    collectors_run: int
    collectors_skipped: int
    collectors_failed: int
    total_evidence: int
    vulnerabilities_by_severity: Dict[str, int]
    collector_results: List[CollectorResult]
    state_transitions: List[Dict[str, Any]]
    report_paths: List[str] = field(default_factory=list)
    graph_summary: Dict[str, Any] = field(default_factory=dict)

    def get_collector_result(self, key: str) -> Optional[CollectorResult]:
        """Look up a collector result by task_key, tool_id, or task_title."""
        for cr in self.collector_results:
            if cr.tool_id == key or cr.task_title == key or cr.task_key == key:
                return cr
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "status": self.status,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "collectors_total": self.collectors_total,
            "collectors_run": self.collectors_run,
            "collectors_skipped": self.collectors_skipped,
            "collectors_failed": self.collectors_failed,
            "total_evidence": self.total_evidence,
            "vulnerabilities_by_severity": dict(self.vulnerabilities_by_severity),
            "collector_results": [cr.to_dict() for cr in self.collector_results],
            "state_transitions": list(self.state_transitions),
            "report_paths": list(self.report_paths),
            "graph_summary": dict(self.graph_summary),
        }
