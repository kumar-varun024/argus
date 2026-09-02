from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4


class ReportSeverity(str, Enum):
    """Normalized vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_string(cls, val: Optional[str]) -> "ReportSeverity":
        if not val:
            return cls.INFO
        normalized = str(val).strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        if "crit" in normalized:
            return cls.CRITICAL
        elif "high" in normalized:
            return cls.HIGH
        elif "med" in normalized:
            return cls.MEDIUM
        elif "low" in normalized:
            return cls.LOW
        return cls.INFO

    @property
    def rank(self) -> int:
        """Numeric rank for sorting (Critical = 4 down to Info = 0)."""
        ranks = {
            ReportSeverity.CRITICAL: 4,
            ReportSeverity.HIGH: 3,
            ReportSeverity.MEDIUM: 2,
            ReportSeverity.LOW: 1,
            ReportSeverity.INFO: 0,
        }
        return ranks.get(self, 0)


@dataclass
class CVSSData:
    """CVSS v3.1 scoring data and vector."""
    score: float
    vector: str
    severity_rating: str
    metrics: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "vector": self.vector,
            "severity_rating": self.severity_rating,
            "metrics": dict(self.metrics),
        }


@dataclass
class CWEInfo:
    """Common Weakness Enumeration mapping."""
    id: str
    name: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
        }


@dataclass
class Finding:
    """Normalized, deduplicated vulnerability finding."""
    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    category: str = "general"
    severity: str = "info"  # critical, high, medium, low, info
    cvss: CVSSData = field(
        default_factory=lambda: CVSSData(
            score=0.0,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            severity_rating="None",
        )
    )
    cwe: Optional[CWEInfo] = None
    host: str = ""
    endpoint: str = ""
    parameter: Optional[str] = None
    parameter_type: Optional[str] = None
    payload: Optional[str] = None
    description: str = ""
    steps_to_reproduce: list[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    confidence: float = 1.0
    status: str = "CONFIRMED"
    evidence_ids: list[str] = field(default_factory=list)
    duplicate_count: int = 1
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "cvss": self.cvss.to_dict() if isinstance(self.cvss, CVSSData) else self.cvss,
            "cwe": self.cwe.to_dict() if isinstance(self.cwe, CWEInfo) else self.cwe,
            "host": self.host,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "parameter_type": self.parameter_type,
            "payload": self.payload,
            "description": self.description,
            "steps_to_reproduce": list(self.steps_to_reproduce),
            "impact": self.impact,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "status": self.status,
            "evidence_ids": list(self.evidence_ids),
            "duplicate_count": self.duplicate_count,
            "tags": list(self.tags),
            "references": list(self.references),
            "metadata": dict(self.metadata),
        }


@dataclass
class ReportSummary:
    """Aggregate metrics and counts across all findings."""
    total_findings: int
    total_evidence_items: int
    deduplicated_count: int
    severity_counts: dict[str, int] = field(default_factory=lambda: {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    })
    category_counts: dict[str, int] = field(default_factory=dict)
    host_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "total_evidence_items": self.total_evidence_items,
            "deduplicated_count": self.deduplicated_count,
            "severity_counts": dict(self.severity_counts),
            "category_counts": dict(self.category_counts),
            "host_counts": dict(self.host_counts),
        }


@dataclass
class VulnerabilityReport:
    """Full vulnerability report containing structured findings and metadata."""
    report_id: str = field(default_factory=lambda: str(uuid4()))
    mission_id: str = ""
    target: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    generator_version: str = "1.0.0"
    summary: ReportSummary = field(
        default_factory=lambda: ReportSummary(
            total_findings=0,
            total_evidence_items=0,
            deduplicated_count=0,
            severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            category_counts={},
            host_counts={},
        )
    )
    findings: list[Finding] = field(default_factory=list)
    grouped_by_category: dict[str, list[Finding]] = field(default_factory=dict)
    grouped_by_host: dict[str, list[Finding]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "mission_id": self.mission_id,
            "target": self.target,
            "generated_at": self.generated_at,
            "generator_version": self.generator_version,
            "summary": self.summary.to_dict() if isinstance(self.summary, ReportSummary) else self.summary,
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings],
            "grouped_by_category": {
                k: [f.to_dict() if hasattr(f, "to_dict") else f for f in v]
                for k, v in self.grouped_by_category.items()
            },
            "grouped_by_host": {
                k: [f.to_dict() if hasattr(f, "to_dict") else f for f in v]
                for k, v in self.grouped_by_host.items()
            },
        }
