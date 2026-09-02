from __future__ import annotations

import json
from typing import Any, Dict, Union

from argus.reporting.models import (
    CVSSData,
    CWEInfo,
    Finding,
    ReportSeverity,
    ReportSummary,
    VulnerabilityReport,
)


class JSONReportRenderer:
    """Lossless, machine-readable JSON renderer and parser for VulnerabilityReport."""

    def render(self, report: VulnerabilityReport, indent: int = 2) -> str:
        """Serializes a VulnerabilityReport into a structured JSON string."""
        data = self.to_dict(report)
        return json.dumps(data, indent=indent, default=str)

    def to_dict(self, report: VulnerabilityReport) -> dict[str, Any]:
        """Converts a VulnerabilityReport into a standard JSON-serializable dictionary."""
        if hasattr(report, "to_dict"):
            return report.to_dict()

        # Fallback manual extraction
        findings_data = [
            f.to_dict() if hasattr(f, "to_dict") else self._finding_to_dict(f)
            for f in getattr(report, "findings", [])
        ]
        summary_data = (
            report.summary.to_dict()
            if hasattr(report.summary, "to_dict")
            else getattr(report, "summary", {})
        )

        return {
            "report_id": getattr(report, "report_id", ""),
            "mission_id": getattr(report, "mission_id", ""),
            "target": getattr(report, "target", ""),
            "generated_at": getattr(report, "generated_at", ""),
            "generator_version": getattr(report, "generator_version", "1.0.0"),
            "summary": summary_data,
            "findings": findings_data,
            "grouped_by_category": {
                k: [f.to_dict() if hasattr(f, "to_dict") else self._finding_to_dict(f) for f in v]
                for k, v in getattr(report, "grouped_by_category", {}).items()
            },
            "grouped_by_host": {
                k: [f.to_dict() if hasattr(f, "to_dict") else self._finding_to_dict(f) for f in v]
                for k, v in getattr(report, "grouped_by_host", {}).items()
            },
        }

    def parse(self, json_data: Union[str, dict[str, Any]]) -> VulnerabilityReport:
        """Parses a JSON string or dictionary back into a typed VulnerabilityReport object."""
        if isinstance(json_data, str):
            raw = json.loads(json_data)
        else:
            raw = dict(json_data)

        # Parse Summary
        raw_summary = raw.get("summary", {})
        summary = ReportSummary(
            total_findings=raw_summary.get("total_findings", 0),
            total_evidence_items=raw_summary.get("total_evidence_items", 0),
            deduplicated_count=raw_summary.get("deduplicated_count", 0),
            severity_counts=raw_summary.get("severity_counts", {}),
            category_counts=raw_summary.get("category_counts", {}),
            host_counts=raw_summary.get("host_counts", {}),
        )

        # Parse Findings
        findings: list[Finding] = []
        for f_raw in raw.get("findings", []):
            findings.append(self._parse_finding_dict(f_raw))

        # Parse Groupings
        grouped_by_cat: dict[str, list[Finding]] = {}
        for cat, items in raw.get("grouped_by_category", {}).items():
            grouped_by_cat[cat] = [self._parse_finding_dict(item) for item in items]

        grouped_by_host: dict[str, list[Finding]] = {}
        for host, items in raw.get("grouped_by_host", {}).items():
            grouped_by_host[host] = [self._parse_finding_dict(item) for item in items]

        return VulnerabilityReport(
            report_id=raw.get("report_id", ""),
            mission_id=raw.get("mission_id", ""),
            target=raw.get("target", ""),
            generated_at=raw.get("generated_at", ""),
            generator_version=raw.get("generator_version", "1.0.0"),
            summary=summary,
            findings=findings,
            grouped_by_category=grouped_by_cat,
            grouped_by_host=grouped_by_host,
        )

    def _parse_finding_dict(self, f_raw: dict[str, Any]) -> Finding:
        # CVSS
        cvss_raw = f_raw.get("cvss", {})
        cvss = CVSSData(
            score=float(cvss_raw.get("score", 0.0)),
            vector=cvss_raw.get("vector", ""),
            severity_rating=cvss_raw.get("severity_rating", "None"),
            metrics=cvss_raw.get("metrics", {}),
        )

        # CWE
        cwe_raw = f_raw.get("cwe")
        cwe = None
        if cwe_raw and isinstance(cwe_raw, dict):
            cwe = CWEInfo(id=cwe_raw.get("id", ""), name=cwe_raw.get("name", ""))

        return Finding(
            id=f_raw.get("id", ""),
            title=f_raw.get("title", ""),
            category=f_raw.get("category", "general"),
            severity=f_raw.get("severity", "info"),
            cvss=cvss,
            cwe=cwe,
            host=f_raw.get("host", ""),
            endpoint=f_raw.get("endpoint", ""),
            parameter=f_raw.get("parameter"),
            parameter_type=f_raw.get("parameter_type"),
            payload=f_raw.get("payload"),
            description=f_raw.get("description", ""),
            steps_to_reproduce=f_raw.get("steps_to_reproduce", []),
            impact=f_raw.get("impact", ""),
            remediation=f_raw.get("remediation", ""),
            confidence=float(f_raw.get("confidence", 1.0)),
            status=f_raw.get("status", "CONFIRMED"),
            evidence_ids=f_raw.get("evidence_ids", []),
            duplicate_count=int(f_raw.get("duplicate_count", 1)),
            tags=f_raw.get("tags", []),
            references=f_raw.get("references", []),
            metadata=f_raw.get("metadata", {}),
        )

    @staticmethod
    def _finding_to_dict(f: Any) -> dict[str, Any]:
        if hasattr(f, "to_dict"):
            return f.to_dict()
        return dict(getattr(f, "__dict__", {}))
