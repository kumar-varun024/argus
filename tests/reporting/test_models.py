from __future__ import annotations

import pytest
from argus.reporting.models import (
    CVSSData,
    CWEInfo,
    Finding,
    ReportSeverity,
    ReportSummary,
    VulnerabilityReport,
)


def test_report_severity_enum_and_ranking():
    assert ReportSeverity.CRITICAL.value == "critical"
    assert ReportSeverity.HIGH.value == "high"
    assert ReportSeverity.MEDIUM.value == "medium"
    assert ReportSeverity.LOW.value == "low"
    assert ReportSeverity.INFO.value == "info"

    assert ReportSeverity.CRITICAL.rank == 4
    assert ReportSeverity.HIGH.rank == 3
    assert ReportSeverity.MEDIUM.rank == 2
    assert ReportSeverity.LOW.rank == 1
    assert ReportSeverity.INFO.rank == 0


def test_report_severity_from_string():
    assert ReportSeverity.from_string("CRITICAL") == ReportSeverity.CRITICAL
    assert ReportSeverity.from_string("critical") == ReportSeverity.CRITICAL
    assert ReportSeverity.from_string("high") == ReportSeverity.HIGH
    assert ReportSeverity.from_string("MEDIUM") == ReportSeverity.MEDIUM
    assert ReportSeverity.from_string("low") == ReportSeverity.LOW
    assert ReportSeverity.from_string("info") == ReportSeverity.INFO
    assert ReportSeverity.from_string(None) == ReportSeverity.INFO
    assert ReportSeverity.from_string("unknown_val") == ReportSeverity.INFO
    assert ReportSeverity.from_string("critical_severity") == ReportSeverity.CRITICAL


def test_cvss_data_model():
    cvss = CVSSData(
        score=9.8,
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity_rating="Critical",
        metrics={"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    )
    assert cvss.score == 9.8
    assert cvss.severity_rating == "Critical"
    d = cvss.to_dict()
    assert d["score"] == 9.8
    assert d["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert d["metrics"]["AV"] == "N"


def test_cwe_info_model():
    cwe = CWEInfo(id="CWE-89", name="SQL Injection")
    assert cwe.id == "CWE-89"
    assert cwe.name == "SQL Injection"
    d = cwe.to_dict()
    assert d == {"id": "CWE-89", "name": "SQL Injection"}


def test_finding_defaults_and_to_dict():
    f = Finding(
        id="finding-1",
        title="SQL Injection in /api/users",
        category="sql_injection",
        severity="critical",
        cvss=CVSSData(score=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity_rating="Critical"),
        cwe=CWEInfo(id="CWE-89", name="SQL Injection"),
        host="api.target.com",
        endpoint="/api/users",
        parameter="id",
        parameter_type="query",
        payload="' OR 1=1--",
        description="SQL injection vulnerability found.",
        steps_to_reproduce=["Step 1", "Step 2"],
        impact="Full DB takeover",
        remediation="Use parameterized queries",
        confidence=1.0,
        status="CONFIRMED",
        evidence_ids=["ev-123", "ev-456"],
        duplicate_count=2,
        tags=["sqli", "owasp-top-10"],
        references=["https://owasp.org"],
        metadata={"custom": "val"},
    )
    d = f.to_dict()
    assert d["id"] == "finding-1"
    assert d["title"] == "SQL Injection in /api/users"
    assert d["severity"] == "critical"
    assert d["cvss"]["score"] == 9.8
    assert d["cwe"]["id"] == "CWE-89"
    assert d["host"] == "api.target.com"
    assert d["duplicate_count"] == 2
    assert len(d["evidence_ids"]) == 2
    assert "sqli" in d["tags"]


def test_report_summary_and_vulnerability_report():
    summary = ReportSummary(
        total_findings=2,
        total_evidence_items=4,
        deduplicated_count=2,
        severity_counts={"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
        category_counts={"sql_injection": 1, "idor": 1},
        host_counts={"api.target.com": 2},
    )
    report = VulnerabilityReport(
        report_id="rep-123",
        mission_id="mission-456",
        target="api.target.com",
        summary=summary,
        findings=[],
        grouped_by_category={"sql_injection": []},
        grouped_by_host={"api.target.com": []},
    )
    assert report.report_id == "rep-123"
    assert report.summary.total_findings == 2
    assert report.summary.deduplicated_count == 2
    d = report.to_dict()
    assert d["report_id"] == "rep-123"
    assert d["summary"]["total_evidence_items"] == 4
    assert d["summary"]["severity_counts"]["critical"] == 1
