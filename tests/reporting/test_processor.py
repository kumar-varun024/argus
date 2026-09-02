from __future__ import annotations

import pytest
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.reporting.processor import EvidenceProcessor


def test_five_evidence_items_deduplication_and_severity_sorting():
    """Acceptance Criteria Test: Ingest 5 Evidence items, verify deduplication and severity sorting."""
    processor = EvidenceProcessor(default_target="example.com")

    # Item 1: High SQLi on api.example.com /api/v1/search?q
    ev1 = Evidence(
        evidence_id="ev-001",
        category="sql_injection",
        severity="high",
        confidence=0.80,
        title="SQLi in Search",
        metadata={
            "host": "api.example.com",
            "endpoint": "/api/v1/search",
            "parameter": "q",
            "tags": ["sqli"],
        },
    )

    # Item 2: Critical SQLi on api.example.com /api/v1/search?q (DUPLICATE of item 1 with higher severity & payload)
    ev2 = Evidence(
        evidence_id="ev-002",
        category="sql_injection",
        severity="critical",
        confidence=0.95,
        title="Critical SQL Injection in /api/v1/search",
        metadata={
            "host": "api.example.com",
            "endpoint": "/api/v1/search",
            "parameter": "q",
            "payload": "' UNION SELECT 1,2,database()--",
            "tags": ["sqli", "cve"],
        },
    )

    # Item 3: High BAC / IDOR on api.example.com /api/v1/users?id
    ev3 = Evidence(
        evidence_id="ev-003",
        category="broken_access_control",
        severity="high",
        confidence=0.90,
        title="BOLA in User Profile",
        metadata={
            "host": "api.example.com",
            "endpoint": "/api/v1/users",
            "parameter": "id",
            "payload": "user_id=1002",
        },
    )

    # Item 4: Medium Reflected XSS on app.example.com /profile?name
    ev4 = Evidence(
        evidence_id="ev-004",
        category="reflected_xss",
        severity="medium",
        confidence=0.85,
        title="Reflected XSS in Profile",
        metadata={
            "host": "app.example.com",
            "endpoint": "/profile",
            "parameter": "name",
            "payload": "<script>alert(document.domain)</script>",
        },
    )

    # Item 5: Low Information Disclosure on api.example.com /debug
    ev5 = Evidence(
        evidence_id="ev-005",
        category="information_disclosure",
        severity="low",
        confidence=0.70,
        title="Server Version Banner Leaked",
        metadata={
            "host": "api.example.com",
            "endpoint": "/debug",
        },
    )

    evidence_items = [ev1, ev2, ev3, ev4, ev5]
    report = processor.process(evidence_items, target="example.com", mission_id="mission-test-5")

    # 1. Summary validation
    assert report.summary.total_evidence_items == 5
    assert report.summary.total_findings == 4
    assert report.summary.deduplicated_count == 1
    assert report.summary.severity_counts["critical"] == 1
    assert report.summary.severity_counts["high"] == 1
    assert report.summary.severity_counts["medium"] == 1
    assert report.summary.severity_counts["low"] == 1
    assert report.summary.severity_counts["info"] == 0

    # 2. Check deduplicated finding (SQL Injection)
    sqli_finding = next(f for f in report.findings if f.category == "sql_injection")
    assert sqli_finding.duplicate_count == 2
    assert set(sqli_finding.evidence_ids) == {"ev-001", "ev-002"}
    assert sqli_finding.severity == "critical"
    assert sqli_finding.cvss.score >= 9.0  # Critical >= 9.0
    assert sqli_finding.confidence == 0.95
    assert sqli_finding.payload == "' UNION SELECT 1,2,database()--"
    assert "cve" in sqli_finding.tags

    # 3. Check Severity Sorting Order: Critical -> High -> Medium -> Low
    assert len(report.findings) == 4
    assert report.findings[0].severity == "critical"
    assert report.findings[0].cvss.score >= 9.0
    assert report.findings[1].severity == "high"
    assert 7.0 <= report.findings[1].cvss.score <= 8.9
    assert report.findings[2].severity == "medium"
    assert 4.0 <= report.findings[2].cvss.score <= 6.9
    assert report.findings[3].severity == "low"
    assert 0.1 <= report.findings[3].cvss.score <= 3.9

    # 4. Check Grouping by Category
    assert len(report.grouped_by_category) == 4
    assert len(report.grouped_by_category["sql_injection"]) == 1
    assert len(report.grouped_by_category["broken_access_control"]) == 1
    assert len(report.grouped_by_category["reflected_xss"]) == 1
    assert len(report.grouped_by_category["information_disclosure"]) == 1

    # 5. Check Grouping by Host
    assert len(report.grouped_by_host) == 2
    assert len(report.grouped_by_host["api.example.com"]) == 3
    assert len(report.grouped_by_host["app.example.com"]) == 1


def test_evidence_store_ingestion():
    store = EvidenceStore()
    ev = Evidence(
        evidence_id="ev-101",
        category="csrf",
        severity="medium",
        metadata={"host": "bank.example.com", "endpoint": "/transfer"},
    )
    store.add(ev)

    processor = EvidenceProcessor()
    report = processor.process(store, target="bank.example.com")

    assert report.summary.total_evidence_items == 1
    assert report.summary.total_findings == 1
    assert report.findings[0].category == "csrf"
    assert report.findings[0].cvss.score >= 4.0
    assert report.findings[0].cvss.score <= 6.9


def test_empty_evidence_processing():
    processor = EvidenceProcessor()
    report = processor.process([], target="empty.com")

    assert report.summary.total_evidence_items == 0
    assert report.summary.total_findings == 0
    assert report.summary.deduplicated_count == 0
    assert len(report.findings) == 0
    assert len(report.grouped_by_category) == 0
    assert len(report.grouped_by_host) == 0


def test_url_parsing_and_step_generation():
    ev = Evidence(
        evidence_id="ev-url",
        category="ssrf",
        severity="high",
        metadata={
            "url": "https://service.internal.corp:8443/webhook?callback=http://169.254.169.254/latest/meta-data/",
            "payload": "http://169.254.169.254/latest/meta-data/",
        },
    )

    processor = EvidenceProcessor()
    report = processor.process([ev])

    f = report.findings[0]
    assert f.host == "service.internal.corp:8443"
    assert f.endpoint.startswith("/webhook")
    assert f.cwe is not None
    assert f.cwe.id == "CWE-918"
    assert len(f.steps_to_reproduce) >= 1
    assert "169.254.169.254" in f.impact or "cloud metadata" in f.impact or "internal" in f.impact
