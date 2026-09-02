import json
import pytest
from uuid import uuid4

from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.reporting.cvss import CVSSCalculator, cvss_roundup
from argus.reporting.generator import ReportGenerator
from argus.reporting.json import JSONReportRenderer
from argus.reporting.markdown import HackerOneMarkdownRenderer
from argus.reporting.models import (
    CVSSData,
    Finding,
    ReportSeverity,
    ReportSummary,
    VulnerabilityReport,
)
from argus.reporting.processor import EvidenceProcessor


class TestChallengerDeduplicationAndSorting:
    """Adversarial stress-testing of evidence deduplication and deterministic sorting."""

    def test_five_evidence_deduplication_and_severity_upgrade(self):
        """Verify: 5 evidence items with duplicate category/host/endpoint/param and varied severities.
        
        Item 1: sqli, host=api.example.com, endpoint=/v1/users, param=id, sev=low
        Item 2: sqli, host=api.example.com, endpoint=/v1/users, param=id, sev=medium
        Item 3: sqli, host=api.example.com, endpoint=/v1/users, param=id, sev=critical
        Item 4: xss, host=app.example.com, endpoint=/search, param=q, sev=low
        Item 5: xss, host=app.example.com, endpoint=/search, param=q, sev=high
        """
        store = EvidenceStore()
        
        # 3 duplicate SQLi items
        ev1 = Evidence(
            evidence_id="ev-1",
            category="sqli",
            title="SQLi Low",
            description="SQL Injection low finding",
            severity="low",
            confidence=0.5,
            metadata={"host": "api.example.com", "endpoint": "/v1/users", "parameter": "id"},
        )
        ev2 = Evidence(
            evidence_id="ev-2",
            category="sqli",
            title="SQLi Medium",
            description="SQL Injection medium finding",
            severity="medium",
            confidence=0.8,
            metadata={"host": "api.example.com", "endpoint": "/v1/users", "parameter": "id"},
        )
        ev3 = Evidence(
            evidence_id="ev-3",
            category="sqli",
            title="SQLi Critical",
            description="SQL Injection critical finding",
            severity="critical",
            confidence=0.95,
            metadata={"host": "api.example.com", "endpoint": "/v1/users", "parameter": "id"},
        )
        
        # 2 duplicate XSS items
        ev4 = Evidence(
            evidence_id="ev-4",
            category="xss",
            title="XSS Low",
            description="XSS low finding",
            severity="low",
            confidence=0.6,
            metadata={"host": "app.example.com", "endpoint": "/search", "parameter": "q"},
        )
        ev5 = Evidence(
            evidence_id="ev-5",
            category="xss",
            title="XSS High",
            description="XSS high finding",
            severity="high",
            confidence=0.9,
            metadata={"host": "app.example.com", "endpoint": "/search", "parameter": "q"},
        )

        for ev in [ev1, ev2, ev3, ev4, ev5]:
            store.add(ev)

        generator = ReportGenerator()
        report = generator.generate_from_evidence(store, target="example.com", mission_id="mission-stress-5")

        # 1. Total counts
        assert report.summary.total_evidence_items == 5
        assert report.summary.total_findings == 2
        assert report.summary.deduplicated_count == 3
        assert len(report.findings) == 2

        # 2. Severity Sorting: Critical must come before High
        assert report.findings[0].severity == "critical"
        assert report.findings[0].category == "sqli"
        assert report.findings[0].duplicate_count == 3
        assert set(report.findings[0].evidence_ids) == {"ev-1", "ev-2", "ev-3"}
        assert report.findings[0].cvss.score >= 9.0
        assert report.findings[0].confidence == 0.95

        assert report.findings[1].severity == "high"
        assert report.findings[1].category == "xss"
        assert report.findings[1].duplicate_count == 2
        assert set(report.findings[1].evidence_ids) == {"ev-4", "ev-5"}
        assert 7.0 <= report.findings[1].cvss.score <= 8.9
        assert report.findings[1].confidence == 0.9

    def test_full_severity_hierarchy_sorting(self):
        """Verify strict sorting order: Critical -> High -> Medium -> Low -> Info."""
        items = [
            Evidence(category="info_cat", severity="info", title="Info Finding", metadata={"host": "h1", "endpoint": "/info"}),
            Evidence(category="low_cat", severity="low", title="Low Finding", metadata={"host": "h1", "endpoint": "/low"}),
            Evidence(category="med_cat", severity="medium", title="Medium Finding", metadata={"host": "h1", "endpoint": "/med"}),
            Evidence(category="high_cat", severity="high", title="High Finding", metadata={"host": "h1", "endpoint": "/high"}),
            Evidence(category="crit_cat", severity="critical", title="Critical Finding", metadata={"host": "h1", "endpoint": "/crit"}),
        ]
        processor = EvidenceProcessor()
        report = processor.process(items)

        severities = [f.severity for f in report.findings]
        assert severities == ["critical", "high", "medium", "low", "info"]

    def test_sorting_tiebreak_by_cvss_then_title(self):
        """Verify secondary sorting by CVSS score descending, and tertiary by title alphabetical."""
        items = [
            Evidence(category="high_b", severity="high", title="Beta High", metadata={"host": "h1", "endpoint": "/b", "cvss_score": 7.5}),
            Evidence(category="high_a", severity="high", title="Alpha High", metadata={"host": "h1", "endpoint": "/a", "cvss_score": 8.5}),
            Evidence(category="high_c", severity="high", title="Gamma High", metadata={"host": "h1", "endpoint": "/c", "cvss_score": 7.5}),
        ]
        processor = EvidenceProcessor()
        report = processor.process(items)

        assert report.findings[0].title == "Alpha High"  # CVSS 8.5
        assert report.findings[1].title == "Beta High"   # CVSS 7.5 (alphabetical 'b')
        assert report.findings[2].title == "Gamma High"  # CVSS 7.5 (alphabetical 'g')

    def test_whitespace_and_case_insensitive_dedup(self):
        """Verify deduplication handles uppercase and whitespace variations in keys."""
        items = [
            Evidence(category="SQLI", severity="low", metadata={"host": "API.TARGET.COM ", "endpoint": "/V1/Users", "parameter": " ID "}),
            Evidence(category="sqli ", severity="high", metadata={"host": "api.target.com", "endpoint": "/v1/users", "parameter": "id"}),
        ]
        processor = EvidenceProcessor()
        report = processor.process(items)
        assert len(report.findings) == 1
        assert report.findings[0].duplicate_count == 2
        assert report.findings[0].severity == "high"


class TestChallengerCVSSCalculations:
    """Adversarial stress-testing of CVSS v3.1 mathematical calculations and boundaries."""

    @pytest.mark.parametrize(
        "vector,expected_score,expected_severity",
        [
            # FIRST Specification Examples & Standard Vectors
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, ReportSeverity.CRITICAL),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, ReportSeverity.CRITICAL),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1, ReportSeverity.HIGH),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, ReportSeverity.HIGH),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, ReportSeverity.MEDIUM),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4, ReportSeverity.MEDIUM),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 6.5, ReportSeverity.MEDIUM),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, ReportSeverity.LOW),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N", 1.6, ReportSeverity.LOW),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, ReportSeverity.INFO),
            # Specific CVE Benchmarks
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, ReportSeverity.HIGH), # CVE-2014-2005
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H", 7.7, ReportSeverity.HIGH), # CVE-2012-1516
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, ReportSeverity.HIGH), # WordPress SOP
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, ReportSeverity.HIGH), # GHOST CVE-2015-0235
            ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8, ReportSeverity.HIGH), # D-Link DIR-600
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, ReportSeverity.MEDIUM), # MySQL CVE-2013-0375
        ],
    )
    def test_first_benchmark_vectors(self, vector, expected_score, expected_severity):
        score = CVSSCalculator.calculate_base_score(vector)
        assert score == expected_score
        severity = CVSSCalculator.score_to_severity(score)
        assert severity == expected_severity

    @pytest.mark.parametrize(
        "score,expected_severity",
        [
            (10.0, ReportSeverity.CRITICAL),
            (9.0, ReportSeverity.CRITICAL),
            (8.9, ReportSeverity.HIGH),
            (7.0, ReportSeverity.HIGH),
            (6.9, ReportSeverity.MEDIUM),
            (4.0, ReportSeverity.MEDIUM),
            (3.9, ReportSeverity.LOW),
            (0.1, ReportSeverity.LOW),
            (0.0, ReportSeverity.INFO),
            (-1.0, ReportSeverity.INFO),
        ],
    )
    def test_severity_boundary_scores(self, score, expected_severity):
        assert CVSSCalculator.score_to_severity(score) == expected_severity

    def test_cvss_roundup_precision(self):
        """Verify mathematical behavior of cvss_roundup against rounding quirks."""
        assert cvss_roundup(4.0) == 4.0
        assert cvss_roundup(4.00000) == 4.0
        assert cvss_roundup(4.00001) == 4.1
        assert cvss_roundup(4.01) == 4.1
        assert cvss_roundup(4.09) == 4.1
        assert cvss_roundup(4.10) == 4.1
        assert cvss_roundup(0.0) == 0.0


class TestChallengerMarkdownCompleteness:
    """Adversarial testing of Markdown report structure and required HackerOne sections."""

    def test_markdown_required_sections_present(self):
        generator = ReportGenerator()
        finding = Finding(
            id="find-123",
            title="Remote Code Execution in File Upload",
            category="rce",
            severity="critical",
            cvss=CVSSData(score=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity_rating="Critical"),
            host="app.example.com",
            endpoint="/api/v1/upload",
            parameter="file",
            parameter_type="multipart/form-data",
            payload="<?php phpinfo(); ?>",
            description="Arbitrary file upload leads to RCE.",
            steps_to_reproduce=[
                "Upload malicious PHP shell to `/api/v1/upload`.",
                "Access `/uploads/shell.php`.",
                "Observe command execution output.",
            ],
            impact="Complete server compromise and loss of data confidentiality and integrity.",
            remediation="Enforce file extension allowlists and store uploaded files outside web root.",
            confidence=1.0,
            status="CONFIRMED",
            evidence_ids=["ev-rce-1"],
            duplicate_count=1,
        )
        report = VulnerabilityReport(
            report_id="rep-1",
            mission_id="mission-md-check",
            target="app.example.com",
            findings=[finding],
            summary=ReportSummary(
                total_findings=1,
                total_evidence_items=1,
                deduplicated_count=0,
                severity_counts={"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
            ),
        )

        md = generator.render_markdown(report)

        # 1. Document Header & Title
        assert "# Vulnerability Assessment Report — app.example.com" in md
        assert "### Finding 1: Remote Code Execution in File Upload" in md
        # 2. Severity
        assert "**CRITICAL**" in md
        # 3. CVSS Score & Vector
        assert "**CVSS v3.1 Score**" in md
        assert "**9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)" in md
        # 4. Steps to Reproduce
        assert "#### Steps to Reproduce" in md
        assert "1. Upload malicious PHP shell to `/api/v1/upload`." in md
        assert "2. Access `/uploads/shell.php`." in md
        assert "3. Observe command execution output." in md
        # 5. Impact Analysis
        assert "#### Impact Analysis" in md
        assert "Complete server compromise" in md
        # 6. Recommended Remediation
        assert "#### Recommended Remediation" in md
        assert "Enforce file extension allowlists" in md
        # 7. Proof of Concept Payload
        assert "#### Proof of Concept Payload" in md
        assert "<?php phpinfo(); ?>" in md


class TestChallengerJSONSchemaAndParsing:
    """Adversarial testing of JSON output, schema compliance, and lossless roundtripping."""

    def test_json_loads_and_schema_validation(self):
        generator = ReportGenerator()
        finding = Finding(
            id="f-1",
            title="Reflected XSS",
            category="xss",
            severity="medium",
            cvss=CVSSData(score=6.1, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", severity_rating="Medium"),
            host="xss.target.com",
            endpoint="/search",
            parameter="q",
            payload="<script>alert(1)</script>",
            description="Reflected XSS in search query.",
            steps_to_reproduce=["Navigate to /search?q=<script>alert(1)</script>"],
            impact="Execute arbitrary JavaScript in victim context.",
            remediation="Contextually encode output and configure CSP.",
            confidence=0.9,
            status="CONFIRMED",
            evidence_ids=["ev-xss-1"],
            duplicate_count=2,
            tags=["owasp-top-10", "web"],
            references=["https://owasp.org/www-community/attacks/xss/"],
            metadata={"browser": "headless-chrome"},
        )
        report = VulnerabilityReport(
            report_id="rep-json-1",
            mission_id="mission-json-check",
            target="xss.target.com",
            findings=[finding],
            summary=ReportSummary(
                total_findings=1,
                total_evidence_items=2,
                deduplicated_count=1,
                severity_counts={"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
                category_counts={"xss": 1},
                host_counts={"xss.target.com": 1},
            ),
            grouped_by_category={"xss": [finding]},
            grouped_by_host={"xss.target.com": [finding]},
        )

        json_str = generator.render_json(report)

        # 1. Parse with json.loads
        data = json.loads(json_str)

        # 2. Check top-level schema fields
        required_top_level = [
            "report_id", "mission_id", "target", "generated_at",
            "generator_version", "summary", "findings",
            "grouped_by_category", "grouped_by_host",
        ]
        for field in required_top_level:
            assert field in data, f"Missing required top-level field: {field}"

        # 3. Check summary schema fields
        required_summary_fields = [
            "total_findings", "total_evidence_items", "deduplicated_count",
            "severity_counts", "category_counts", "host_counts",
        ]
        for field in required_summary_fields:
            assert field in data["summary"], f"Missing summary field: {field}"

        # 4. Check finding schema fields
        assert len(data["findings"]) == 1
        f_data = data["findings"][0]
        required_finding_fields = [
            "id", "title", "category", "severity", "cvss", "cwe",
            "host", "endpoint", "parameter", "parameter_type", "payload",
            "description", "steps_to_reproduce", "impact", "remediation",
            "confidence", "status", "evidence_ids", "duplicate_count",
            "tags", "references", "metadata",
        ]
        for field in required_finding_fields:
            assert field in f_data, f"Missing finding field: {field}"

        # 5. Check CVSS schema fields
        assert "score" in f_data["cvss"]
        assert "vector" in f_data["cvss"]
        assert "severity_rating" in f_data["cvss"]
        assert f_data["cvss"]["score"] == 6.1

    def test_json_lossless_roundtrip(self):
        """Verify report survives serialize -> deserialize -> serialize without loss."""
        generator = ReportGenerator()
        finding = Finding(
            id=str(uuid4()),
            title="BOLA in Order API",
            category="bola",
            severity="high",
            cvss=CVSSData(score=8.1, vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", severity_rating="High"),
            host="orders.example.com",
            endpoint="/api/orders/999",
            parameter="order_id",
            payload="999",
            description="BOLA flaw allowing unauthorized access to any user order.",
            steps_to_reproduce=["GET /api/orders/999 with user A token"],
            impact="Unauthorized PII and financial records access.",
            remediation="Enforce object-level authorization checks.",
            confidence=1.0,
            status="CONFIRMED",
            evidence_ids=["ev-bola-1"],
            duplicate_count=1,
            tags=["bola", "api-sec"],
            references=["https://cwe.mitre.org/data/definitions/639.html"],
            metadata={"method": "GET"},
        )
        report = VulnerabilityReport(
            report_id="rep-roundtrip",
            mission_id="mission-roundtrip",
            target="orders.example.com",
            findings=[finding],
            summary=ReportSummary(
                total_findings=1,
                total_evidence_items=1,
                deduplicated_count=0,
                severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
                category_counts={"bola": 1},
                host_counts={"orders.example.com": 1},
            ),
            grouped_by_category={"bola": [finding]},
            grouped_by_host={"orders.example.com": [finding]},
        )

        renderer = JSONReportRenderer()
        json_out = renderer.render(report)
        parsed_report = renderer.parse(json_out)
        json_out_2 = renderer.render(parsed_report)

        assert json.loads(json_out) == json.loads(json_out_2)
        assert parsed_report.findings[0].title == report.findings[0].title
        assert parsed_report.findings[0].cvss.score == report.findings[0].cvss.score
        assert parsed_report.summary.severity_counts == report.summary.severity_counts


class TestChallengerStressAndAdversarialInputs:
    """Adversarial stress testing with large batches, malformed inputs, and edge cases."""

    def test_thousand_evidence_items_stress(self):
        """Stress test: 1,000 evidence items across 50 simulated endpoints."""
        store = EvidenceStore()
        severities = ["info", "low", "medium", "high", "critical"]
        for i in range(1000):
            ep_idx = i % 50
            sev = severities[(i // 50) % 5]
            ev = Evidence(
                evidence_id=f"ev-{i}",
                category=f"cat_{ep_idx % 5}",
                title=f"Finding {i}",
                severity=sev,
                metadata={
                    "host": f"host{ep_idx % 3}.target.com",
                    "endpoint": f"/api/endpoint_{ep_idx}",
                    "parameter": f"param_{ep_idx}",
                },
            )
            store.add(ev)

        generator = ReportGenerator()
        report = generator.generate_from_evidence(store, target="target.com", mission_id="stress-1000")

        assert report.summary.total_evidence_items == 1000
        assert report.summary.total_findings == 50
        assert report.summary.deduplicated_count == 950
        # Since 1000/50 = 20 batches of 50 items, across 20 iterations, (i // 50) takes values 0 to 19,
        # which cycles through all severities including critical (index 4).
        # Thus every endpoint was touched by critical evidence and should be upgraded to critical.
        assert all(f.severity == "critical" for f in report.findings)
        assert all(f.duplicate_count == 20 for f in report.findings)
        assert len(report.findings[0].evidence_ids) == 20

    def test_empty_evidence_store(self):
        """Edge case: completely empty evidence store."""
        store = EvidenceStore()
        generator = ReportGenerator()
        report = generator.generate_from_evidence(store, target="empty.com", mission_id="empty-mission")

        assert report.summary.total_evidence_items == 0
        assert report.summary.total_findings == 0
        assert report.summary.deduplicated_count == 0
        assert len(report.findings) == 0

        md = generator.render_markdown(report)
        assert "*No vulnerabilities or security findings were identified.*" in md

        json_str = generator.render_json(report)
        parsed = json.loads(json_str)
        assert parsed["summary"]["total_findings"] == 0

    def test_malformed_evidence_missing_fields(self):
        """Edge case: Evidence with None metadata, empty strings, missing host/endpoint."""
        ev = Evidence(
            category="",
            title="",
            description="",
            severity=None,
            confidence=None,
            metadata=None,
        )
        processor = EvidenceProcessor()
        report = processor.process([ev], target="default.org")

        assert len(report.findings) == 1
        finding = report.findings[0]
        assert finding.category == "general"
        assert finding.severity == "info"
        assert finding.host == "default.org"
        assert finding.endpoint == "/"
        assert finding.confidence == 1.0
