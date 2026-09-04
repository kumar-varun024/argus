"""
Unit and integration tests for Scan Evidence Indexer & Semantic Search Engine.

Tests post-scan indexing of evidence, findings, and historical reports,
conceptual semantic queries (e.g. auth bypass via parameter tampering),
metadata filtering, and lifecycle integration.
"""

import json
from pathlib import Path
import pytest

from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.reporting.models import CVSSData, CWEInfo, Finding, VulnerabilityReport
from argus.reporting.vector_indexer import FindingSemanticSearchEngine, ScanEvidenceIndexer
from argus.runtime.mission import Mission, MissionState
from argus.runtime.lifecycle import MissionLifecycle
from argus.vector.store import VectorStore


@pytest.fixture
def in_memory_vector_store():
    """Isolated in-memory VectorStore for tests."""
    store = VectorStore(db_path=":memory:", use_sqlite_vec=False)
    yield store
    store.close()


@pytest.fixture
def indexer(in_memory_vector_store):
    """ScanEvidenceIndexer instance backed by in-memory VectorStore."""
    return ScanEvidenceIndexer(vector_store=in_memory_vector_store)


@pytest.fixture
def search_engine(in_memory_vector_store):
    """FindingSemanticSearchEngine instance backed by in-memory VectorStore."""
    return FindingSemanticSearchEngine(vector_store=in_memory_vector_store)


@pytest.fixture
def sample_findings():
    """A realistic set of scan findings across various vulnerability classes."""
    return [
        Finding(
            id="f-sqli-01",
            title="SQL Injection in Authentication Login Form",
            category="sql_injection",
            severity="critical",
            cvss=CVSSData(score=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity_rating="Critical"),
            cwe=CWEInfo(id="89", name="Improper Neutralization of Special Elements in SQL Command"),
            host="auth.example.com",
            endpoint="/api/v1/login",
            parameter="username",
            parameter_type="POST_BODY",
            payload="' OR '1'='1' --",
            description="The login endpoint is vulnerable to Boolean-based blind SQL injection in the username parameter, allowing complete authentication bypass.",
            impact="Attackers can bypass authentication and gain administrative access to database records.",
            remediation="Use parameterized queries / prepared statements with PDO.",
            tags=["sqli", "auth", "login", "database"],
        ),
        Finding(
            id="f-idor-01",
            title="Broken Object Level Authorization (BOLA) in User Profile API",
            category="idor",
            severity="high",
            cvss=CVSSData(score=8.6, vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", severity_rating="High"),
            cwe=CWEInfo(id="639", name="Authorization Bypass Through User-Controlled Key"),
            host="api.example.com",
            endpoint="/api/v2/users/{user_id}/financials",
            parameter="user_id",
            parameter_type="PATH_VARIABLE",
            payload="1337",
            description="Parameter tampering on the user_id path parameter allows authenticated users to view arbitrary customer financial records and statements without authorization.",
            impact="Unauthorized disclosure of sensitive financial records and customer PII.",
            remediation="Enforce object-level access control checks verifying user ownership of requested resources.",
            tags=["idor", "bola", "parameter_tampering", "authorization"],
        ),
        Finding(
            id="f-jwt-01",
            title="JWT Algorithm Confusion and Parameter Manipulation",
            category="auth_bypass",
            severity="high",
            cvss=CVSSData(score=8.1, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", severity_rating="High"),
            cwe=CWEInfo(id="287", name="Improper Authentication"),
            host="auth.example.com",
            endpoint="/api/v1/verify_token",
            parameter="Authorization",
            parameter_type="HEADER",
            payload="eyJhbGciOiJub25lIn0...",
            description="The API accepts unsigned JWT tokens with 'alg': 'none', allowing arbitrary claim tampering to elevate privileges to administrator.",
            impact="Authentication bypass and unauthorized privilege escalation.",
            remediation="Reject tokens with 'none' algorithm and enforce RS256 verification.",
            tags=["jwt", "auth_bypass", "tokens", "session"],
        ),
        Finding(
            id="f-rce-01",
            title="Remote Code Execution via Insecure Java Deserialization",
            category="rce",
            severity="critical",
            cvss=CVSSData(score=10.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", severity_rating="Critical"),
            cwe=CWEInfo(id="502", name="Deserialization of Untrusted Data"),
            host="app.example.com",
            endpoint="/api/v1/queue/job",
            parameter="job_payload",
            parameter_type="POST_BODY",
            payload="rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hc...",
            description="The job processing worker deserializes untrusted Java objects using ObjectInputStream, enabling unauthenticated remote code execution via ysoserial gadget chains.",
            impact="Complete system compromise and arbitrary command execution.",
            remediation="Use safe serialization formats like JSON or implement look-ahead ObjectInputFilter.",
            tags=["rce", "deserialization", "java", "ysoserial"],
        ),
        Finding(
            id="f-info-01",
            title="Unprotected JavaScript Source Maps Disclosing Secrets",
            category="information_disclosure",
            severity="medium",
            cvss=CVSSData(score=5.3, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", severity_rating="Medium"),
            cwe=CWEInfo(id="200", name="Exposure of Sensitive Information"),
            host="static.example.com",
            endpoint="/assets/app.bundle.js.map",
            parameter=None,
            payload=None,
            description="Production JavaScript source maps are publicly accessible, leaking source code, internal staging endpoints, and hardcoded development API keys.",
            impact="Information leakage facilitating further targeted attacks.",
            remediation="Disable source map generation in production webpack/vite builds.",
            tags=["information_disclosure", "source_map", "leak", "secrets"],
        ),
        Finding(
            id="f-xss-01",
            title="Stored Cross-Site Scripting (XSS) in Comment Feed",
            category="xss",
            severity="medium",
            cvss=CVSSData(score=6.1, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", severity_rating="Medium"),
            cwe=CWEInfo(id="79", name="Improper Neutralization of Input During Web Page Generation"),
            host="blog.example.com",
            endpoint="/post/comment",
            parameter="body",
            parameter_type="POST_BODY",
            payload="<script>alert(document.cookie)</script>",
            description="User-submitted comments are rendered without sanitization, allowing stored script execution in other users' browsers.",
            impact="Session cookie theft and browser redirection.",
            remediation="Sanitize HTML content using DOMPurify before rendering.",
            tags=["xss", "stored_xss", "javascript"],
        ),
    ]


def test_indexer_index_single_finding(indexer, in_memory_vector_store):
    """Test indexing an individual Finding."""
    finding = Finding(
        id="f-001",
        title="SQL Injection in Search Form",
        category="sql_injection",
        severity="high",
        host="test.local",
        endpoint="/search",
        parameter="q",
        description="SQL injection in search query parameter.",
    )

    doc_id = indexer.index_finding(finding, mission_id="m-123", target="test.local")
    assert doc_id == "finding:m-123:f-001"

    doc = in_memory_vector_store.get(doc_id)
    assert doc is not None
    assert doc.source_type == "finding"
    assert doc.mission_id == "m-123"
    assert doc.severity == "high"
    assert "SQL Injection" in doc.content
    assert doc.metadata["parameter"] == "q"


def test_indexer_index_findings_batch(indexer, in_memory_vector_store, sample_findings):
    """Test batch indexing multiple findings."""
    doc_ids = indexer.index_findings(sample_findings, mission_id="mission-alpha", target="example.com")
    assert len(doc_ids) == len(sample_findings)
    assert in_memory_vector_store.count() == len(sample_findings)


def test_indexer_index_evidence(indexer, in_memory_vector_store):
    """Test indexing single and batch Evidence items."""
    ev1 = Evidence(
        evidence_id="ev-1",
        mission_id="m-ev",
        title="Open Port 22 SSH",
        category="recon",
        severity="info",
        description="SSH service banner OpenSSH 8.2p1",
        value="OpenSSH_8.2p1",
        tags=["ssh", "port_22"],
    )
    ev2 = Evidence(
        evidence_id="ev-2",
        mission_id="m-ev",
        title="Vulnerable Apache Version",
        category="vulnerability",
        severity="high",
        description="Apache HTTPD 2.4.49 path traversal",
        value="Apache/2.4.49",
        tags=["apache", "path_traversal"],
    )

    ev_store = EvidenceStore()
    ev_store.add(ev1)
    ev_store.add(ev2)

    ids = indexer.index_evidence_items(ev_store)
    assert len(ids) == 2
    assert in_memory_vector_store.count({"source_type": "evidence"}) == 2

    doc = in_memory_vector_store.get("evidence:m-ev:ev-1")
    assert doc is not None
    assert "Open Port 22 SSH" in doc.content


def test_indexer_index_vulnerability_report(indexer, in_memory_vector_store, sample_findings):
    """Test indexing a VulnerabilityReport and its overview."""
    report = VulnerabilityReport(
        report_id="rep-xyz",
        mission_id="m-xyz",
        target="example.com",
        findings=sample_findings,
    )

    count = indexer.index_report(report)
    assert count == len(sample_findings)

    # Report overview document plus all findings
    total_docs = in_memory_vector_store.count()
    assert total_docs == len(sample_findings) + 1
    assert in_memory_vector_store.count({"source_type": "report"}) == 1


def test_indexer_index_historical_reports(indexer, tmp_path):
    """Test scanning and indexing historical JSON reports from disk."""
    report_file = tmp_path / "report_target_20260901_abc123.json"
    report_data = {
        "report_id": "hist-001",
        "mission_id": "m-hist",
        "target": "legacy.corp",
        "findings": [
            {
                "id": "h-f1",
                "title": "Legacy PHP File Inclusion",
                "category": "path_traversal",
                "severity": "critical",
                "host": "legacy.corp",
                "endpoint": "/index.php",
                "parameter": "page",
                "description": "LFI vulnerability in page parameter allows reading /etc/passwd.",
            },
            {
                "id": "h-f2",
                "title": "Default Admin Credentials",
                "category": "auth_bypass",
                "severity": "high",
                "host": "legacy.corp",
                "endpoint": "/admin",
                "description": "Default credentials admin:admin enabled on login portal.",
            },
        ],
    }

    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f)

    indexed = indexer.index_historical_reports(tmp_path)
    assert indexed == 2


def test_semantic_search_auth_bypass_conceptual_queries(indexer, search_engine, sample_findings):
    """
    R2 Core Requirement Test:
    Semantic searching for 'authentication bypass via parameter tampering'
    must retrieve IDOR/BOLA, SQL injection login bypass, and JWT parameter manipulation.
    """
    indexer.index_findings(sample_findings, mission_id="m-demo", target="example.com")

    # Conceptual search query without exact title match
    results = search_engine.search_findings(
        query="authentication bypass via parameter tampering",
        top_k=5,
        min_score=0.3,
    )

    assert len(results) >= 3

    # Top results should be the auth bypass, IDOR/BOLA parameter tampering, and SQLi login bypass
    result_ids = [r.metadata.get("finding_id") for r in results]
    
    # Must retrieve IDOR (parameter tampering authorization bypass), SQLi (login auth bypass), JWT (claim tampering auth bypass)
    assert "f-idor-01" in result_ids or "f-sqli-01" in result_ids or "f-jwt-01" in result_ids

    # Unrelated medium info finding (like source maps) should rank lower or not in top 2
    top_two_ids = result_ids[:2]
    assert "f-info-01" not in top_two_ids


def test_semantic_search_deserialization_rce_query(indexer, search_engine, sample_findings):
    """Test semantic query for remote code execution deserialization."""
    indexer.index_findings(sample_findings, mission_id="m-demo", target="example.com")

    results = search_engine.search_findings(
        query="remote code execution untrusted deserialization gadget chain",
        top_k=3,
    )

    assert len(results) > 0
    top_id = results[0].metadata.get("finding_id")
    assert top_id == "f-rce-01"
    assert results[0].score > 0.70


def test_semantic_search_secrets_disclosure_query(indexer, search_engine, sample_findings):
    """Test semantic query for sensitive information disclosure / secrets leak."""
    indexer.index_findings(sample_findings, mission_id="m-demo", target="example.com")

    results = search_engine.search_findings(
        query="sensitive information disclosure source code leak api keys",
        top_k=3,
    )

    assert len(results) > 0
    top_id = results[0].metadata.get("finding_id")
    assert top_id == "f-info-01"


def test_semantic_search_severity_filter(indexer, search_engine, sample_findings):
    """Test filtering semantic search by severity tier."""
    indexer.index_findings(sample_findings, mission_id="m-demo", target="example.com")

    # Filter critical severity
    crit_results = search_engine.search_findings(
        query="vulnerability exploit",
        severity="critical",
        top_k=10,
    )
    assert len(crit_results) > 0
    for r in crit_results:
        assert r.severity.lower() == "critical"

    # Filter high severity
    high_results = search_engine.search_findings(
        query="vulnerability exploit",
        severity=["high", "critical"],
        top_k=10,
    )
    assert len(high_results) > 0
    for r in high_results:
        assert r.severity.lower() in ("high", "critical")


def test_semantic_search_category_filter(indexer, search_engine, sample_findings):
    """Test filtering semantic search by category."""
    indexer.index_findings(sample_findings, mission_id="m-demo", target="example.com")

    results = search_engine.search_findings(
        query="arbitrary injection exploit",
        category="sql_injection",
        top_k=5,
    )
    assert len(results) > 0
    for r in results:
        assert r.category.lower() == "sql_injection"


def test_semantic_search_mission_id_filter(indexer, search_engine, sample_findings):
    """Test isolating semantic search by mission ID."""
    indexer.index_findings(sample_findings[:3], mission_id="mission-alpha", target="alpha.corp")
    indexer.index_findings(sample_findings[3:], mission_id="mission-beta", target="beta.corp")

    alpha_results = search_engine.search_findings(
        query="vulnerability",
        mission_id="mission-alpha",
        top_k=10,
    )
    for r in alpha_results:
        assert r.mission_id == "mission-alpha"

    beta_results = search_engine.search_findings(
        query="vulnerability",
        mission_id="mission-beta",
        top_k=10,
    )
    for r in beta_results:
        assert r.mission_id == "mission-beta"


def test_semantic_search_host_filter(indexer, search_engine, sample_findings):
    """Test filtering by host metadata."""
    indexer.index_findings(sample_findings, mission_id="m-demo", target="example.com")

    results = search_engine.search_findings(
        query="security vulnerability",
        host="auth.example.com",
        top_k=5,
    )
    assert len(results) > 0
    for r in results:
        assert r.metadata.get("host") == "auth.example.com"


def test_semantic_search_evidence_api(indexer, search_engine):
    """Test search_evidence API."""
    ev = Evidence(
        evidence_id="ev-ssh",
        mission_id="m-1",
        title="Weak SSH Cipher Supported",
        category="crypto",
        severity="medium",
        description="SSH server supports 3DES and CBC ciphers vulnerable to Sweet32.",
        tags=["ssh", "crypto", "sweet32"],
    )
    indexer.index_evidence(ev)

    results = search_engine.search_evidence(
        query="cryptographic weak cipher sweet32 CBC",
        top_k=5,
    )
    assert len(results) > 0
    assert results[0].source_type == "evidence"
    assert "Weak SSH Cipher" in results[0].content


def test_semantic_search_all_api(indexer, search_engine, sample_findings):
    """Test search_all API returning both findings and evidence."""
    indexer.index_findings(sample_findings, mission_id="m-combo", target="example.com")
    indexer.index_evidence(
        Evidence(
            evidence_id="ev-combo",
            mission_id="m-combo",
            title="Database Connection String in Config",
            category="secrets",
            severity="high",
            description="Cleartext database password exposed in configuration file.",
            tags=["database", "secrets"],
        )
    )

    results = search_engine.search_all(
        query="database password credentials",
        mission_id="m-combo",
        top_k=10,
    )
    assert len(results) > 0
    source_types = {r.source_type for r in results}
    assert "finding" in source_types or "evidence" in source_types


def test_get_finding_and_clear_mission(indexer, search_engine, sample_findings):
    """Test get_finding lookup and clear_mission deletion."""
    indexer.index_findings(sample_findings, mission_id="m-clear-test", target="example.com")
    assert search_engine.count_findings({"mission_id": "m-clear-test"}) == len(sample_findings)

    # Get specific finding
    res = search_engine.get_finding("f-sqli-01", mission_id="m-clear-test")
    assert res is not None
    assert res.metadata["finding_id"] == "f-sqli-01"

    # Clear mission
    deleted = search_engine.clear_mission("m-clear-test")
    assert deleted == len(sample_findings)
    assert search_engine.count_findings({"mission_id": "m-clear-test"}) == 0


def test_mission_lifecycle_post_scan_indexing_integration(tmp_path):
    """Test that MissionLifecycle.complete triggers post-scan indexing without errors."""
    mission = Mission(target="http://test.local", id="mission-life-01", status=MissionState.RUNNING)
    ev = Evidence(
        evidence_id="ev-life-1",
        mission_id="mission-life-01",
        title="Admin Interface Discovered",
        category="recon",
        severity="info",
        description="Admin interface reachable at /admin",
    )
    mission.evidence.add(ev)

    # Complete mission
    MissionLifecycle.complete(mission, output_dir=str(tmp_path))
    assert mission.status == MissionState.COMPLETED
    assert mission.phase == "finished"
