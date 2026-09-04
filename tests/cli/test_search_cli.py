"""
Integration tests for ARGUS Search CLI commands (Sprint 31b).

Uses Typer's CliRunner to verify:
- 'argus search <query>' table and JSON formatting
- Multi-field filters: --type, --severity, --category, --mission, --top-k, --min-score, --verbose
- Subcommands: 'argus search cves', 'argus search memory', 'argus search stats'
- Empty results and error edge cases
- CLI app registration in argus.cli.app
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from typer.testing import CliRunner

from argus.cli.app import app
from argus.cli.search_cli import search_app
from argus.evidence.model import Evidence
from argus.knowledge.cve_kb import CVEKnowledgeBase
from argus.knowledge.cve_models import CVEEntry
from argus.memory.manager import MemoryManager
from argus.reporting.models import Finding
from argus.reporting.vector_indexer import ScanEvidenceIndexer
from argus.vector.embeddings import EmbeddingEngine
from argus.vector.models import VectorStoreConfig
from argus.vector.store import VectorStore

runner = CliRunner()


# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture
def temp_cli_db(tmp_path: Path) -> str:
    """Create a temporary populated database path for CLI integration tests."""
    db_path = str(tmp_path / "cli_search_test.db")
    config = VectorStoreConfig(db_path=db_path, dimension=384, use_sqlite_vec=False)
    engine = EmbeddingEngine(provider="deterministic", dimension=384)
    store = VectorStore(config=config, embedding_engine=engine)

    # 1. Index Findings
    indexer = ScanEvidenceIndexer(vector_store=store)
    indexer.index_finding(
        Finding(
            id="f-sqli-1",
            title="SQL Injection in Admin Portal",
            category="sql_injection",
            severity="critical",
            host="portal.example.com",
            endpoint="/admin/login",
            description="Classic error-based SQL injection vulnerability in username parameter.",
        ),
        mission_id="mission_alpha",
    )
    indexer.index_finding(
        Finding(
            id="f-xss-1",
            title="Cross-Site Scripting in Comments",
            category="xss",
            severity="medium",
            host="blog.example.com",
            endpoint="/comments",
            description="Reflected XSS via comment field without script sanitization.",
        ),
        mission_id="mission_beta",
    )

    # 2. Index Evidence
    indexer.index_evidence(
        Evidence(
            evidence_id="ev-sqli-1",
            title="Database Error Leak Evidence",
            category="sql_injection",
            severity="critical",
            mission_id="mission_alpha",
            description="Leaked SQL syntax error disclosing PostgreSQL internal schema.",
        )
    )

    # 3. Ingest CVEs
    cve_kb = CVEKnowledgeBase(vector_store=store)
    cve_kb.ingest_entries(
        [
            CVEEntry(
                cve_id="CVE-2021-44228",
                title="Apache Log4j2 Remote Code Execution (Log4Shell)",
                description="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints resulting in RCE.",
                severity="critical",
                cvss_score=10.0,
                cwes=["CWE-502"],
                affected_products=["Apache Log4j", "log4j-core"],
            ),
            CVEEntry(
                cve_id="CVE-2022-22965",
                title="Spring Framework Remote Code Execution (Spring4Shell)",
                description="Spring MVC or Spring WebFlux applications allow RCE via data binding on JDK 9+.",
                severity="critical",
                cvss_score=9.8,
                cwes=["CWE-94"],
                affected_products=["Spring Framework", "Apache Tomcat"],
            ),
        ]
    )

    # 4. Record Memories
    mem_mgr = MemoryManager(vector_store=store)
    mem_mgr.record_attack_pattern(
        content="Injecting UNION SELECT 1,2,3 into search parameter bypasses basic WAF signatures.",
        title="WAF SQLi Bypass",
        mission_id="mission_alpha",
        tags=["waf", "sqli"],
    )
    mem_mgr.record_user_correction(
        content="Ignore port 8080 during web enumeration as it is a sandbox proxy.",
        title="Ignore Port 8080",
        mission_id="mission_alpha",
    )

    store.close()
    return db_path


@pytest.fixture
def empty_cli_db(tmp_path: Path) -> str:
    """Create an empty temporary database for negative testing."""
    db_path = str(tmp_path / "empty_search_test.db")
    config = VectorStoreConfig(db_path=db_path, dimension=384, use_sqlite_vec=False)
    engine = EmbeddingEngine(provider="deterministic", dimension=384)
    store = VectorStore(config=config, embedding_engine=engine)
    store.close()
    return db_path


# ==============================================================================
# 1. CLI App Registration & Help Tests
# ==============================================================================


def test_cli_search_registered_in_main_app():
    """Verify 'search' subcommand is registered in main Typer app."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "search" in result.stdout
    assert "Semantic search across" in result.stdout


def test_cli_search_subcommand_help():
    """Verify 'argus search --help' lists available subcommands and options."""
    result = runner.invoke(app, ["search", "--help"])
    assert result.exit_code == 0
    assert "cves" in result.stdout
    assert "memory" in result.stdout
    assert "stats" in result.stdout


def test_cli_search_app_direct_help():
    """Verify search_app directly displays help cleanly."""
    result = runner.invoke(search_app, ["--help"])
    assert result.exit_code == 0
    assert "cves" in result.stdout
    assert "memory" in result.stdout
    assert "stats" in result.stdout


# ==============================================================================
# 2. Error Paths & Empty State Handling
# ==============================================================================


def test_cli_search_missing_query_error():
    """Invoking search without a query exits with code 1 and helpful error message."""
    result = runner.invoke(app, ["search"])
    assert result.exit_code == 1
    assert "Missing search query" in result.stdout or "Usage:" in result.stdout


def test_cli_search_empty_database_graceful_message(empty_cli_db: str):
    """Searching an empty database prints a graceful message rather than crashing."""
    result = runner.invoke(app, ["search", "SQL injection", "--db-path", empty_cli_db])
    assert result.exit_code == 0
    assert "No results found" in result.stdout


def test_cli_search_empty_database_json_output(empty_cli_db: str):
    """Searching an empty database with --json returns valid empty JSON array."""
    result = runner.invoke(app, ["search", "--json", "SQL injection", "--db-path", empty_cli_db])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout.strip())
    assert isinstance(parsed, list)
    assert len(parsed) == 0


# ==============================================================================
# 3. Main Search Table & JSON Formatting
# ==============================================================================


def test_cli_search_basic_formatted_table(temp_cli_db: str):
    """Basic search returns Rich table with required columns: Score, Type, Severity, Title / Content, Category."""
    result = runner.invoke(app, ["search", "SQL injection", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    output = result.stdout
    assert "Score" in output
    assert "Type" in output
    assert "Severity" in output
    assert "Title / Content" in output
    assert "Category" in output
    assert "CRITICAL" in output


def test_cli_search_json_flag_valid_json_array(temp_cli_db: str):
    """--json flag outputs a valid JSON array containing structured metadata."""
    result = runner.invoke(app, ["search", "--json", "SQL injection", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    items = json.loads(result.stdout.strip())
    assert isinstance(items, list)
    assert len(items) > 0

    first = items[0]
    for required_key in ["id", "score", "source_type", "severity", "category", "title", "content", "metadata"]:
        assert required_key in first
    assert isinstance(first["score"], float)


# ==============================================================================
# 4. Filters Verification
# ==============================================================================


def test_cli_search_type_filter(temp_cli_db: str):
    """--type / -t filters search results by source_type."""
    result = runner.invoke(app, ["search", "-t", "finding", "--json", "SQL", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    items = json.loads(result.stdout.strip())
    assert len(items) > 0
    assert all(item["source_type"] == "finding" for item in items)


def test_cli_search_severity_filter(temp_cli_db: str):
    """--severity / -s filters search results by severity tier."""
    result = runner.invoke(app, ["search", "-s", "critical", "--json", "injection", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    items = json.loads(result.stdout.strip())
    assert len(items) > 0
    assert all(item["severity"] == "critical" for item in items)


def test_cli_search_category_filter(temp_cli_db: str):
    """--category / -c filters search results by vulnerability category."""
    result = runner.invoke(app, ["search", "-c", "sql_injection", "--json", "database", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    items = json.loads(result.stdout.strip())
    assert len(items) > 0
    assert all(item["category"] == "sql_injection" for item in items)


def test_cli_search_mission_filter(temp_cli_db: str):
    """--mission / -m filters search results by mission identifier."""
    result = runner.invoke(app, ["search", "-m", "mission_alpha", "--json", "vulnerability", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    items = json.loads(result.stdout.strip())
    assert len(items) > 0
    assert all(item["mission_id"] == "mission_alpha" for item in items)


def test_cli_search_top_k_option(temp_cli_db: str):
    """--top-k / -k limits number of returned items."""
    result = runner.invoke(app, ["search", "-k", "1", "--json", "injection", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    items = json.loads(result.stdout.strip())
    assert len(items) == 1


def test_cli_search_min_score_option(temp_cli_db: str):
    """--min-score filters out matches below similarity threshold."""
    result = runner.invoke(app, ["search", "--min-score", "0.999", "--json", "unrelated query", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    items = json.loads(result.stdout.strip())
    assert len(items) == 0


# ==============================================================================
# 5. Verbose Flag Tests
# ==============================================================================


def test_cli_search_verbose_table(temp_cli_db: str):
    """--verbose / -v adds Mission, ID, and embedding details to table output."""
    result = runner.invoke(app, ["search", "-v", "SQL injection", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    assert "Mission" in result.stdout
    assert "ID" in result.stdout
    assert "Provider" in result.stdout
    assert "Dimension" in result.stdout


def test_cli_search_verbose_json(temp_cli_db: str):
    """--verbose / -v with --json includes embeddings_info block in each result."""
    result = runner.invoke(app, ["search", "-v", "--json", "SQL injection", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    items = json.loads(result.stdout.strip())
    assert len(items) > 0
    assert "embeddings_info" in items[0]
    assert "provider" in items[0]["embeddings_info"]
    assert "dimension" in items[0]["embeddings_info"]
    assert "metric" in items[0]["embeddings_info"]


# ==============================================================================
# 6. Subcommands: cves, memory, stats
# ==============================================================================


def test_cli_search_cves_subcommand(temp_cli_db: str):
    """'argus search cves <query>' searches CVE records specifically."""
    result = runner.invoke(app, ["search", "cves", "Log4j", "--severity", "critical", "--json", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    items = json.loads(result.stdout.strip())
    assert len(items) >= 1
    assert all(item["source_type"] == "cve" for item in items)
    assert items[0]["id"] == "cve:CVE-2021-44228"


def test_cli_search_cves_cwe_and_product_filter(temp_cli_db: str):
    """'argus search cves' supports --cwe and --product post-filtering."""
    result = runner.invoke(
        app,
        [
            "search",
            "cves",
            "remote code execution",
            "--cwe",
            "CWE-502",
            "--product",
            "Apache",
            "--json",
            "--db-path",
            temp_cli_db,
        ],
    )
    assert result.exit_code == 0
    items = json.loads(result.stdout.strip())
    assert len(items) == 1
    assert items[0]["id"] == "cve:CVE-2021-44228"


def test_cli_search_memory_subcommand(temp_cli_db: str):
    """'argus search memory <query>' searches conversational memories."""
    result = runner.invoke(
        app,
        [
            "search",
            "memory",
            "WAF bypass injection",
            "--memory-type",
            "attack_pattern",
            "--json",
            "--db-path",
            temp_cli_db,
        ],
    )
    assert result.exit_code == 0
    items = json.loads(result.stdout.strip())
    assert len(items) >= 1
    assert items[0]["source_type"] == "memory"
    assert items[0]["category"] == "attack_pattern"
    assert "WAF SQLi Bypass" in items[0]["title"]


def test_cli_search_stats_rich_table(temp_cli_db: str):
    """'argus search stats' prints index statistics table."""
    result = runner.invoke(app, ["search", "stats", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    assert "ARGUS Vector Index Statistics" in result.stdout
    assert "Total Documents" in result.stdout
    assert "Embedding Provider" in result.stdout
    assert "finding" in result.stdout
    assert "evidence" in result.stdout
    assert "cve" in result.stdout
    assert "memory" in result.stdout


def test_cli_search_stats_json(temp_cli_db: str):
    """'argus search stats --json' outputs structured JSON statistics object."""
    result = runner.invoke(app, ["search", "stats", "--json", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    stats = json.loads(result.stdout.strip())
    assert isinstance(stats, dict)
    assert "total_documents" in stats
    assert stats["total_documents"] >= 5
    assert "vector_store_path" in stats
    assert "embedding_provider" in stats
    assert "counts_by_source_type" in stats
    counts = stats["counts_by_source_type"]
    assert counts["finding"] == 2
    assert counts["evidence"] == 1
    assert counts["cve"] == 2
    assert counts["memory"] == 2


def test_cli_search_query_explicit_subcommand(temp_cli_db: str):
    """'argus search query <query>' explicit command invocation behaves identically."""
    result = runner.invoke(app, ["search", "query", "SQL injection", "--json", "--db-path", temp_cli_db])
    assert result.exit_code == 0
    items = json.loads(result.stdout.strip())
    assert isinstance(items, list)
    assert len(items) > 0
