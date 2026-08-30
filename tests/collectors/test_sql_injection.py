"""
Unit and integration tests for SQLInjectionCollector, SQLInjectionPayloadGenerator,
SQLInjectionAnalyzer, TaskGenerator DAG wiring, ToolRegistry, and AttackSurfaceGraph integration.
"""
from typing import Any, Dict, List, Optional, Tuple
import pytest
import urllib.parse

from argus.collectors.sql_injection import (
    SQLInjectionCollector,
    SQLInjectionPayloadGenerator,
    SQLInjectionAnalyzer,
    DEFAULT_ERROR_PAYLOADS,
    DEFAULT_BOOLEAN_PAIRS,
)
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry


class MockSQLiHttpClient:
    """Mock HTTP client that returns configurable responses based on URL/method/payload matching."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, str, float]]] = None):
        # routes: key -> (status_code, body, elapsed)
        self.routes: Dict[str, Tuple[int, str, float]] = routes or {}
        self.requested_urls: List[str] = []
        self.requested_posts: List[Dict[str, Any]] = []

    def set_route(self, url: str, status_code: int, body: str, elapsed: float = 0.05):
        self.routes[url] = (status_code, body, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        self.requested_urls.append(target_url)

        headers = kwargs.get("headers") or {}
        # Check if header has injected payload match
        for hk, hv in headers.items():
            if f"header:{hk}:{hv}" in self.routes:
                status_code, body, elapsed = self.routes[f"header:{hk}:{hv}"]
                return HttpResponse(
                    success=(200 <= status_code < 300),
                    status_code=status_code,
                    raw_body=body,
                    body=body,
                    url=target_url,
                    elapsed=elapsed,
                )

        if target_url in self.routes:
            status_code, body, elapsed = self.routes[target_url]
            return HttpResponse(
                success=(200 <= status_code < 300),
                status_code=status_code,
                raw_body=body,
                body=body,
                url=target_url,
                elapsed=elapsed,
            )

        # Partial URL or query string match
        for reg_url, (status_code, body, elapsed) in self.routes.items():
            if target_url == reg_url:
                return HttpResponse(
                    success=(200 <= status_code < 300),
                    status_code=status_code,
                    raw_body=body,
                    body=body,
                    url=target_url,
                    elapsed=elapsed,
                )

        return HttpResponse(success=True, status_code=200, raw_body="OK Normal Response", body="OK Normal Response", url=target_url, elapsed=0.05)

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        data = kwargs.get("data")
        json_data = kwargs.get("json")
        self.requested_posts.append({"url": target_url, "data": data, "json": json_data})

        # Check payload matches in json or data
        payload_val = ""
        if isinstance(json_data, dict):
            for v in json_data.values():
                if isinstance(v, str):
                    payload_val = v
                    break
        elif isinstance(data, dict):
            for v in data.values():
                if isinstance(v, str):
                    payload_val = v
                    break

        if payload_val and f"payload:{payload_val}" in self.routes:
            status_code, body, elapsed = self.routes[f"payload:{payload_val}"]
            return HttpResponse(
                success=(200 <= status_code < 300),
                status_code=status_code,
                raw_body=body,
                body=body,
                url=target_url,
                elapsed=elapsed,
            )

        if target_url in self.routes:
            status_code, body, elapsed = self.routes[target_url]
            return HttpResponse(
                success=(200 <= status_code < 300),
                status_code=status_code,
                raw_body=body,
                body=body,
                url=target_url,
                elapsed=elapsed,
            )

        return HttpResponse(success=True, status_code=200, raw_body="OK POST Response", body="OK POST Response", url=target_url, elapsed=0.05)


def test_sql_injection_generator_base_payloads():
    """Tests that SQLInjectionPayloadGenerator produces error, boolean pairs, and time payloads."""
    generator = SQLInjectionPayloadGenerator()
    error_payloads = generator.generate_error_payloads()
    boolean_pairs = generator.generate_boolean_payload_pairs()
    time_payloads = generator.generate_time_payloads(delay=5)

    assert len(error_payloads) >= 10
    assert "'" in error_payloads
    assert any("UNION" in p for p in error_payloads)
    assert any("CONVERT" in p or "SLEEP" in p for p in error_payloads)

    assert len(boolean_pairs) >= 5
    for true_p, false_p in boolean_pairs:
        assert isinstance(true_p, str) and isinstance(false_p, str)
        assert true_p != false_p

    assert len(time_payloads) >= 5
    assert any("SLEEP(5)" in p or "pg_sleep(5)" in p or "WAITFOR DELAY" in p for p in time_payloads)


def test_sql_injection_generator_waf_mutations():
    """Tests the 5 distinct WAF bypass mutation strategies."""
    generator = SQLInjectionPayloadGenerator()
    base = "' UNION SELECT 1, 2, 3--"

    # Strategy 1: Case Alternation
    case_mut = generator.mutate_case_alternation(base)
    assert "uNiOn" in case_mut or "sElEcT" in case_mut

    # Strategy 2: Comment Insertion
    comment_mut = generator.mutate_comment_insertion(base)
    assert "/**/" in comment_mut

    # Strategy 3: URL Encoding
    url_mut = generator.mutate_url_encoding(base)
    assert "%27" in url_mut and "%20" in url_mut

    # Strategy 4: Double URL Encoding
    double_mut = generator.mutate_double_url_encoding(base)
    assert "%2527" in double_mut and "%2520" in double_mut

    # Strategy 5: Whitespace Substitution
    ws_mut = generator.mutate_whitespace_substitution(base)
    assert "%09" in ws_mut

    # Combined mutation list
    all_mutations = generator.mutate_waf_bypass(base)
    assert len(all_mutations) >= 5
    assert base not in all_mutations


def test_sql_injection_analyzer_error_mysql():
    """Tests Error-Based Detection for MySQL signatures with severity='critical'."""
    analyzer = SQLInjectionAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=500,
        raw_body="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1",
    )
    result = analyzer.analyze_error_based(resp, payload="'")
    assert result is not None
    assert result["technique"] == "error_based"
    assert result["dbms"] == "mysql"
    assert result["severity"] == "critical"
    assert result["template_id"] == "sqli-error-mysql"
    assert "You have an error in your SQL syntax" in result["snippet"]


def test_sql_injection_analyzer_error_postgres():
    """Tests Error-Based Detection for PostgreSQL signatures with severity='critical'."""
    analyzer = SQLInjectionAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=500,
        raw_body="pg_query(): Query failed: ERROR: syntax error at or near \"'\" at character 42",
    )
    result = analyzer.analyze_error_based(resp, payload="'")
    assert result is not None
    assert result["dbms"] == "postgresql"
    assert result["severity"] == "critical"
    assert result["template_id"] == "sqli-error-postgresql"


def test_sql_injection_analyzer_error_mssql():
    """Tests Error-Based Detection for MSSQL signatures with severity='critical'."""
    analyzer = SQLInjectionAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=500,
        raw_body="[Microsoft][ODBC SQL Server Driver][SQL Server]Unclosed quotation mark after the character string '''.",
    )
    result = analyzer.analyze_error_based(resp, payload="'")
    assert result is not None
    assert result["dbms"] == "mssql"
    assert result["severity"] == "critical"
    assert result["template_id"] == "sqli-error-mssql"


def test_sql_injection_analyzer_error_oracle():
    """Tests Error-Based Detection for Oracle signatures with severity='critical'."""
    analyzer = SQLInjectionAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=500,
        raw_body="ORA-01756: quoted string not properly terminated\nOracle error occurred in cursor execution.",
    )
    result = analyzer.analyze_error_based(resp, payload="'")
    assert result is not None
    assert result["dbms"] == "oracle"
    assert result["severity"] == "critical"
    assert result["template_id"] == "sqli-error-oracle"


def test_sql_injection_analyzer_error_sqlite():
    """Tests Error-Based Detection for SQLite signatures with severity='critical'."""
    analyzer = SQLInjectionAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=500,
        raw_body="sqlite3.OperationalError: near \"'\": syntax error\nSQLITE_ERROR in query execution",
    )
    result = analyzer.analyze_error_based(resp, payload="'")
    assert result is not None
    assert result["dbms"] == "sqlite"
    assert result["severity"] == "critical"
    assert result["template_id"] == "sqli-error-sqlite"


def test_sql_injection_analyzer_boolean_differential_length():
    """Tests Boolean-Based Blind Differential Length Analysis with severity='high'."""
    analyzer = SQLInjectionAnalyzer()
    baseline = HttpResponse(success=True, status_code=200, raw_body="A" * 2000)
    true_resp = HttpResponse(success=True, status_code=200, raw_body="A" * 2000)
    false_resp = HttpResponse(success=True, status_code=200, raw_body="A" * 100)

    result = analyzer.analyze_boolean_blind(
        true_resp=true_resp,
        false_resp=false_resp,
        baseline=baseline,
        true_payload="' OR 1=1--",
        false_payload="' OR 1=2--",
    )
    assert result is not None
    assert result["technique"] == "boolean_blind"
    assert result["severity"] == "high"
    assert result["true_length"] == 2000
    assert result["false_length"] == 100
    assert result["length_delta"] == 1900


def test_sql_injection_analyzer_boolean_differential_status():
    """Tests Boolean-Based Blind Differential Status Analysis (200 OK vs 404/500)."""
    analyzer = SQLInjectionAnalyzer()
    baseline = HttpResponse(success=True, status_code=200, raw_body="Item found")
    true_resp = HttpResponse(success=True, status_code=200, raw_body="Item found")
    false_resp = HttpResponse(success=False, status_code=404, raw_body="Item not found")

    result = analyzer.analyze_boolean_blind(
        true_resp=true_resp,
        false_resp=false_resp,
        baseline=baseline,
    )
    assert result is not None
    assert result["technique"] == "boolean_blind"
    assert result["severity"] == "high"
    assert result["subtype"] == "status_code_differential"
    assert result["true_status"] == 200
    assert result["false_status"] == 404


def test_sql_injection_analyzer_boolean_identical_reject():
    """Tests that identical responses for TRUE and FALSE are rejected."""
    analyzer = SQLInjectionAnalyzer()
    baseline = HttpResponse(success=True, status_code=200, raw_body="Standard Page Content")
    true_resp = HttpResponse(success=True, status_code=200, raw_body="Standard Page Content")
    false_resp = HttpResponse(success=True, status_code=200, raw_body="Standard Page Content")

    result = analyzer.analyze_boolean_blind(
        true_resp=true_resp,
        false_resp=false_resp,
        baseline=baseline,
    )
    assert result is None


def test_sql_injection_analyzer_time_delay_confirmed():
    """Tests Time-Based Blind Delay Measurement when latency delta >= 4.0s."""
    analyzer = SQLInjectionAnalyzer()
    injected_resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body="OK Data",
        elapsed=5.12,
    )
    result = analyzer.analyze_time_blind(injected_resp, baseline_elapsed=0.08, threshold=4.0)
    assert result is not None
    assert result["technique"] == "time_blind"
    assert result["severity"] == "critical"
    assert result["injected_elapsed"] == 5.12
    assert result["delay_delta"] >= 4.0


def test_sql_injection_analyzer_time_delay_rejected():
    """Tests Time-Based Blind Delay Measurement when latency delta is below 4.0s."""
    analyzer = SQLInjectionAnalyzer()
    injected_resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body="OK Data",
        elapsed=4.60,
    )
    # Baseline was also slow (4.30s), so delta is only 0.30s
    result = analyzer.analyze_time_blind(injected_resp, baseline_elapsed=4.30, threshold=4.0)
    assert result is None


def test_sql_injection_analyzer_false_positive_rejection():
    """Tests rejection of generic application error words and titles."""
    analyzer = SQLInjectionAnalyzer()
    generic_error_resp = HttpResponse(
        success=False,
        status_code=400,
        raw_body="<html><head><title>Application Error</title></head><body><h1>Bad Request: Validation Error</h1><p>Please contact database admin</p></body></html>",
    )
    # is_false_positive should return True
    assert analyzer.is_false_positive(generic_error_resp, payload="'") is True
    # analyze_error_based should return None
    assert analyzer.analyze_error_based(generic_error_resp, payload="'") is None


def test_sql_injection_analyzer_reflection_discard():
    """Tests rejection of pure payload reflection without database execution."""
    analyzer = SQLInjectionAnalyzer()
    reflection_resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body="<html><body><h1>Search Results</h1><p>You searched for: ' OR 1=1--</p><p>0 results found.</p></body></html>",
    )
    assert analyzer.is_false_positive(reflection_resp, payload="' OR 1=1--") is True
    assert analyzer.analyze_error_based(reflection_resp, payload="' OR 1=1--") is None


def test_sql_injection_collector_query_param_error_based():
    """
    R1/R2/R4: Tests SQLInjectionCollector fuzzing GET query parameter,
    creating Evidence, mission vulnerabilities, and attack surface graph nodes/edges.
    """
    mission = Mission(target="example.com")
    mission.endpoints = [{"url": "https://example.com/items?id=1", "path": "/items", "params": {"id": "1"}}]
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockSQLiHttpClient()
    vuln_url = "https://example.com/items?id=%27"
    mock_client.set_route(
        vuln_url,
        500,
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
    )

    collector = SQLInjectionCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "sql_injection"
    assert ev.severity == "critical"
    assert ev.status == "CONFIRMED"
    assert ev.confidence == 0.95
    assert ev.metadata["dbms"] == "mysql"
    assert ev.metadata["parameter"] == "id"

    # Verify mission state updates
    assert len(mission.vulnerabilities) >= 1
    assert mission.vulnerabilities[0]["severity"] == "critical"
    assert mission.vulnerabilities[0]["parameter"] == "id"

    # Verify attack surface graph expansion
    graph = mission.attack_surface_graph
    assert len(graph.nodes) >= 3
    assert any(e.type == "HAS_ENDPOINT" for e in graph.edges)
    assert any(e.type == "HAS_VULNERABILITY" for e in graph.edges)


def test_sql_injection_collector_post_body_json():
    """Tests SQLInjectionCollector fuzzing POST body JSON fields."""
    mission = Mission(target="example.com")
    mission.endpoints = [{
        "url": "https://example.com/api/login",
        "method": "POST",
        "body": {"username": "admin", "password": "secret"},
    }]
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockSQLiHttpClient()
    mock_client.set_route(
        "payload:'",
        500,
        "PostgreSQL ERROR: syntax error at or near \"'\"",
    )

    collector = SQLInjectionCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "sql_injection"
    assert ev.severity == "critical"
    assert ev.metadata["parameter_type"] == "post_body"


def test_sql_injection_collector_headers():
    """Tests SQLInjectionCollector fuzzing HTTP headers (Cookie, Referer, X-Forwarded-For)."""
    mission = Mission(target="example.com")
    mission.endpoints = [{"url": "https://example.com/profile", "path": "/profile"}]
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockSQLiHttpClient()
    mock_client.set_route(
        "header:X-Forwarded-For:127.0.0.1''",
        500,
        "Unclosed quotation mark after the character string [SQL Server]",
    )

    collector = SQLInjectionCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "sql_injection"
    assert ev.metadata["parameter_type"] == "header"
    assert ev.metadata["parameter"] == "X-Forwarded-For"


def test_sql_injection_task_generator_dag_wiring():
    """Tests TaskGenerator DAG reconnaissance templates and gap resolution for SQL injection."""
    assert "sql_injection" in _RECON_TEMPLATES
    template = _RECON_TEMPLATES["sql_injection"]
    assert template["title"] == "Fuzz SQL Injection"
    assert "Discover API Endpoints" in template["dependencies"]
    assert template["category"] == TaskCategory.EVIDENCE_CORRELATION

    mission = Mission(target="example.com")
    mission.endpoints = ["https://example.com/api/users?id=1"]
    generator = TaskGenerator(mission)

    # Keyword gap resolution
    gaps = [
        CoverageGap(area="sql injection", description="SQL injection fuzzing needed", severity=0.81),
        CoverageGap(area="sqli", description="Unchecked parameters for sqli", severity=0.81),
    ]
    tasks = generator.from_gaps(gaps)
    assert len(tasks) >= 1
    assert tasks[0].metadata["tool_id"] == "sql_injection"
    assert "Discover API Endpoints" in tasks[0].dependencies


def test_sql_injection_tool_registry_and_plugin_adapter():
    """Tests ToolRegistry registration and PluginExecutorAdapter fallback for sql_injection."""
    tool = registry.get("sql_injection")
    assert tool is not None
    assert tool.capability == "sql_injection_detector"
    assert tool.safety_requirements["type"] == "internal"
    assert "network" in tool.safety_requirements["permissions"]

    adapter = PluginExecutorAdapter()
    instance = adapter._instantiate_specialist_fallback("sql_injection")
    assert isinstance(instance, SQLInjectionCollector)


def test_sql_injection_attack_surface_graph_builder_reconstruction():
    """Tests AttackSurfaceGraphBuilder reconstruction from sql_injection evidence."""
    ev = Evidence(
        title="SQL Injection on https://example.com/search?q=test",
        category="sql_injection",
        severity="critical",
        value="https://example.com/search?q=test",
        metadata={
            "url": "https://example.com/search?q=test",
            "host": "https://example.com",
            "parameter": "q",
            "template_id": "sqli-error-mysql",
            "status_code": 500,
        },
    )

    builder = AttackSurfaceGraphBuilder()
    graph = builder.build_from_evidence([ev], target="example.com")

    assert "endpoint:https://example.com/search?q=test" in graph.nodes
    assert "live_host:https://example.com" in graph.nodes
    assert any(e.type == "HAS_ENDPOINT" for e in graph.edges)
    assert any(e.type == "HAS_VULNERABILITY" for e in graph.edges)
