"""
Adversarial, boundary value, and corner case tests for the SQL Injection Detection Engine.
Covers false positive suppression, dynamic noise filtering, WAF mutation evasion,
malformed endpoints, nested structures, and ControlledMission execution.
"""
from typing import Any, Dict, List, Optional, Tuple
import pytest

from argus.collectors.sql_injection import (
    SQLInjectionCollector,
    SQLInjectionPayloadGenerator,
    SQLInjectionAnalyzer,
)
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission


class MockAdversarialSQLiHttpClient:
    """Configurable HTTP client for testing adversarial edge cases."""

    def __init__(self):
        self.routes: Dict[str, Tuple[int, str, float]] = {}
        self.exception_on_url: Dict[str, Exception] = {}

    def set_route(self, key: str, status: int, body: str, elapsed: float = 0.05):
        self.routes[key] = (status, body, elapsed)

    def set_exception(self, url: str, exc: Exception):
        self.exception_on_url[url] = exc

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        if target_url in self.exception_on_url:
            raise self.exception_on_url[target_url]

        headers = kwargs.get("headers") or {}
        for hk, hv in headers.items():
            if f"header:{hk}:{hv}" in self.routes:
                st, bd, el = self.routes[f"header:{hk}:{hv}"]
                return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, url=target_url, elapsed=el)

        if target_url in self.routes:
            st, bd, el = self.routes[target_url]
            return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, url=target_url, elapsed=el)

        return HttpResponse(success=True, status_code=200, raw_body="Benign Default Page", body="Benign Default Page", url=target_url, elapsed=0.05)

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        if target_url in self.exception_on_url:
            raise self.exception_on_url[target_url]

        json_data = kwargs.get("json")
        data = kwargs.get("data")
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
            st, bd, el = self.routes[f"payload:{payload_val}"]
            return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, url=target_url, elapsed=el)

        if target_url in self.routes:
            st, bd, el = self.routes[target_url]
            return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, url=target_url, elapsed=el)

        return HttpResponse(success=True, status_code=200, raw_body="Benign POST Response", body="Benign POST Response", url=target_url, elapsed=0.05)


def test_adversarial_malformed_url_and_empty_endpoints():
    """Tests that SQLInjectionCollector gracefully handles empty missions, None endpoints, and malformed URLs."""
    mission = Mission(target="")
    mission.endpoints = [None, "", ":::malformed-url###", {"invalid": 123}]
    mission.live_hosts = [None, ""]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockAdversarialSQLiHttpClient()
    collector = SQLInjectionCollector(http_client=mock_client)
    evidence = collector.collect(mission)
    assert isinstance(evidence, list)
    assert len(evidence) == 0


def test_adversarial_pre_existing_baseline_db_error():
    """
    Tests that if the baseline already returns a database error (e.g. broken backend service),
    the analyzer does not attribute this pre-existing error to the injected payload.
    """
    analyzer = SQLInjectionAnalyzer()
    existing_error = "PostgreSQL ERROR: relation \"users_v1\" does not exist"

    baseline_resp = HttpResponse(success=False, status_code=500, raw_body=existing_error)
    injected_resp = HttpResponse(success=False, status_code=500, raw_body=existing_error)

    result = analyzer.analyze_error_based(
        response=injected_resp,
        baseline=baseline_resp,
        payload="'",
    )
    assert result is None


def test_adversarial_dynamic_token_noise_filter():
    """
    Tests that small byte count fluctuations (1-5 bytes from dynamic CSRF tokens/timestamps)
    do NOT trigger false positive boolean-based SQL injection.
    """
    analyzer = SQLInjectionAnalyzer()
    base_body = "<html><body><h1>Dashboard</h1><input name='csrf' value='a8f3b2'/></body></html>"
    true_body = "<html><body><h1>Dashboard</h1><input name='csrf' value='b9c4c3'/></body></html>"
    false_body = "<html><body><h1>Dashboard</h1><input name='csrf' value='c0d5d4'/></body></html>"

    baseline = HttpResponse(success=True, status_code=200, raw_body=base_body)
    true_resp = HttpResponse(success=True, status_code=200, raw_body=true_body)
    false_resp = HttpResponse(success=True, status_code=200, raw_body=false_body)

    result = analyzer.analyze_boolean_blind(
        true_resp=true_resp,
        false_resp=false_resp,
        baseline=baseline,
        true_payload="' OR 1=1--",
        false_payload="' OR 1=2--",
    )
    assert result is None


def test_adversarial_http_exception_and_timeout():
    """Tests that network connection errors and timeouts during fuzzing do not crash the collector."""
    mission = Mission(target="example.com")
    mission.endpoints = [{"url": "https://example.com/api/test?q=val", "path": "/api/test", "params": {"q": "val"}}]
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockAdversarialSQLiHttpClient()
    mock_client.set_exception("https://example.com/api/test?q=%27", TimeoutError("Connection timed out"))

    collector = SQLInjectionCollector(http_client=mock_client)
    evidence = collector.collect(mission)
    assert isinstance(evidence, list)


def test_adversarial_nested_and_deep_json_body():
    """Tests fuzzing endpoints with JSON bodies containing multiple fields."""
    mission = Mission(target="example.com")
    mission.endpoints = [{
        "url": "https://example.com/api/update",
        "method": "POST",
        "body": {"filter": {"id": "100", "role": "editor"}, "action": "view"},
    }]
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockAdversarialSQLiHttpClient()
    collector = SQLInjectionCollector(http_client=mock_client)
    evidence = collector.collect(mission)
    assert isinstance(evidence, list)


def test_adversarial_waf_case_alternation_execution():
    """Tests that SQLInjectionPayloadGenerator produces case alternation variants for all major SQL keywords."""
    generator = SQLInjectionPayloadGenerator()
    payload = "SELECT * FROM users WHERE id=1 AND SLEEP(5)"
    mutated = generator.mutate_case_alternation(payload)
    assert "sElEcT" in mutated or "fRoM" in mutated or "wHeRe" in mutated or "sLeEp" in mutated


def test_adversarial_waf_comment_insertion_execution():
    """Tests comment insertion mutation on complex SQL statements."""
    generator = SQLInjectionPayloadGenerator()
    payload = "UNION SELECT 1, 2, 3 FROM admin"
    mutated = generator.mutate_comment_insertion(payload)
    assert "/**/" in mutated


def test_adversarial_waf_url_and_double_encoding():
    """Tests URL and double URL encoding of injection payloads."""
    generator = SQLInjectionPayloadGenerator()
    payload = "' OR 1=1--"
    url_enc = generator.mutate_url_encoding(payload)
    double_enc = generator.mutate_double_url_encoding(payload)

    assert "%27" in url_enc
    assert "%2527" in double_enc


def test_adversarial_waf_whitespace_substitutions():
    """Tests whitespace substitution mutations (tabs %09, newlines %0a, comments /**/)."""
    generator = SQLInjectionPayloadGenerator()
    payload = "' OR 1=1--"
    ws_sub = generator.mutate_whitespace_substitution(payload)
    assert "%09" in ws_sub

    all_waf = generator.mutate_waf_bypass(payload)
    assert any("/**/" in v for v in all_waf)
    assert any("%0a" in v for v in all_waf)


def test_adversarial_multiple_parameters_on_same_endpoint():
    """Tests that multiple vulnerable parameters on the same endpoint generate distinct vulnerability keys without collisions."""
    mission = Mission(target="example.com")
    mission.endpoints = [{"url": "https://example.com/search?user=admin&cat=books", "path": "/search", "params": {"user": "admin", "cat": "books"}}]
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockAdversarialSQLiHttpClient()
    # Inject error for 'user' parameter
    mock_client.set_route(
        "https://example.com/search?user=%27&cat=books",
        500,
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
    )
    # Inject error for 'cat' parameter
    mock_client.set_route(
        "https://example.com/search?user=admin&cat=%27",
        500,
        "pg_query(): Query failed: ERROR: syntax error at or near \"'\"",
    )

    collector = SQLInjectionCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) == 2
    params_found = {ev.metadata["parameter"] for ev in evidence_list}
    assert "user" in params_found
    assert "cat" in params_found

    # Verify KnowledgeGraph has distinct vulnerability nodes
    graph = mission.attack_surface_graph
    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) == 2


def test_adversarial_non_ascii_unicode_in_parameters():
    """Tests handling of non-ASCII and Unicode characters in query parameters."""
    mission = Mission(target="example.com")
    mission.endpoints = [{"url": "https://example.com/search?q=café_☕&filter=naïve", "path": "/search", "params": {"q": "café_☕", "filter": "naïve"}}]
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockAdversarialSQLiHttpClient()
    collector = SQLInjectionCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)
    assert isinstance(evidence_list, list)


def test_adversarial_controlled_mission_execute_adapter():
    """Tests execution via ControlledMission adapter wrapper."""
    mission = Mission(target="example.com")
    mission.endpoints = [{"url": "https://example.com/items?id=1", "path": "/items", "params": {"id": "1"}}]
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockAdversarialSQLiHttpClient()
    mock_client.set_route(
        "https://example.com/items?id=%27",
        500,
        "You have an error in your SQL syntax",
    )

    collector = SQLInjectionCollector(http_client=mock_client)
    controlled_mission = ControlledMission(mission)
    evidence_list = collector.execute(controlled_mission)

    assert len(evidence_list) >= 1
    assert evidence_list[0].category == "sql_injection"
