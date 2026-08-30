"""
Unit and integration tests for XSSCollector, XSSPayloadGenerator, XSSAnalyzer,
and attack surface graph integration.
"""
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import pytest

from argus.collectors.xss import (
    XSSCollector,
    XSSAnalyzer,
    XSSPayloadGenerator,
    XSSContext,
)
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission


class MockXSSHttpClient:
    """Mock HTTP client that returns configurable responses based on URL/method/payload matching."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, str, float]]] = None):
        # routes: key -> (status_code, body, elapsed)
        self.routes: Dict[str, Tuple[int, str, float]] = routes or {}
        self.requested_urls: List[str] = []
        self.requested_posts: List[Dict[str, Any]] = []
        self.stored_state: Dict[str, str] = {}

    def set_route(self, url: str, status_code: int, body: str, elapsed: float = 0.05):
        self.routes[url] = (status_code, body, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        self.requested_urls.append(target_url)

        headers = kwargs.get("headers") or {}
        # Check header injection matches
        for hk, hv in headers.items():
            if f"header:{hk}:{hv}" in self.routes:
                status_code, body, elapsed = self.routes[f"header:{hk}:{hv}"]
                return HttpResponse(
                    success=(200 <= status_code < 300),
                    status_code=status_code,
                    raw_body=body,
                    body=body,
                    headers={"Content-Type": "text/html; charset=utf-8"},
                    url=target_url,
                    elapsed=elapsed,
                )

        # Check stored state persistence
        parsed = urllib.parse.urlparse(target_url)
        clean_path = parsed.path
        if clean_path in self.stored_state:
            persisted_body = f"<html><body><div id='comments'>{self.stored_state[clean_path]}</div></body></html>"
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=persisted_body,
                body=persisted_body,
                headers={"Content-Type": "text/html; charset=utf-8"},
                url=target_url,
                elapsed=0.05,
            )

        # Direct URL match
        if target_url in self.routes:
            status_code, body, elapsed = self.routes[target_url]
            return HttpResponse(
                success=(200 <= status_code < 300),
                status_code=status_code,
                raw_body=body,
                body=body,
                headers={"Content-Type": "text/html; charset=utf-8"},
                url=target_url,
                elapsed=elapsed,
            )

        # Query param reflection simulation
        if parsed.query:
            qs = urllib.parse.parse_qs(parsed.query)
            for param_key, param_vals in qs.items():
                for val in param_vals:
                    # Check if matching route registered
                    if f"param:{param_key}:{val}" in self.routes:
                        status_code, body, elapsed = self.routes[f"param:{param_key}:{val}"]
                        return HttpResponse(
                            success=(200 <= status_code < 300),
                            status_code=status_code,
                            raw_body=body,
                            body=body,
                            headers={"Content-Type": "text/html; charset=utf-8"},
                            url=target_url,
                            elapsed=elapsed,
                        )
                    # Check wildcard reflection registered
                    if f"reflect:{param_key}" in self.routes:
                        status_code, tmpl, elapsed = self.routes[f"reflect:{param_key}"]
                        body = tmpl.format(val=val)
                        return HttpResponse(
                            success=(200 <= status_code < 300),
                            status_code=status_code,
                            raw_body=body,
                            body=body,
                            headers={"Content-Type": "text/html; charset=utf-8"},
                            url=target_url,
                            elapsed=elapsed,
                        )

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="<html><body><h1>Normal Page</h1></body></html>",
            body="<html><body><h1>Normal Page</h1></body></html>",
            headers={"Content-Type": "text/html; charset=utf-8"},
            url=target_url,
            elapsed=0.05,
        )

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        data = kwargs.get("data")
        json_data = kwargs.get("json")
        self.requested_posts.append({"url": target_url, "data": data, "json": json_data})

        parsed = urllib.parse.urlparse(target_url)
        clean_path = parsed.path

        # Simulate Stored XSS persistence
        if isinstance(data, dict):
            for k in ("comment", "message", "content", "text", "feedback", "name"):
                if k in data and data[k]:
                    self.stored_state[clean_path] = data[k]
                    break

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
                headers={"Content-Type": "text/html; charset=utf-8"},
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
                headers={"Content-Type": "text/html; charset=utf-8"},
                url=target_url,
                elapsed=elapsed,
            )

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="<html><body><h1>POST Received</h1></body></html>",
            body="<html><body><h1>POST Received</h1></body></html>",
            headers={"Content-Type": "text/html; charset=utf-8"},
            url=target_url,
            elapsed=0.05,
        )


# =============================================================================
# Unit Tests: XSSPayloadGenerator
# =============================================================================

def test_xss_payload_generator_canary():
    gen = XSSPayloadGenerator()
    canary1 = gen.generate_canary("test")
    canary2 = gen.generate_canary("test")
    assert canary1.startswith("test")
    assert canary2.startswith("test")
    assert canary1 != canary2
    assert canary1.isalnum()

    probe = gen.get_canary_probe(canary1)
    assert canary1 in probe


def test_xss_payload_generator_context_payloads():
    gen = XSSPayloadGenerator()
    canary = "testcanary123"

    for ctx in [
        XSSContext.HTML_BODY,
        XSSContext.ATTRIBUTE_DOUBLE,
        XSSContext.ATTRIBUTE_SINGLE,
        XSSContext.ATTRIBUTE_UNQUOTED,
        XSSContext.SCRIPT_STRING_DOUBLE,
        XSSContext.SCRIPT_STRING_SINGLE,
        XSSContext.SCRIPT_BLOCK,
        XSSContext.URL_ATTRIBUTE,
        XSSContext.COMMENT,
        XSSContext.UNKNOWN,
    ]:
        payloads = gen.get_context_payloads(ctx, canary)
        assert isinstance(payloads, list)
        assert len(payloads) >= 1
        for p in payloads:
            assert "payload" in p
            assert "breakout" in p
            assert canary in p["payload"]


def test_xss_payload_generator_default_suite_and_stored():
    gen = XSSPayloadGenerator()
    canary = "testcanary456"

    suite = gen.get_default_payload_suite(canary)
    assert len(suite) >= 5
    for payload, context, marker in suite:
        assert isinstance(payload, str)
        assert isinstance(context, XSSContext)
        assert isinstance(marker, str)
        assert canary in payload

    stored = gen.get_stored_payload(canary)
    assert canary in stored
    assert "<" in stored and ">" in stored


# =============================================================================
# Unit Tests: XSSAnalyzer
# =============================================================================

def test_xss_analyzer_context_detection():
    analyzer = XSSAnalyzer()
    canary = "xyz123"

    # HTML body
    body_html = f"<div>Hello {canary} world</div>"
    assert analyzer.detect_context(body_html, canary) == XSSContext.HTML_BODY

    # Attribute double
    attr_double = f'<input type="text" name="user" value="{canary}">'
    assert analyzer.detect_context(attr_double, canary) == XSSContext.ATTRIBUTE_DOUBLE

    # Attribute single
    attr_single = f"<input type='text' name='user' value='{canary}'>"
    assert analyzer.detect_context(attr_single, canary) == XSSContext.ATTRIBUTE_SINGLE

    # Attribute unquoted
    attr_unquoted = f"<input type=text name=user value={canary}>"
    assert analyzer.detect_context(attr_unquoted, canary) == XSSContext.ATTRIBUTE_UNQUOTED

    # Script string double
    script_double = f'<script>var query = "{canary}";</script>'
    assert analyzer.detect_context(script_double, canary) == XSSContext.SCRIPT_STRING_DOUBLE

    # Script string single
    script_single = f"<script>var query = '{canary}';</script>"
    assert analyzer.detect_context(script_single, canary) == XSSContext.SCRIPT_STRING_SINGLE

    # Script block
    script_block = f"<script>alert({canary});</script>"
    assert analyzer.detect_context(script_block, canary) in (XSSContext.SCRIPT_BLOCK, XSSContext.SCRIPT_STRING_DOUBLE, XSSContext.SCRIPT_STRING_SINGLE)

    # URL attribute
    url_attr = f'<a href="javascript:alert(\'{canary}\')">Click</a>'
    assert analyzer.detect_context(url_attr, canary) == XSSContext.URL_ATTRIBUTE

    # Comment
    comment_html = f"<!-- User comment: {canary} -->"
    assert analyzer.detect_context(comment_html, canary) == XSSContext.COMMENT


def test_xss_analyzer_is_properly_escaped():
    analyzer = XSSAnalyzer()
    canary = "safe123"

    # Properly escaped tags
    escaped_body = f"<div>Search results for &lt;script&gt;alert('{canary}')&lt;/script&gt;</div>"
    assert analyzer.is_properly_escaped(escaped_body, canary) is True

    # Properly escaped quotes in attribute
    escaped_attr = f'<input value="&quot;&gt;&lt;script&gt;{canary}&lt;/script&gt;">'
    assert analyzer.is_properly_escaped(escaped_attr, canary) is True

    # Raw unescaped breakout
    unescaped_body = f"<div>Search results for <script>alert('{canary}')</script></div>"
    assert analyzer.is_properly_escaped(unescaped_body, canary) is False

    # Raw unescaped attribute breakout
    unescaped_attr = f'<input value=""><img src=x onerror=alert(\'{canary}\')>">'
    assert analyzer.is_properly_escaped(unescaped_attr, canary) is False


def test_xss_analyzer_analyze_reflected():
    analyzer = XSSAnalyzer()
    canary = "rxss999"
    payload = f"<script>/*{canary}*/</script>"

    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body=f"<html><body>Search: {payload}</body></html>",
        body=f"<html><body>Search: {payload}</body></html>",
        headers={"Content-Type": "text/html"},
        url="http://target.test/search?q=test",
    )

    finding = analyzer.analyze_reflected(resp, canary, payload)
    assert finding is not None
    assert finding["xss_type"] == "reflected"
    assert finding["severity"] == "high"
    assert finding["confidence"] == 0.95
    assert canary in finding["snippet"]


def test_xss_analyzer_analyze_stored():
    analyzer = XSSAnalyzer()
    canary = "stored888"
    payload = f"<b id=\"argus_{canary}\">{canary}</b><script>/*{canary}*/</script>"

    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body=f"<html><body><div id='comments'>{payload}</div></body></html>",
        body=f"<html><body><div id='comments'>{payload}</div></body></html>",
        headers={"Content-Type": "text/html"},
        url="http://target.test/comments",
    )

    finding = analyzer.analyze_stored(resp, canary, payload)
    assert finding is not None
    assert finding["xss_type"] == "stored"
    assert finding["severity"] == "critical"
    assert finding["confidence"] == 0.95
    assert finding["template_id"] == "xss-stored"


# =============================================================================
# Unit Tests: XSSCollector Full Flow & Vectors
# =============================================================================

def test_xss_collector_reflected_get_query():
    """Tests GET query parameter fuzzing and Evidence generation."""
    mission = Mission(target="http://target.test")
    mission.endpoints = ["http://target.test/search?q=test"]
    mission.live_hosts = ["http://target.test"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockXSSHttpClient()
    # Configure reflection on param 'q'
    mock_client.routes["reflect:q"] = (200, "<html><body><div>Results for: {val}</div></body></html>", 0.05)

    collector = XSSCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.category == "xss"
    assert ev.severity == "high"
    assert "q" in ev.metadata["parameter"]
    assert len(mission.vulnerabilities) >= 1
    assert mission.vulnerabilities[0]["severity"] == "high"

    # Verify KnowledgeGraph Nodes and Edges
    graph = mission.attack_surface_graph
    assert len(graph.nodes_by_type("live_host")) >= 1
    assert len(graph.nodes_by_type("endpoint")) >= 1
    assert len(graph.nodes_by_type("vulnerability")) >= 1

    has_endpoint_edges = [e for e in graph.edges if e.type == "HAS_ENDPOINT"]
    has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(has_endpoint_edges) >= 1
    assert len(has_vuln_edges) >= 2


def test_xss_collector_reflected_post_form():
    """Tests POST form body parameter fuzzing."""
    mission = Mission(target="http://target.test")
    mission.endpoints = [{"url": "http://target.test/feedback", "method": "POST", "body": {"message": "hello"}}]
    mission.live_hosts = ["http://target.test"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockXSSHttpClient()
    collector = XSSCollector(http_client=mock_client)

    # Let POST with any payload reflect raw in response
    def custom_post(url, **kwargs):
        data = kwargs.get("data") or {}
        msg = data.get("message", "")
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body=f"<html><body>Feedback received: <div>{msg}</div></body></html>",
            body=f"<html><body>Feedback received: <div>{msg}</div></body></html>",
            headers={"Content-Type": "text/html"},
            url=url,
        )

    mock_client.post = custom_post

    evidence = collector.collect(mission)
    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.category == "xss"
    assert ev.metadata["parameter_type"] == "post_form"


def test_xss_collector_reflected_post_json():
    """Tests POST JSON body parameter fuzzing."""
    mission = Mission(target="http://target.test")
    mission.endpoints = [{"url": "http://target.test/api/search", "method": "POST", "body": {"query": "hello"}}]
    mission.live_hosts = ["http://target.test"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockXSSHttpClient()
    collector = XSSCollector(http_client=mock_client)

    def custom_post(url, **kwargs):
        json_data = kwargs.get("json") or {}
        q = json_data.get("query", "")
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body=f"<html><body>Search Results: <div>{q}</div></body></html>",
            body=f"<html><body>Search Results: <div>{q}</div></body></html>",
            headers={"Content-Type": "text/html"},
            url=url,
        )

    mock_client.post = custom_post

    evidence = collector.collect(mission)
    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.category == "xss"
    assert ev.metadata["parameter_type"] == "post_json"


def test_xss_collector_header_injection():
    """Tests HTTP header fuzzing (User-Agent, Referer, X-Forwarded-For)."""
    mission = Mission(target="http://target.test")
    mission.endpoints = ["http://target.test/profile"]
    mission.live_hosts = ["http://target.test"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockXSSHttpClient()
    collector = XSSCollector(http_client=mock_client)

    def custom_get(mission_or_url, url=None, **kwargs):
        target_url = url if url is not None else mission_or_url
        headers = kwargs.get("headers") or {}
        ua = headers.get("User-Agent", "default")
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body=f"<html><body>Your User-Agent: <span>{ua}</span></body></html>",
            body=f"<html><body>Your User-Agent: <span>{ua}</span></body></html>",
            headers={"Content-Type": "text/html"},
            url=str(target_url),
        )

    mock_client.get = custom_get

    evidence = collector.collect(mission)
    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.category == "xss"
    assert ev.metadata["parameter_type"] == "header"
    assert ev.metadata["parameter"] == "User-Agent"
    assert ev.severity == "medium"


def test_xss_collector_stored_xss():
    """Tests stateful POST-then-GET Stored XSS validation."""
    mission = Mission(target="http://target.test")
    mission.endpoints = [{"url": "http://target.test/comments", "method": "POST"}]
    mission.live_hosts = ["http://target.test"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockXSSHttpClient()
    collector = XSSCollector(http_client=mock_client)

    evidence = collector.collect(mission)
    stored_ev = [ev for ev in evidence if ev.metadata.get("xss_type") == "stored"]
    assert len(stored_ev) >= 1
    ev = stored_ev[0]
    assert ev.category == "xss"
    assert ev.severity == "critical"
    assert ev.metadata["template_id"] == "xss-stored"
    assert ev.metadata["parameter_type"] == "stored_post"


def test_xss_collector_execute_adapter():
    """Tests plugin execute adapter interface."""
    mission = Mission(target="http://target.test")
    mission.endpoints = []
    mission.live_hosts = ["http://target.test"]
    mock_client = MockXSSHttpClient()
    collector = XSSCollector(http_client=mock_client)

    res = collector.execute(mission)
    assert isinstance(res, list)
