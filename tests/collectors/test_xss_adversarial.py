"""
Adversarial, boundary value, and false positive suppression tests for the XSS Detection Engine.
Covers entity-encoding false positive filtering, non-HTML content-type rejection,
malformed HTML parsing, network timeouts, invalid endpoints, and state resilience.
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


class MockAdversarialXSSHttpClient:
    """Configurable HTTP client for testing adversarial edge cases."""

    def __init__(self):
        self.routes: Dict[str, Tuple[int, str, Dict[str, str]]] = {}
        self.exception_on_url: Dict[str, Exception] = {}

    def set_route(self, key: str, status: int, body: str, headers: Optional[Dict[str, str]] = None):
        hdrs = headers or {"Content-Type": "text/html; charset=utf-8"}
        self.routes[key] = (status, body, hdrs)

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
                st, bd, hd = self.routes[f"header:{hk}:{hv}"]
                return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=0.05)

        if target_url in self.routes:
            st, bd, hd = self.routes[target_url]
            return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=0.05)

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="<html><body><h1>Safe Page</h1></body></html>",
            body="<html><body><h1>Safe Page</h1></body></html>",
            headers={"Content-Type": "text/html; charset=utf-8"},
            url=target_url,
            elapsed=0.05,
        )

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        if target_url in self.exception_on_url:
            raise self.exception_on_url[target_url]

        if target_url in self.routes:
            st, bd, hd = self.routes[target_url]
            return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=0.05)

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
# False Positive Rejection Tests (Entity Encodings)
# =============================================================================

def test_adversarial_entity_encoded_tag_rejection():
    """Verifies that entity-encoded < and > (&lt; and &gt;) do not generate false positives."""
    analyzer = XSSAnalyzer()
    canary = "argusxss_fp1"

    # Escaped as &lt;script&gt;
    escaped_body = f"<html><body>Search: &lt;script&gt;alert('{canary}')&lt;/script&gt;</body></html>"
    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body=escaped_body,
        body=escaped_body,
        headers={"Content-Type": "text/html"},
        url="http://target.test/search?q=test",
    )

    finding = analyzer.analyze_reflected(resp, canary, f"<script>alert('{canary}')</script>")
    assert finding is None, "False positive triggered on entity-encoded <script> tags!"


def test_adversarial_entity_encoded_quote_rejection():
    """Verifies that entity-encoded quotes (&quot;, &#39;, &#x27;) in attributes do not generate false positives."""
    analyzer = XSSAnalyzer()
    canary = "argusxss_fp2"

    # Escaped as &quot;&gt;&lt;img ...
    escaped_body = f'<html><body><input name="q" value="&quot;&gt;&lt;img src=x onerror=alert(&#39;{canary}&#39;)&gt;"></body></html>'
    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body=escaped_body,
        body=escaped_body,
        headers={"Content-Type": "text/html"},
        url="http://target.test/search?q=test",
    )

    finding = analyzer.analyze_reflected(resp, canary, f'"><img src=x onerror=alert(\'{canary}\')>')
    assert finding is None, "False positive triggered on entity-encoded attribute breakout!"


def test_adversarial_hex_and_decimal_entity_rejection():
    """Verifies that numeric and hex entity encodings (&#60;, &#62;, &#x3c;, &#x3e;) do not generate false positives."""
    analyzer = XSSAnalyzer()
    canary = "argusxss_fp3"

    escaped_body = f"<html><body>Output: &#60;script&#62;/*{canary}*/&#60;/script&#62;</body></html>"
    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body=escaped_body,
        body=escaped_body,
        headers={"Content-Type": "text/html"},
        url="http://target.test/view",
    )

    finding = analyzer.analyze_reflected(resp, canary, f"<script>/*{canary}*/</script>")
    assert finding is None


# =============================================================================
# Non-HTML Content-Type Rejection Tests
# =============================================================================

def test_adversarial_json_content_type_rejection():
    """Verifies that raw reflections in application/json responses are rejected (not executable HTML)."""
    analyzer = XSSAnalyzer()
    canary = "argusxss_json1"
    payload = f"<script>alert('{canary}')</script>"

    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body=f'{{"status": "ok", "query": "{payload}"}}',
        body=f'{{"status": "ok", "query": "{payload}"}}',
        headers={"Content-Type": "application/json; charset=utf-8"},
        url="http://target.test/api/search",
    )

    finding = analyzer.analyze_reflected(resp, canary, payload)
    assert finding is None, "False positive triggered on JSON API content-type!"


def test_adversarial_text_plain_content_type_rejection():
    """Verifies that raw reflections in text/plain responses are rejected."""
    analyzer = XSSAnalyzer()
    canary = "argusxss_txt1"
    payload = f"<script>alert('{canary}')</script>"

    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body=f"Plain text debug output: {payload}",
        body=f"Plain text debug output: {payload}",
        headers={"Content-Type": "text/plain"},
        url="http://target.test/raw",
    )

    finding = analyzer.analyze_reflected(resp, canary, payload)
    assert finding is None, "False positive triggered on text/plain content-type!"


def test_adversarial_binary_content_type_rejection():
    """Verifies that octet-stream, pdf, and images are rejected."""
    analyzer = XSSAnalyzer()
    canary = "argusxss_bin1"
    payload = f"<script>{canary}</script>"

    for ctype in ["application/pdf", "image/png", "application/octet-stream"]:
        resp = HttpResponse(
            success=True,
            status_code=200,
            raw_body=f"%PDF-1.4 {payload}",
            body=f"%PDF-1.4 {payload}",
            headers={"Content-Type": ctype},
            url="http://target.test/download",
        )
        finding = analyzer.analyze_reflected(resp, canary, payload)
        assert finding is None


# =============================================================================
# Malformed HTML, Null Bytes, and Edge Case Resilience
# =============================================================================

def test_adversarial_malformed_html_handling():
    """Verifies analyzer handles malformed, unclosed, or heavily broken HTML without exceptions."""
    analyzer = XSSAnalyzer()
    canary = "argusxss_malformed"

    broken_htmls = [
        f"<<<<invalid tags <<script>>{canary}<///script>>",
        f"<div <span unclosed attr=\"{canary}",
        f"<script>{canary}",  # unclosed script
        f"<!-- unclosed comment {canary}",
        f"<a href='javascript:{canary}",
        "",
        None,
    ]

    for html_snippet in broken_htmls:
        ctx = analyzer.detect_context(html_snippet or "", canary)
        assert isinstance(ctx, XSSContext)


def test_adversarial_null_bytes_in_response():
    """Verifies null bytes in HTML body do not cause unhandled crashes."""
    analyzer = XSSAnalyzer()
    canary = "argusxss_null"
    payload = f"<script>/*{canary}*/</script>"

    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body=f"<html>\x00<body>\x00{payload}\x00</body></html>",
        body=f"<html>\x00<body>\x00{payload}\x00</body></html>",
        headers={"Content-Type": "text/html"},
        url="http://target.test/null",
    )

    finding = analyzer.analyze_reflected(resp, canary, payload)
    assert finding is not None
    assert finding["xss_type"] == "reflected"


def test_adversarial_massive_response_body():
    """Verifies that large HTML documents (e.g. 200KB+) are analyzed quickly without runaway regex backtracking."""
    analyzer = XSSAnalyzer()
    canary = "argusxss_large"
    payload = f"<script>/*{canary}*/</script>"

    # 1000 lines of junk before and after
    padding_before = "<div>Some repeated HTML content for padding</div>\n" * 500
    padding_after = "<span>More trailing junk content</span>\n" * 500
    large_html = f"<html><body>{padding_before}{payload}{padding_after}</body></html>"

    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body=large_html,
        body=large_html,
        headers={"Content-Type": "text/html"},
        url="http://target.test/large",
    )

    finding = analyzer.analyze_reflected(resp, canary, payload)
    assert finding is not None
    assert finding["xss_type"] == "reflected"


# =============================================================================
# Network Fault and Collector Error Handling
# =============================================================================

def test_adversarial_collector_handles_network_exceptions_and_timeouts():
    """Verifies collector continues smoothly when endpoints raise network errors or timeouts."""
    mission = Mission(target="http://target.test")
    mission.endpoints = [
        "http://target.test/timeout_endpoint",
        "http://target.test/error_endpoint",
        "http://target.test/valid_search?q=test",
    ]
    mission.live_hosts = ["http://target.test"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockAdversarialXSSHttpClient()
    mock_client.set_exception("http://target.test/timeout_endpoint", TimeoutError("Connection timed out"))
    mock_client.set_exception("http://target.test/error_endpoint", ConnectionResetError("Connection reset by peer"))

    collector = XSSCollector(http_client=mock_client)
    # Should not raise exception
    evidence = collector.collect(mission)
    assert isinstance(evidence, list)


def test_adversarial_malformed_mission_endpoints():
    """Verifies collector gracefully handles None, non-string, or malformed URL endpoints in mission."""
    mission = Mission(target="")
    mission.endpoints = [
        None,
        "",
        "://invalid-url###",
        {"invalid": 123},
        "http://target.test/safe",
    ]
    mission.live_hosts = [None, ""]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockAdversarialXSSHttpClient()
    collector = XSSCollector(http_client=mock_client)
    evidence = collector.collect(mission)
    assert isinstance(evidence, list)


def test_adversarial_controlled_mission_publish():
    """Verifies that ControlledMission finding publishing is handled safely."""
    raw_mission = Mission(target="http://target.test")
    raw_mission.endpoints = ["http://target.test/search?q=test"]
    raw_mission.live_hosts = ["http://target.test"]
    raw_mission.evidence = EvidenceStore()
    raw_mission.vulnerabilities = []
    raw_mission.attack_surface_graph = KnowledgeGraph()

    published_findings = []

    class MockControlledMission(ControlledMission):
        def __init__(self, inner):
            self._mission = inner

        def publish_finding(self, finding_id: str, finding_data: Any):
            published_findings.append((finding_id, finding_data))

    mock_client = MockAdversarialXSSHttpClient()

    def custom_get(mission_or_url, url=None, **kwargs):
        target_url = url if url is not None else mission_or_url
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body=f"<html><body><div>Search results: {target_url}</div></body></html>",
            body=f"<html><body><div>Search results: {target_url}</div></body></html>",
            headers={"Content-Type": "text/html"},
            url=str(target_url),
        )

    mock_client.get = custom_get

    ctrl_mission = MockControlledMission(raw_mission)
    collector = XSSCollector(http_client=mock_client)
    evs = collector.collect(ctrl_mission)
    assert isinstance(evs, list)


# =============================================================================
# Multi-Vector Fuzzing & Graph Topology Verification
# =============================================================================

def test_adversarial_multi_vector_fuzzing_and_graph_topology():
    """
    Stress-tests all 5 fuzzing vectors in a single mission:
    GET query params, POST form, POST JSON, HTTP headers, and Stored XSS,
    verifying attack surface graph node and edge creation.
    """
    mission = Mission(target="http://target.test")
    mission.live_hosts = ["http://target.test"]
    mission.endpoints = [
        {"url": "http://target.test/search?q=foo", "method": "GET", "params": {"q": "foo"}},
        {"url": "http://target.test/contact", "method": "POST", "body": {"message": "hello"}},
        {"url": "http://target.test/api/v1/update", "method": "POST", "body": {"name": "test"}},
        {"url": "http://target.test/user-profile", "method": "GET"},
        {"url": "http://target.test/guestbook", "method": "POST"},
    ]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    stored_posts = {}

    class ComprehensiveMockClient:
        def get(self, mission_or_url, url=None, **kwargs):
            t_url = str(url if url is not None else mission_or_url)
            parsed = urllib.parse.urlparse(t_url)
            headers = kwargs.get("headers") or {}
            params = kwargs.get("params") or {}
            if not params and parsed.query:
                qs = urllib.parse.parse_qs(parsed.query)
                params = {k: v[0] if isinstance(v, list) else v for k, v in qs.items()}

            # Header injection reflection
            for hk, hv in headers.items():
                if any(pfx in str(hv) for pfx in ("hdrxss", "argusxss", "<script>", "alert(")):
                    return HttpResponse(
                        success=True,
                        status_code=200,
                        raw_body=f"<html><body>Header debug: <span>{hv}</span></body></html>",
                        body=f"<html><body>Header debug: <span>{hv}</span></body></html>",
                        headers={"Content-Type": "text/html"},
                        url=t_url,
                    )

            # Stored persistence check
            if parsed.path == "/guestbook" and "/guestbook" in stored_posts:
                persisted = stored_posts["/guestbook"]
                return HttpResponse(
                    success=True,
                    status_code=200,
                    raw_body=f"<html><body><div id='gb'>{persisted}</div></body></html>",
                    body=f"<html><body><div id='gb'>{persisted}</div></body></html>",
                    headers={"Content-Type": "text/html"},
                    url=t_url,
                )

            # GET query reflection
            if "q" in params:
                val = params["q"]
                if isinstance(val, list):
                    val = val[0]
                return HttpResponse(
                    success=True,
                    status_code=200,
                    raw_body=f"<html><body>Results for: <b>{val}</b></body></html>",
                    body=f"<html><body>Results for: <b>{val}</b></body></html>",
                    headers={"Content-Type": "text/html"},
                    url=t_url,
                )

            return HttpResponse(
                success=True,
                status_code=200,
                raw_body="<html><body>Normal page</body></html>",
                body="<html><body>Normal page</body></html>",
                headers={"Content-Type": "text/html"},
                url=t_url,
            )

        def post(self, mission_or_url, url=None, **kwargs):
            t_url = str(url if url is not None else mission_or_url)
            parsed = urllib.parse.urlparse(t_url)
            data = kwargs.get("data")
            json_data = kwargs.get("json")

            # Stored submission
            if parsed.path == "/guestbook" and isinstance(data, dict):
                for k in ("comment", "message", "content", "text", "feedback", "name"):
                    if k in data and data[k]:
                        stored_posts["/guestbook"] = data[k]
                        break
                return HttpResponse(
                    success=True,
                    status_code=200,
                    raw_body="<html><body>Submitted successfully</body></html>",
                    body="<html><body>Submitted successfully</body></html>",
                    headers={"Content-Type": "text/html"},
                    url=t_url,
                )

            # Form reflection
            if parsed.path == "/contact" and isinstance(data, dict):
                msg = data.get("message", "")
                return HttpResponse(
                    success=True,
                    status_code=200,
                    raw_body=f"<html><body>Message echoed: <div>{msg}</div></body></html>",
                    body=f"<html><body>Message echoed: <div>{msg}</div></body></html>",
                    headers={"Content-Type": "text/html"},
                    url=t_url,
                )

            # JSON reflection
            if parsed.path == "/api/v1/update" and isinstance(json_data, dict):
                name = json_data.get("name", "")
                return HttpResponse(
                    success=True,
                    status_code=200,
                    raw_body=f"<html><body>Updated item: <span>{name}</span></body></html>",
                    body=f"<html><body>Updated item: <span>{name}</span></body></html>",
                    headers={"Content-Type": "text/html"},
                    url=t_url,
                )

            return HttpResponse(
                success=True,
                status_code=200,
                raw_body="<html><body>Post OK</body></html>",
                body="<html><body>Post OK</body></html>",
                headers={"Content-Type": "text/html"},
                url=t_url,
            )

    collector = XSSCollector(http_client=ComprehensiveMockClient())
    evidence = collector.collect(mission)

    assert len(evidence) >= 5, f"Expected at least 5 evidence items, got {len(evidence)}"

    param_types = {ev.metadata.get("parameter_type") for ev in evidence}
    assert "query" in param_types
    assert "post_form" in param_types
    assert "post_json" in param_types
    assert "header" in param_types
    assert "stored_post" in param_types

    # Graph assertions
    graph = mission.attack_surface_graph
    live_host_nodes = graph.nodes_by_type("live_host")
    endpoint_nodes = graph.nodes_by_type("endpoint")
    vuln_nodes = graph.nodes_by_type("vulnerability")

    assert len(live_host_nodes) >= 1
    assert len(endpoint_nodes) >= 4
    assert len(vuln_nodes) >= 5

    has_endpoint_edges = [e for e in graph.edges if e.type == "HAS_ENDPOINT"]
    has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]

    assert len(has_endpoint_edges) >= 4
    assert len(has_vuln_edges) >= 10  # 2 per vulnerability (host->vuln and ep->vuln)


def test_adversarial_intermittent_network_drops():
    """
    Simulates intermittent network drops, timeouts, and broken pipes during fuzzing,
    verifying collector resilience without unhandled exceptions.
    """
    mission = Mission(target="http://target.test")
    mission.live_hosts = ["http://target.test"]
    mission.endpoints = [
        "http://target.test/search?q=test1",
        "http://target.test/search?q=test2",
        "http://target.test/profile?name=test3",
    ]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    req_count = 0

    class FlakyClient:
        def get(self, mission_or_url, url=None, **kwargs):
            nonlocal req_count
            req_count += 1
            t_url = str(url if url is not None else mission_or_url)
            if req_count % 3 == 1:
                raise ConnectionResetError("Connection reset by peer")
            elif req_count % 3 == 2:
                raise TimeoutError("Request timed out")
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=f"<html><body>Echo: {t_url}</body></html>",
                body=f"<html><body>Echo: {t_url}</body></html>",
                headers={"Content-Type": "text/html"},
                url=t_url,
            )

        def post(self, mission_or_url, url=None, **kwargs):
            raise BrokenPipeError("Broken pipe")

    collector = XSSCollector(http_client=FlakyClient())
    evidence = collector.collect(mission)
    assert isinstance(evidence, list)


def test_adversarial_stored_xss_escaped_suppression():
    """
    Verifies that when a target application stores input but safely entity-encodes it
    on render, no Stored XSS false positive evidence is generated.
    """
    mission = Mission(target="http://target.test")
    mission.live_hosts = ["http://target.test"]
    mission.endpoints = [{"url": "http://target.test/comments", "method": "POST"}]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    stored_val = ""

    class EscapingStoredClient:
        def post(self, mission_or_url, url=None, **kwargs):
            nonlocal stored_val
            data = kwargs.get("data") or {}
            stored_val = data.get("comment", "")
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body="<html><body>Saved</body></html>",
                body="<html><body>Saved</body></html>",
                headers={"Content-Type": "text/html"},
                url=str(url or mission_or_url),
            )

        def get(self, mission_or_url, url=None, **kwargs):
            escaped = stored_val.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=f"<html><body><div id='comments'>{escaped}</div></body></html>",
                body=f"<html><body><div id='comments'>{escaped}</div></body></html>",
                headers={"Content-Type": "text/html"},
                url=str(url or mission_or_url),
            )

    collector = XSSCollector(http_client=EscapingStoredClient())
    evidence = collector.collect(mission)

    stored_findings = [ev for ev in evidence if ev.metadata.get("xss_type") == "stored"]
    assert len(stored_findings) == 0, "False positive Stored XSS generated for properly escaped persisted input!"


def test_adversarial_query_parameter_arrays_and_special_chars():
    """
    Verifies endpoint candidate extraction and fuzzing with array query params and special characters.
    """
    mission = Mission(target="http://target.test")
    mission.live_hosts = ["http://target.test"]
    mission.endpoints = [
        "http://target.test/filter?tags[]=xss&tags[]=sec",
        "http://target.test/search?q=a+b&category=tech%26news",
    ]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    collector = XSSCollector(http_client=MockAdversarialXSSHttpClient())
    candidates = collector._extract_candidate_endpoints(mission)

    urls = [c["url"] for c in candidates]
    assert any("tags" in u for u in urls)
    assert any("category" in u for u in urls)


# =============================================================================
# Adversarial Content-Type and Entity-Encoding Enhancement Tests
# =============================================================================

def test_adversarial_xml_content_type_rejection():
    """
    Verifies that reflections in application/xml and text/xml responses are strictly
    rejected to prevent false positives against XML/SOAP/REST endpoints.
    """
    analyzer = XSSAnalyzer()
    canary = "argusxss_xml1"
    payload = f"<script>alert('{canary}')</script>"

    for xml_ct in ["application/xml", "text/xml", "application/xml; charset=utf-8", "text/xml; charset=ISO-8859-1"]:
        # Reflected check
        resp_xml = HttpResponse(
            success=True,
            status_code=200,
            raw_body=f"<response><data>{payload}</data></response>",
            body=f"<response><data>{payload}</data></response>",
            headers={"Content-Type": xml_ct},
            url="http://target.test/api/data.xml",
        )
        finding_refl = analyzer.analyze_reflected(resp_xml, canary, payload)
        assert finding_refl is None, f"False positive triggered on XML content-type: {xml_ct}"

        # Stored check
        finding_stored = analyzer.analyze_stored(resp_xml, canary, payload)
        assert finding_stored is None, f"False positive stored XSS triggered on XML content-type: {xml_ct}"


def test_adversarial_javascript_and_css_content_type_rejection():
    """
    Verifies that reflections in application/javascript, text/javascript, and text/css
    responses are not flagged as HTML XSS.
    """
    analyzer = XSSAnalyzer()
    canary = "argusxss_js_css"
    payload = f"<script>alert('{canary}')</script>"

    for non_html_ct in [
        "application/javascript",
        "text/javascript",
        "application/javascript; charset=utf-8",
        "text/css",
        "text/css; charset=utf-8",
    ]:
        resp = HttpResponse(
            success=True,
            status_code=200,
            raw_body=f"/* debug: {payload} */",
            body=f"/* debug: {payload} */",
            headers={"Content-Type": non_html_ct},
            url="http://target.test/static/bundle.js",
        )
        finding = analyzer.analyze_reflected(resp, canary, payload)
        assert finding is None, f"False positive triggered on content-type: {non_html_ct}"


def test_adversarial_entity_encoded_quote_event_handler_suppression():
    """
    Verifies that entity-encoded quotes in event handler test payloads
    (e.g., '&quot; onfocus=&quot;alert(...)&quot;', '&#34;', '&#x22;', '&apos;', '&#39;', '&#x27;')
    are recognized as safely escaped attributes and do not trigger false positive XSS findings.
    """
    analyzer = XSSAnalyzer()
    canary = "argusxss_event_fp"

    # Test cases where user attempted attribute quote breakout with event handler,
    # but the target server properly entity-encoded the quotes.
    safe_event_bodies = [
        # Named entity quote
        f'<html><body><input name="search" value="&quot; onfocus=&quot;alert(\'{canary}\')&quot;"></body></html>',
        # Decimal entity quote (&#34;)
        f'<html><body><input name="search" value="&#34; onfocus=&#34;alert(\'{canary}\')&#34;"></body></html>',
        # Hex entity quote (&#x22;)
        f'<html><body><input name="search" value="&#x22; onfocus=&#x22;alert(\'{canary}\')&#x22;"></body></html>',
        # Single quote entity variations (&apos;, &#39;, &#x27;)
        f"<html><body><input name='search' value='&apos; onfocus=&apos;alert(\"{canary}\")&apos;'></body></html>",
        f"<html><body><input name='search' value='&#39; onfocus=&#39;alert(\"{canary}\")&#39;'></body></html>",
        f"<html><body><input name='search' value='&#x27; onfocus=&#x27;alert(\"{canary}\")&#x27;'></body></html>",
    ]

    for body in safe_event_bodies:
        assert analyzer.is_properly_escaped(body, canary) is True, f"Failed to suppress FP for safe entity quote in: {body}"

        resp = HttpResponse(
            success=True,
            status_code=200,
            raw_body=body,
            body=body,
            headers={"Content-Type": "text/html"},
            url="http://target.test/search?q=test",
        )
        finding = analyzer.analyze_reflected(resp, canary, f'" onfocus="alert(\'{canary}\')')
        assert finding is None, f"False positive reflected XSS triggered for safely escaped event payload in: {body}"


def test_adversarial_leading_zeros_entity_suppression():
    """
    Verifies that hex and decimal entity encodings with leading zeros
    (e.g., &#x003c;, &#0060;, &#x03c;, &#060;, &#X003C;) are recognized
    as safely escaped tags and properly suppressed.
    """
    analyzer = XSSAnalyzer()
    canary = "argusxss_leading_zeros"

    escaped_variants = [
        # Hex with multiple leading zeros
        f"<div>&#x003c;script&#x003e;/*{canary}*/&#x003c;/script&#x003e;</div>",
        # Hex with single leading zero
        f"<div>&#x03c;script&#x03e;/*{canary}*/&#x03c;/script&#x03e;</div>",
        # Uppercase Hex with leading zeros
        f"<div>&#X003C;script&#X003E;/*{canary}*/&#X003C;/script&#X003E;</div>",
        # Decimal with multiple leading zeros
        f"<div>&#0060;script&#0062;/*{canary}*/&#0060;/script&#0062;</div>",
        # Decimal with single leading zero
        f"<div>&#060;script&#062;/*{canary}*/&#060;/script&#062;</div>",
        # Standard decimal and hex
        f"<div>&#60;script&#62;/*{canary}*/&#60;/script&#62;</div>",
        f"<div>&#x3c;script&#x3e;/*{canary}*/&#x3c;/script&#x3e;</div>",
    ]

    for body in escaped_variants:
        assert analyzer.is_properly_escaped(body, canary) is True, f"Failed to suppress FP for leading zero entity in: {body}"

        resp = HttpResponse(
            success=True,
            status_code=200,
            raw_body=body,
            body=body,
            headers={"Content-Type": "text/html"},
            url="http://target.test/view",
        )
        finding = analyzer.analyze_reflected(resp, canary, f"<script>/*{canary}*/</script>")
        assert finding is None, f"False positive reflected XSS triggered for leading zero entity in: {body}"


