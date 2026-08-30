"""
Adversarial Stress and Boundary Test Suite for Server-Side Request Forgery (SSRF) Detection Engine.

Covers:
1. Boundary Latency Differentials (exact sub-second delta thresholds: 3.99s vs 4.00s, high baseline traps).
2. False Positive Resistance (static HTML containing metadata terms, search query verbatim reflection).
3. Benign Error Page Matching (404, 500, generic exceptions without internal service signatures).
4. Parameter Fuzzing across Diverse Formats (deeply nested JSON, RESTful path segments, HTTP headers with varied casing).
5. Generator Robustness (malformed IPs, edge-case octets, multi-mutation bypass combinations).
6. Graph Builder Idempotency & Polymorphic Client Resilience.
"""
import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import pytest

from argus.collectors.ssrf import (
    SSRFAnalyzer,
    SSRFCollector,
    SSRFPayloadGenerator,
    SSRFResult,
    SSRFTechnique,
    SSRFCloudProvider,
    Severity,
    CLOUD_METADATA_SIGNATURES,
    INTERNAL_SERVICE_SIGNATURES,
)
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission
from argus.plugins.interfaces import ControlledMission


class AdversarialMockSSRFHttpClient:
    """Configurable mock HTTP client for adversarial SSRF test cases."""

    def __init__(self):
        self.get_routes: Dict[str, Tuple[int, str, float]] = {}
        self.post_routes: Dict[str, Tuple[int, str, float]] = {}
        self.header_routes: Dict[str, Tuple[int, str, float]] = {}
        self.request_history: List[Dict[str, Any]] = []

    def set_get_response(self, url_or_keyword: str, status_code: int, body: str, elapsed: float = 0.05):
        self.get_routes[url_or_keyword] = (status_code, body, elapsed)

    def set_post_response(self, keyword_or_url: str, status_code: int, body: str, elapsed: float = 0.05):
        self.post_routes[keyword_or_url] = (status_code, body, elapsed)

    def set_header_response(self, header_key: str, header_val_substr: str, status_code: int, body: str, elapsed: float = 0.05):
        self.header_routes[f"{header_key.lower()}:{header_val_substr}"] = (status_code, body, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        headers = kwargs.get("headers") or {}
        self.request_history.append({"method": "GET", "url": target_url, "headers": headers})

        # 1. Header routes
        for hk, hv in headers.items():
            for key, val in self.header_routes.items():
                req_hk, req_hsub = key.split(":", 1)
                if hk.lower() == req_hk.lower() and req_hsub in str(hv):
                    return HttpResponse(
                        success=(200 <= val[0] < 300),
                        status_code=val[0],
                        raw_body=val[1],
                        body=val[1],
                        url=target_url,
                        elapsed=val[2],
                    )

        # 2. Exact GET URL match
        if target_url in self.get_routes:
            sc, b, el = self.get_routes[target_url]
            return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        # 3. Partial keyword match (raw and unquoted)
        unquoted = urllib.parse.unquote_plus(target_url)
        for kw, (sc, b, el) in self.get_routes.items():
            if kw in target_url or kw in unquoted:
                return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        # Default clean response
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="<html><body><h1>Clean Application Page</h1><p>Welcome to the portal.</p></body></html>",
            body="Clean Application Page",
            url=target_url,
            elapsed=0.05,
        )

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        data = kwargs.get("data")
        json_data = kwargs.get("json")
        headers = kwargs.get("headers") or {}
        self.request_history.append({"method": "POST", "url": target_url, "data": data, "json": json_data, "headers": headers})

        # Match keyword in JSON or data values
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

        if payload_val:
            for kw, (sc, b, el) in self.post_routes.items():
                if kw in payload_val or payload_val in kw:
                    return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        if target_url in self.post_routes:
            sc, b, el = self.post_routes[target_url]
            return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="<html><body><h1>Clean POST Page</h1></body></html>",
            body="Clean POST Page",
            url=target_url,
            elapsed=0.05,
        )


# =============================================================================
# 1. Differential Timing Boundary & Trap Tests
# =============================================================================

def test_timing_boundary_exact_3_99s_vs_4_00s():
    """Verify timing differential rejects delta 3.99s and accepts delta 4.00s."""
    analyzer = SSRFAnalyzer()
    base_resp = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://target/", elapsed=0.10)

    # 3.99s delta (4.09 - 0.10 = 3.99s) -> Must reject
    sub_threshold_resp = HttpResponse(success=True, status_code=200, raw_body="Drop", body="Drop", url="http://target/", elapsed=4.09)
    assert analyzer.analyze_differential_timing(sub_threshold_resp, base_resp, threshold=4.0) is None

    # 4.00s delta (4.10 - 0.10 = 4.00s) -> Must accept
    at_threshold_resp = HttpResponse(success=True, status_code=200, raw_body="Drop", body="Drop", url="http://target/", elapsed=4.10)
    res = analyzer.analyze_differential_timing(at_threshold_resp, base_resp, threshold=4.0)
    assert res is not None
    assert res["technique"] == "differential_timing"
    assert res["delay_delta"] >= 4.00


def test_timing_high_baseline_trap():
    """Verify high baseline elapsed latency prevents false positive blind SSRF trigger."""
    analyzer = SSRFAnalyzer()
    # Baseline server is slow (3.5s elapsed)
    base_resp = HttpResponse(success=True, status_code=200, raw_body="Slow OK", body="Slow OK", url="http://target/", elapsed=3.50)
    # Injected response is 4.5s elapsed (total elapsed is > 4.0s, but delta is only 1.0s)
    inj_resp = HttpResponse(success=True, status_code=200, raw_body="Slow Injected", body="Slow Injected", url="http://target/", elapsed=4.50)

    assert analyzer.analyze_differential_timing(inj_resp, base_resp, threshold=4.0) is None


def test_timing_zero_baseline():
    """Verify timing differential works correctly when baseline is None or 0.0s."""
    analyzer = SSRFAnalyzer()
    inj_resp = HttpResponse(success=True, status_code=200, raw_body="Timeout", body="Timeout", url="http://target/", elapsed=4.50)

    res = analyzer.analyze_differential_timing(inj_resp, None, threshold=4.0)
    assert res is not None
    assert res["delay_delta"] == 4.50


# =============================================================================
# 2. False Positive & Reflection Resistance Tests
# =============================================================================

def test_verbatim_search_reflection_suppression():
    """Verify verbatim search echo of metadata URL does not trigger SSRF false positive."""
    analyzer = SSRFAnalyzer()
    search_body = """
    <html>
      <head><title>Search Results</title></head>
      <body>
        <h1>Search</h1>
        <p>Results for query: http://169.254.169.254/latest/meta-data/iam/security-credentials/</p>
        <p>No documents found matching your search term.</p>
      </body>
    </html>
    """
    resp = HttpResponse(success=True, status_code=200, raw_body=search_body, body=search_body, url="http://target/search", elapsed=0.1)

    target_info = {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "signature": "aws_iam_role"}
    res = analyzer.analyze_cloud_metadata(resp, target_info=target_info)
    assert res is None


def test_static_documentation_page_suppression():
    """Verify static documentation article mentioning AWS IMDS is suppressed if already present in baseline."""
    analyzer = SSRFAnalyzer()
    doc_body = """
    <html>
      <head><title>DevOps Security Guide</title></head>
      <body>
        <h2>Configuring AWS IAM Roles</h2>
        <p>Always inspect security-credentials/my-role to ensure proper permissions on EC2.</p>
      </body>
    </html>
    """
    base_resp = HttpResponse(success=True, status_code=200, raw_body=doc_body, body=doc_body, url="http://target/docs", elapsed=0.1)
    inj_resp = HttpResponse(success=True, status_code=200, raw_body=doc_body, body=doc_body, url="http://target/docs?url=http://169.254.169.254", elapsed=0.1)

    res = analyzer.analyze_cloud_metadata(inj_resp, baseline=base_resp)
    assert res is None


def test_benign_404_and_500_error_pages_suppression():
    """Verify generic 404 / 500 error pages do not trigger SSRF findings."""
    analyzer = SSRFAnalyzer()
    error_404_body = "<html><head><title>404 Not Found</title></head><body>Resource not found on this server.</body></html>"
    resp_404 = HttpResponse(success=False, status_code=404, raw_body=error_404_body, body=error_404_body, url="http://target/nonexistent", elapsed=0.1)
    assert analyzer.analyze_cloud_metadata(resp_404) is None
    assert analyzer.analyze_internal_service(resp_404) is None

    error_500_body = "<html><head><title>500 Internal Server Error</title></head><body>NullPointerException at app.Server.handle(Server.java:42)</body></html>"
    resp_500 = HttpResponse(success=False, status_code=500, raw_body=error_500_body, body=error_500_body, url="http://target/error", elapsed=0.1)
    assert analyzer.analyze_cloud_metadata(resp_500) is None
    assert analyzer.analyze_internal_service(resp_500) is None


def test_empty_and_minimal_body_suppression():
    """Verify empty or truncated bodies are cleanly rejected as false positives."""
    analyzer = SSRFAnalyzer()
    assert analyzer.is_false_positive(None) is True
    assert analyzer.is_false_positive(HttpResponse(success=True, status_code=200, raw_body="", body="", url="", elapsed=0.0)) is True
    assert analyzer.is_false_positive(HttpResponse(success=True, status_code=200, raw_body="abc", body="abc", url="", elapsed=0.0)) is True


# =============================================================================
# 3. Parameter Fuzzing Across Diverse Formats
# =============================================================================

def test_nested_json_post_fuzzing():
    """Verify SSRFCollector handles nested JSON structures in POST bodies."""
    mock_client = AdversarialMockSSRFHttpClient()
    mock_client.set_post_response(
        "6379",
        200,
        "+PONG\r\n",
        0.05,
    )
    collector = SSRFCollector(http_client=mock_client)

    mission = Mission(
        target="http://example.com",
        endpoints=[{
            "url": "http://example.com/api/v2/integration",
            "method": "POST",
            "body": {
                "service_name": "redis_sync",
                "target_url": "http://example.org",
                "retry_count": 3,
            },
        }],
    )

    evidence = collector.collect(mission)
    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.metadata["parameter"] in ("service_name", "target_url")
    assert ev.metadata["parameter_type"] == "json"
    assert ev.metadata["target_service"] == "redis"


def test_header_casing_variations():
    """Verify SSRFCollector handles HTTP headers with varied casing (Referer, REFERER, x-forwarded-for)."""
    mock_client = AdversarialMockSSRFHttpClient()
    mock_client.set_header_response(
        "x-forwarded-for",
        "169.254.169.254",
        200,
        '{"Code": "Success", "AccessKeyId": "AKIA1234567890ABCDEF", "SecretAccessKey": "secret123"}',
        0.05,
    )
    collector = SSRFCollector(http_client=mock_client)

    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/api/ping", "method": "GET"}],
    )

    evidence = collector.collect(mission)
    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.metadata["parameter_type"] == "header"
    assert "AKIA" in ev.metadata["evidence_snippet"]


def test_multiple_candidate_endpoints_single_vulnerable():
    """Verify collector correctly identifies vulnerable endpoint among multiple secure endpoints."""
    mock_client = AdversarialMockSSRFHttpClient()
    # Only injected requests with internal redis target to /vulnerable return +PONG
    mock_client.set_get_response(
        "http://example.com/vulnerable?url=http%3A%2F%2F127.0.0.1%3A6379%2F",
        200,
        "+PONG\r\n",
        0.05,
    )
    mock_client.set_get_response(
        "http://example.com/vulnerable?url=http://127.0.0.1:6379/",
        200,
        "+PONG\r\n",
        0.05,
    )
    collector = SSRFCollector(http_client=mock_client)

    mission = Mission(
        target="http://example.com",
        endpoints=[
            {"url": "http://example.com/secure1?url=http://safe.com", "method": "GET"},
            {"url": "http://example.com/secure2?url=http://safe.com", "method": "GET"},
            {"url": "http://example.com/vulnerable?url=http://safe.com", "method": "GET"},
            {"url": "http://example.com/secure3?url=http://safe.com", "method": "GET"},
        ],
    )

    evidence = collector.collect(mission)
    assert len(evidence) == 1
    assert "/vulnerable" in evidence[0].value



# =============================================================================
# 4. Generator Mutation Robustness & Edge Cases
# =============================================================================

def test_generator_malformed_ip_handling():
    """Verify SSRFPayloadGenerator gracefully handles malformed and out-of-range IP strings."""
    gen = SSRFPayloadGenerator()
    assert gen.ip_to_decimal("999.999.999.999") is None
    assert gen.ip_to_decimal("127.0.0") is None
    assert gen.ip_to_decimal("127.0.0.1.1") is None
    assert gen.ip_to_decimal("not_an_ip") is None
    assert gen.ip_to_decimal("") is None

    # Verify mutation methods do not raise exceptions on invalid hostnames
    assert len(gen.mutate_decimal_ip("invalid_hostname")) >= 1
    assert len(gen.mutate_hex_ip("invalid_hostname")) >= 1
    assert len(gen.mutate_octal_ip("invalid_hostname")) >= 1
    assert len(gen.mutate_shortened_ip("invalid_hostname")) >= 1


def test_generator_all_9_bypass_strategies_coverage():
    """Verify all 9 bypass mutation strategies produce valid, non-empty payload lists."""
    gen = SSRFPayloadGenerator()
    host = "127.0.0.1"

    s1 = gen.mutate_decimal_ip(host)
    assert any("2130706433" in p for p in s1)

    s2 = gen.mutate_hex_ip(host)
    assert any("0x7f" in p for p in s2)

    s3 = gen.mutate_octal_ip(host)
    assert any("0177" in p for p in s3)

    s4 = gen.mutate_shortened_ip(host)
    assert any("127.1" in p or "0.0.0.0" in p for p in s4)

    s5 = gen.mutate_url_encoding("http://127.0.0.1/")
    assert any("%3A%2F%2F" in p or "%31%32%37" in p for p in s5)

    s6 = gen.mutate_alternative_schemes(host, 6379)
    assert any("gopher://" in p for p in s6)

    s7 = gen.mutate_ipv6(host)
    assert any("[::1]" in p for p in s7)

    s8 = gen.mutate_dns_rebinding(host)
    assert any("nip.io" in p or "localtest.me" in p for p in s8)

    s9 = gen.mutate_parser_ambiguity(host)
    assert any("@" in p or "#" in p for p in s9)


def test_generator_aws_imds_mutations():
    """Verify mutations on AWS IMDS IP 169.254.169.254 produce valid decimal, hex, and octal representations."""
    gen = SSRFPayloadGenerator()
    aws_ip = "169.254.169.254"

    dec_variants = gen.mutate_decimal_ip(aws_ip, "/latest/meta-data/")
    assert any("2852039166" in p for p in dec_variants)

    hex_variants = gen.mutate_hex_ip(aws_ip, "/latest/meta-data/")
    assert any("0xa9fea9fe" in p or "0xa9.0xfe.0xa9.0xfe" in p for p in hex_variants)

    oct_variants = gen.mutate_octal_ip(aws_ip, "/latest/meta-data/")
    assert any("0251.0376.0251.0376" in p for p in oct_variants)


# =============================================================================
# 5. Service Signature Parsing Edge Cases
# =============================================================================

def test_redis_err_and_ok_variations():
    """Verify analyzer matches Redis -ERR unknown command and +OK status responses."""
    analyzer = SSRFAnalyzer()
    resp_err = HttpResponse(success=True, status_code=200, raw_body="-ERR unknown command 'GET /'\r\n", body="-ERR", url="http://target/fetch", elapsed=0.1)
    res_err = analyzer.analyze_internal_service(resp_err)
    assert res_err is not None
    assert res_err["target_service"] == "redis"

    resp_ok = HttpResponse(success=True, status_code=200, raw_body="+OK\r\n", body="+OK", url="http://target/fetch", elapsed=0.1)
    res_ok = analyzer.analyze_internal_service(resp_ok)
    assert res_ok is not None
    assert res_ok["target_service"] == "redis"


def test_postgresql_driver_exception_matching():
    """Verify analyzer matches PostgreSQL JDBC driver exception signatures."""
    analyzer = SSRFAnalyzer()
    pg_body = "org.postgresql.util.PSQLException: Connection to 127.0.0.1:5432 refused. Check that the hostname and port are correct."
    resp = HttpResponse(success=True, status_code=200, raw_body=pg_body, body=pg_body, url="http://target/proxy", elapsed=0.1)
    res = analyzer.analyze_internal_service(resp)
    assert res is not None
    assert res["target_service"] == "postgresql"
    assert res["severity"] == Severity.CRITICAL


def test_elasticsearch_cluster_tagline_matching():
    """Verify analyzer matches Elasticsearch tagline response."""
    analyzer = SSRFAnalyzer()
    es_body = '{\n  "cluster_name" : "docker-cluster",\n  "version" : { "number" : "7.17.0" },\n  "tagline" : "You Know, for Search"\n}'
    resp = HttpResponse(success=True, status_code=200, raw_body=es_body, body=es_body, url="http://target/proxy", elapsed=0.1)
    res = analyzer.analyze_internal_service(resp)
    assert res is not None
    assert res["target_service"] == "elasticsearch"


def test_admin_dashboard_title_variations():
    """Verify analyzer matches multiple admin panel titles (Jenkins, Kibana, Grafana, phpMyAdmin, Actuator)."""
    analyzer = SSRFAnalyzer()
    titles = [
        "<title>Jenkins [Jenkins Dashboard]</title>",
        "<title>Grafana - Home Dashboard</title>",
        "<title>phpMyAdmin 5.1.1</title>",
        "<title>Spring Boot Actuator Endpoints</title>",
        "<title>Kibana - Overview</title>",
    ]
    for title_html in titles:
        resp = HttpResponse(success=True, status_code=200, raw_body=f"<html><head>{title_html}</head></html>", body="Admin", url="http://target/admin", elapsed=0.1)
        res = analyzer.analyze_internal_service(resp)
        assert res is not None, f"Failed matching title: {title_html}"
        assert res["target_service"] == "internal_admin"


# =============================================================================
# 6. Graph Builder & ControlledMission Resilience Tests
# =============================================================================

def test_attack_surface_graph_builder_ssrf_integration():
    """Verify AttackSurfaceGraphBuilder.build_from_evidence creates nodes and HAS_VULNERABILITY edges for SSRF."""
    builder = AttackSurfaceGraphBuilder()
    graph = KnowledgeGraph()

    evidence_item = Evidence(
        mission_id="mission-123",
        source_type="LOG",
        created_by="SYSTEM_GENERATED",
        title="Server-Side Request Forgery: url on http://example.com/fetch",
        description="SSRF to AWS IMDS",
        category="ssrf",
        value="http://example.com/fetch",
        source="http://example.com/fetch",
        status="CONFIRMED",
        confidence=0.95,
        severity="critical",
        metadata={
            "url": "http://example.com/fetch",
            "host": "http://example.com",
            "parameter": "url",
            "template_id": "ssrf_cloud_aws",
            "technique": "cloud_metadata",
            "status_code": 200,
        },
    )

    populated_graph = builder.build_from_evidence([evidence_item], target="http://example.com", graph=graph)
    assert populated_graph is not None

    lh_nodes = populated_graph.nodes_by_type("live_host")
    ep_nodes = populated_graph.nodes_by_type("endpoint")
    vuln_nodes = populated_graph.nodes_by_type("vulnerability")

    assert len(lh_nodes) >= 1
    assert len(ep_nodes) >= 1
    assert len(vuln_nodes) >= 1

    has_endpoint_edges = [e for e in populated_graph.edges if e.type == "HAS_ENDPOINT"]
    assert len(has_endpoint_edges) >= 1

    has_vuln_edges = [e for e in populated_graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(has_vuln_edges) >= 2


def test_controlled_mission_wrapper_resilience():
    """Verify collector gracefully handles ControlledMission publish_finding exceptions."""
    mock_client = AdversarialMockSSRFHttpClient()
    mock_client.set_get_response("169.254.169.254", 200, "security-credentials/role-prod", 0.05)
    collector = SSRFCollector(http_client=mock_client)

    raw_mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/fetch?url=http://safe.com", "method": "GET"}],
    )
    controlled_mission = ControlledMission(raw_mission)

    evidence = collector.collect(controlled_mission)
    assert len(evidence) >= 1
    assert evidence[0].category == "ssrf"


def test_polymorphic_http_client_variants():
    """Verify _execute_request correctly supports mock clients with various method signatures."""
    collector = SSRFCollector()
    mission = Mission(target="http://example.com")

    # 1. Callable mock client
    callable_client = lambda url: HttpResponse(success=True, status_code=200, raw_body="Callable Response", body="Callable", url=url, elapsed=0.01)
    collector.http_client = callable_client
    resp = collector._execute_request(mission, "GET", "http://example.com")
    assert resp is not None
    assert resp.raw_body == "Callable Response"

    # 2. Client with only request()
    class RequestOnlyClient:
        def request(self, method, url, **kwargs):
            return HttpResponse(success=True, status_code=200, raw_body=f"Request {method}", body="OK", url=url, elapsed=0.01)

    collector.http_client = RequestOnlyClient()
    resp = collector._execute_request(mission, "POST", "http://example.com/api")
    assert resp is not None
    assert resp.raw_body == "Request POST"


def test_custom_timeout_and_threshold_configuration():
    """Verify SSRFCollector respects custom timeout and delay threshold arguments."""
    collector = SSRFCollector(timeout=30.0, delay_threshold=6.0)
    assert collector.timeout == 30.0
    assert collector.delay_threshold == 6.0
    assert collector.analyzer is not None
    assert collector.generator is not None


def test_graph_builder_idempotency_duplicate_evidence():
    """Verify AttackSurfaceGraphBuilder handles duplicate evidence items idempotently."""
    builder = AttackSurfaceGraphBuilder()
    graph = KnowledgeGraph()

    ev1 = Evidence(
        mission_id="mission-123",
        source_type="LOG",
        created_by="SYSTEM_GENERATED",
        title="SSRF Vulnerability",
        category="ssrf",
        value="http://example.com/proxy",
        source="http://example.com/proxy",
        status="CONFIRMED",
        confidence=0.95,
        severity="critical",
        metadata={"url": "http://example.com/proxy", "host": "http://example.com", "parameter": "url", "template_id": "ssrf_cloud_aws"},
    )
    ev2 = Evidence(
        mission_id="mission-123",
        source_type="LOG",
        created_by="SYSTEM_GENERATED",
        title="SSRF Vulnerability",
        category="ssrf",
        value="http://example.com/proxy",
        source="http://example.com/proxy",
        status="CONFIRMED",
        confidence=0.95,
        severity="critical",
        metadata={"url": "http://example.com/proxy", "host": "http://example.com", "parameter": "url", "template_id": "ssrf_cloud_aws"},
    )

    g = builder.build_from_evidence([ev1, ev2], target="http://example.com", graph=graph)
    assert len(g.nodes_by_type("endpoint")) == 1
    assert len(g.nodes_by_type("vulnerability")) == 1


def test_analyzer_digitalocean_oracle_alibaba_cloud_responses():
    """Verify analyzer correctly identifies DigitalOcean, Oracle Cloud, and Alibaba Cloud metadata."""
    analyzer = SSRFAnalyzer()

    # DigitalOcean
    do_resp = HttpResponse(success=True, status_code=200, raw_body='{"droplet_id": 1234567, "hostname": "droplet.digitalocean.com"}', body="", url="", elapsed=0.1)
    do_res = analyzer.analyze_cloud_metadata(do_resp)
    assert do_res is not None
    assert do_res["cloud_provider"] == "digitalocean"

    # Oracle Cloud
    oci_resp = HttpResponse(success=True, status_code=200, raw_body='{"id": "ocid1.instance.oc1.iad.ab1234", "canonicalRegionName": "us-ashburn-1"}', body="", url="", elapsed=0.1)
    oci_res = analyzer.analyze_cloud_metadata(oci_resp)
    assert oci_res is not None
    assert oci_res["cloud_provider"] == "oracle"

    # Alibaba Cloud
    ali_resp = HttpResponse(success=True, status_code=200, raw_body="instance-id i-2ze1234567 image-id m-2ze7654321 zone-id cn-beijing-a", body="", url="", elapsed=0.1)
    ali_res = analyzer.analyze_cloud_metadata(ali_resp)
    assert ali_res is not None
    assert ali_res["cloud_provider"] == "alibaba"


def test_analyzer_mongodb_memcached_consul_responses():
    """Verify analyzer matches MongoDB, Memcached, and Consul / etcd responses."""
    analyzer = SSRFAnalyzer()

    # MongoDB
    mongo_resp = HttpResponse(success=True, status_code=200, raw_body='{"isWritablePrimary": true, "wireVersionMin": 0, "maxMessageSizeBytes": 48000000}', body="", url="", elapsed=0.1)
    mongo_res = analyzer.analyze_internal_service(mongo_resp)
    assert mongo_res is not None
    assert mongo_res["target_service"] == "mongodb"

    # Memcached
    mem_resp = HttpResponse(success=True, status_code=200, raw_body="STAT pid 4200\r\nSTAT uptime 86400\r\nVERSION 1.6.9\r\nEND\r\n", body="", url="", elapsed=0.1)
    mem_res = analyzer.analyze_internal_service(mem_resp)
    assert mem_res is not None
    assert mem_res["target_service"] == "memcached"

    # Consul / etcd
    consul_resp = HttpResponse(success=True, status_code=200, raw_body='{"action": "get", "node": {"key": "/config/secret", "value": "s3cr3t", "raft_index": 1024}}', body="", url="", elapsed=0.1)
    consul_res = analyzer.analyze_internal_service(consul_resp)
    assert consul_res is not None
    assert consul_res["target_service"] == "consul_etcd"


def test_analyzer_non_ascii_and_unicode_resilience():
    """Verify analyzer handles binary and non-ASCII characters without decoding errors."""
    analyzer = SSRFAnalyzer()
    binary_body = b"\x00\x00\x00\n5.7.34-log\x00mysql_native_password\x00\xff\xfe\xfd\x80\x90".decode("latin-1")
    resp = HttpResponse(success=True, status_code=200, raw_body=binary_body, body="Binary Handshake", url="http://target/proxy", elapsed=0.1)

    res = analyzer.analyze_internal_service(resp)
    assert res is not None
    assert res["target_service"] == "mysql"

