"""
Unit and Component tests for SSRFCollector, SSRFPayloadGenerator,
SSRFAnalyzer, and associated data models and signatures.
"""
from typing import Any, Dict, List, Optional, Tuple
import pytest
import urllib.parse

from argus.collectors.ssrf import (
    SSRFCollector,
    SSRFPayloadGenerator,
    SSRFAnalyzer,
    SSRFResult,
    SSRFTechnique,
    SSRFCloudProvider,
    Severity,
    CLOUD_METADATA_SIGNATURES,
    INTERNAL_SERVICE_SIGNATURES,
    DEFAULT_SSRF_TARGETS,
    DEFAULT_INTERNAL_SERVICE_TARGETS,
    DEFAULT_TIMING_TARGETS,
    COMMON_SSRF_PARAMS,
    DEFAULT_SSRF_PROBE_ROUTES,
)
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission
from argus.plugins.interfaces import ControlledMission


class MockSSRFHttpClient:
    """Mock HTTP client for SSRF testing."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, str, float]]] = None):
        # routes: key -> (status_code, body, elapsed)
        self.routes: Dict[str, Tuple[int, str, float]] = dict(routes or {})
        self.requested_urls: List[str] = []
        self.requested_posts: List[Dict[str, Any]] = []

    def set_route(self, key: str, status_code: int, body: str, elapsed: float = 0.05):
        self.routes[key] = (status_code, body, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        self.requested_urls.append(target_url)

        headers = kwargs.get("headers") or {}
        # Check header-based routing
        for hk, hv in headers.items():
            header_key = f"header:{hk}:{hv}"
            if header_key in self.routes:
                status_code, body, elapsed = self.routes[header_key]
                return HttpResponse(
                    success=(200 <= status_code < 300),
                    status_code=status_code,
                    raw_body=body,
                    body=body,
                    url=target_url,
                    elapsed=elapsed,
                )

        # Exact URL match
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

        # Partial URL or payload match (including unquoted variants)
        unquoted_url = urllib.parse.unquote_plus(target_url)
        for reg_key, (status_code, body, elapsed) in self.routes.items():
            if reg_key in target_url or reg_key in unquoted_url:
                return HttpResponse(
                    success=(200 <= status_code < 300),
                    status_code=status_code,
                    raw_body=body,
                    body=body,
                    url=target_url,
                    elapsed=elapsed,
                )

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="OK Clean Application Response",
            body="OK Clean Application Response",
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
        self.requested_posts.append({"url": target_url, "data": data, "json": json_data, "headers": headers})

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

        if payload_val:
            for reg_key, (status_code, body, elapsed) in self.routes.items():
                if reg_key in payload_val or payload_val in reg_key:
                    return HttpResponse(
                        success=(200 <= status_code < 300),
                        status_code=status_code,
                        raw_body=body,
                        body=body,
                        url=target_url,
                        elapsed=elapsed,
                    )

        # Exact URL match
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

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="OK Clean POST Response",
            body="OK Clean POST Response",
            url=target_url,
            elapsed=0.05,
        )


# =============================================================================
# 1. Data Models & Enums Tests
# =============================================================================

def test_ssrf_enums_and_data_models():
    """Verify SSRF enums and data model defaults."""
    assert Severity.CRITICAL == "critical"
    assert Severity.HIGH == "high"
    assert SSRFTechnique.CLOUD_METADATA == "cloud_metadata"
    assert SSRFTechnique.INTERNAL_SERVICE == "internal_service"
    assert SSRFTechnique.DIFFERENTIAL_TIMING == "differential_timing"
    assert SSRFCloudProvider.AWS == "aws"
    assert SSRFCloudProvider.GCP == "gcp"
    assert SSRFCloudProvider.AZURE == "azure"

    res = SSRFResult(
        technique=SSRFTechnique.CLOUD_METADATA.value,
        payload="http://169.254.169.254/latest/meta-data/",
        parameter="url",
        parameter_type="query",
        status_code=200,
        target_service="aws_imds",
        matched_pattern="aws_iam_role",
        snippet="security-credentials/admin-role",
        severity=Severity.CRITICAL,
    )
    assert res.technique == "cloud_metadata"
    assert res.target_service == "aws_imds"
    assert res.severity == Severity.CRITICAL
    assert res.confidence == 0.95


# =============================================================================
# 2. Signature Catalog Tests
# =============================================================================

def test_cloud_metadata_signatures_aws():
    """Test AWS IMDS signature pattern matching."""
    iam_sig = CLOUD_METADATA_SIGNATURES["aws_iam_role"]["pattern"]
    assert iam_sig.search("security-credentials/ecs-task-role") is not None
    assert iam_sig.search("security-credentials/production_db_access") is not None

    cred_sig = CLOUD_METADATA_SIGNATURES["aws_security_credentials"]["pattern"]
    cred_json = '{"Code": "Success", "AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "SecretAccessKey": "wJalr"}'
    assert cred_sig.search(cred_json) is not None

    id_sig = CLOUD_METADATA_SIGNATURES["aws_instance_identity"]["pattern"]
    assert id_sig.search('{"instanceId": "i-0123456789abcdef0", "architecture": "x86_64"}') is not None


def test_cloud_metadata_signatures_gcp_azure_others():
    """Test GCP, Azure, DigitalOcean, Oracle, Alibaba signatures."""
    gcp_sig = CLOUD_METADATA_SIGNATURES["gcp_instance_id"]["pattern"]
    assert gcp_sig.search("computeMetadata/v1/instance/id") is not None
    assert gcp_sig.search('{"project": {"projectId": "my-gcp-project"}}') is not None

    gcp_sa = CLOUD_METADATA_SIGNATURES["gcp_service_accounts"]["pattern"]
    assert gcp_sa.search("instance/service-accounts/default@developer.gserviceaccount.com") is not None

    azure_sig = CLOUD_METADATA_SIGNATURES["azure_vm_metadata"]["pattern"]
    assert azure_sig.search('{"compute": {"vmId": "12345678-abcd-1234-abcd-1234567890ab", "osType": "Linux"}}') is not None

    do_sig = CLOUD_METADATA_SIGNATURES["digitalocean_droplet"]["pattern"]
    assert do_sig.search('{"droplet_id": 98765432, "hostname": "app1.digitalocean.com"}') is not None

    oci_sig = CLOUD_METADATA_SIGNATURES["oracle_cloud"]["pattern"]
    assert oci_sig.search('{"id": "ocid1.instance.oc1.iad.anuwcljrn..."}') is not None

    ali_sig = CLOUD_METADATA_SIGNATURES["alibaba_cloud"]["pattern"]
    assert ali_sig.search("instance-id i-2ze1... image-id m-2ze...") is not None


def test_internal_service_signatures():
    """Test internal service response banner patterns."""
    redis_sig = INTERNAL_SERVICE_SIGNATURES["redis_pong"]["pattern"]
    assert redis_sig.search("+PONG") is not None
    assert redis_sig.search("PONG\r\n") is not None
    assert redis_sig.search("redis_version:6.2.6") is not None

    mysql_sig = INTERNAL_SERVICE_SIGNATURES["mysql_handshake"]["pattern"]
    assert mysql_sig.search("\x00\x00\x00\n5.7.34-log\x00mysql_native_password") is not None

    pg_sig = INTERNAL_SERVICE_SIGNATURES["postgres_handshake"]["pattern"]
    assert pg_sig.search("FATAL: password authentication failed for user 'root'") is not None

    es_sig = INTERNAL_SERVICE_SIGNATURES["elasticsearch_banner"]["pattern"]
    assert es_sig.search('{\n  "name" : "node-1",\n  "tagline" : "You Know, for Search"\n}') is not None

    mongo_sig = INTERNAL_SERVICE_SIGNATURES["mongodb_banner"]["pattern"]
    assert mongo_sig.search('{"isWritablePrimary": true, "maxBsonObjectSize": 16777216}') is not None

    mem_sig = INTERNAL_SERVICE_SIGNATURES["memcached_banner"]["pattern"]
    assert mem_sig.search("STAT pid 1234\r\nSTAT uptime 4321") is not None

    admin_sig = INTERNAL_SERVICE_SIGNATURES["admin_dashboard_titles"]["pattern"]
    assert admin_sig.search("<html><head><title>Admin Dashboard - Corporate Internal</title></head></html>") is not None
    assert admin_sig.search("<title>pfSense - Dashboard</title>") is not None


# =============================================================================
# 3. Payload Generator & 9 Bypass Mutation Strategies
# =============================================================================

def test_generator_ip_to_decimal():
    """Test decimal integer conversion for IPv4 addresses."""
    gen = SSRFPayloadGenerator()
    assert gen.ip_to_decimal("127.0.0.1") == 2130706433
    assert gen.ip_to_decimal("169.254.169.254") == 2852039166
    assert gen.ip_to_decimal("0.0.0.0") == 0
    assert gen.ip_to_decimal("255.255.255.255") == 4294967295
    assert gen.ip_to_decimal("invalid.ip") is None


def test_generator_strategy_1_decimal_ip():
    """Test Strategy 1: Decimal IP notation."""
    gen = SSRFPayloadGenerator()
    variants = gen.mutate_decimal_ip("127.0.0.1", "/api/data")
    assert "http://2130706433/api/data" in variants
    assert "https://2130706433/api/data" in variants


def test_generator_strategy_2_hex_ip():
    """Test Strategy 2: Hexadecimal IP notation."""
    gen = SSRFPayloadGenerator()
    variants = gen.mutate_hex_ip("127.0.0.1", "/status")
    assert "http://0x7f000001/status" in variants
    assert "http://0x7f.0x0.0x0.0x1/status" in variants


def test_generator_strategy_3_octal_ip():
    """Test Strategy 3: Octal IP notation."""
    gen = SSRFPayloadGenerator()
    variants = gen.mutate_octal_ip("127.0.0.1", "/info")
    assert "http://0177.0000.0000.0001/info" in variants or "http://0177.0.0.1/info" in variants


def test_generator_strategy_4_shortened_ip():
    """Test Strategy 4: Shortened IP notation."""
    gen = SSRFPayloadGenerator()
    variants = gen.mutate_shortened_ip("127.0.0.1", "/")
    assert "http://127.1/" in variants
    assert "http://0/" in variants
    assert "http://0.0.0.0/" in variants


def test_generator_strategy_5_url_encoding():
    """Test Strategy 5: URL & Double URL encoding."""
    gen = SSRFPayloadGenerator()
    url = "http://169.254.169.254/latest/meta-data/"
    variants = gen.mutate_url_encoding(url)
    assert urllib.parse.quote(url, safe="") in variants
    assert urllib.parse.quote(urllib.parse.quote(url, safe=""), safe="") in variants


def test_generator_strategy_6_alternative_schemes():
    """Test Strategy 6: Alternative URI schemes (dict, gopher, file, ldap)."""
    gen = SSRFPayloadGenerator()
    variants = gen.mutate_alternative_schemes("127.0.0.1", port=6379)
    assert any(v.startswith("dict://") for v in variants)
    assert any(v.startswith("gopher://") for v in variants)
    assert any(v.startswith("file://") for v in variants)
    assert any(v.startswith("ldap://") for v in variants)


def test_generator_strategy_7_ipv6():
    """Test Strategy 7: IPv6 representations."""
    gen = SSRFPayloadGenerator()
    variants = gen.mutate_ipv6("127.0.0.1", "/admin")
    assert "http://[::1]/admin" in variants
    assert "http://[::]/admin" in variants
    assert "http://[::ffff:127.0.0.1]/admin" in variants


def test_generator_strategy_8_dns_rebinding():
    """Test Strategy 8: DNS rebinding & alternative loopback domains."""
    gen = SSRFPayloadGenerator()
    variants = gen.mutate_dns_rebinding("127.0.0.1", "/secret")
    assert "http://localhost/secret" in variants
    assert "http://127.0.0.1.nip.io/secret" in variants
    assert "http://localtest.me/secret" in variants


def test_generator_strategy_9_parser_ambiguity():
    """Test Strategy 9: URL parser ambiguity & credential tricks."""
    gen = SSRFPayloadGenerator()
    variants = gen.mutate_parser_ambiguity("127.0.0.1", "/")
    assert "http://127.0.0.1:80@target.com/" in variants
    assert "http://target.com#@127.0.0.1/" in variants
    assert "http://127.0.0.1?.target.com/" in variants


def test_generate_mutated_payloads_deduplicated():
    """Test that generate_mutated_payloads applies all strategies and returns deduplicated list."""
    gen = SSRFPayloadGenerator()
    payloads = gen.generate_mutated_payloads("http://127.0.0.1/admin")
    assert len(payloads) >= 20
    assert len(payloads) == len(set(payloads))  # Strictly deduplicated
    assert "http://127.0.0.1/admin" in payloads
    assert any("2130706433" in p for p in payloads)
    assert any("[::1]" in p for p in payloads)


# =============================================================================
# 4. SSRF Analyzer Tests
# =============================================================================

def test_analyzer_cloud_metadata_aws():
    """Test analyzer detecting AWS IMDS response."""
    analyzer = SSRFAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body="security-credentials/app-ec2-role\nsecurity-credentials/readonly",
        body="security-credentials/app-ec2-role\nsecurity-credentials/readonly",
        url="http://example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        elapsed=0.1,
    )
    analysis = analyzer.analyze_cloud_metadata(resp, target_info={"signature": "aws_iam_role"})
    assert analysis is not None
    assert analysis["technique"] == "cloud_metadata"
    assert analysis["cloud_provider"] == "aws"
    assert analysis["severity"] == Severity.CRITICAL
    assert "aws_iam_role" in analysis["matched_pattern"]


def test_analyzer_cloud_metadata_azure():
    """Test analyzer detecting Azure IMDS response."""
    analyzer = SSRFAnalyzer()
    body = '{"compute": {"vmId": "abcdef01-2345-6789-abcd-ef0123456789", "name": "myVM", "osType": "Linux"}}'
    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body=body,
        body=body,
        url="http://example.com/proxy",
        elapsed=0.1,
    )
    analysis = analyzer.analyze_cloud_metadata(resp, target_info={"signature": "azure_vm_metadata"})
    assert analysis is not None
    assert analysis["cloud_provider"] == "azure"
    assert analysis["severity"] == Severity.CRITICAL


def test_analyzer_internal_service_redis():
    """Test analyzer detecting internal Redis response."""
    analyzer = SSRFAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body="+PONG\r\n",
        body="+PONG\r\n",
        url="http://example.com/preview",
        elapsed=0.1,
    )
    analysis = analyzer.analyze_internal_service(resp, target_info={"signature": "redis_pong"})
    assert analysis is not None
    assert analysis["technique"] == "internal_service"
    assert analysis["target_service"] == "redis"
    assert analysis["severity"] == Severity.HIGH


def test_analyzer_internal_service_mysql():
    """Test analyzer detecting internal MySQL handshake."""
    analyzer = SSRFAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body="J\x00\x00\x00\n5.7.29-0ubuntu0.18.04.1\x00\x1f\x00\x00\x00mysql_native_password\x00",
        body="mysql handshake",
        url="http://example.com/proxy",
        elapsed=0.1,
    )
    analysis = analyzer.analyze_internal_service(resp, target_info={"signature": "mysql_handshake"})
    assert analysis is not None
    assert analysis["target_service"] == "mysql"
    assert analysis["severity"] == Severity.CRITICAL


def test_analyzer_differential_timing_positive():
    """Test differential timing analysis when delay delta >= 4.0s."""
    analyzer = SSRFAnalyzer()
    base_resp = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://target/", elapsed=0.15)
    inj_resp = HttpResponse(success=True, status_code=200, raw_body="Gateway Timeout", body="Gateway Timeout", url="http://target/", elapsed=5.20)

    analysis = analyzer.analyze_differential_timing(inj_resp, base_resp, threshold=4.0)
    assert analysis is not None
    assert analysis["technique"] == "differential_timing"
    assert analysis["delay_delta"] >= 5.0
    assert analysis["severity"] == Severity.HIGH


def test_analyzer_differential_timing_negative():
    """Test differential timing analysis returns None when delay delta < 4.0s."""
    analyzer = SSRFAnalyzer()
    base_resp = HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url="http://target/", elapsed=0.15)
    inj_resp = HttpResponse(success=True, status_code=200, raw_body="Fast Response", body="Fast Response", url="http://target/", elapsed=2.50)

    analysis = analyzer.analyze_differential_timing(inj_resp, base_resp, threshold=4.0)
    assert analysis is None


def test_analyzer_baseline_subtraction():
    """Test analyzer suppresses finding if match was already in baseline response."""
    analyzer = SSRFAnalyzer()
    body = "Server status: redis_version:6.0.0 (embedded in public status page)"
    base_resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="http://target/", elapsed=0.1)
    inj_resp = HttpResponse(success=True, status_code=200, raw_body=body, body=body, url="http://target/?url=http://127.0.0.1:6379", elapsed=0.1)

    analysis = analyzer.analyze_internal_service(inj_resp, baseline=base_resp)
    assert analysis is None


def test_analyzer_false_positive_rejection():
    """Test false positive suppression for empty bodies or identical responses."""
    analyzer = SSRFAnalyzer()
    empty_resp = HttpResponse(success=True, status_code=200, raw_body="", body="", url="http://target/", elapsed=0.1)
    assert analyzer.is_false_positive(empty_resp) is True

    base_resp = HttpResponse(success=True, status_code=200, raw_body="Static Content Here", body="Static Content Here", url="http://target/", elapsed=0.1)
    inj_resp = HttpResponse(success=True, status_code=200, raw_body="Static Content Here", body="Static Content Here", url="http://target/", elapsed=0.1)
    assert analyzer.is_false_positive(inj_resp, baseline=base_resp) is True


# =============================================================================
# 5. SSRF Collector Fuzzing Vectors & Integration Tests
# =============================================================================

def test_collector_get_query_fuzzing():
    """Test SSRFCollector fuzzing GET query parameters detecting AWS IMDS vulnerability."""
    mock_client = MockSSRFHttpClient()
    mock_client.set_route(
        "169.254.169.254",
        200,
        '{"Code": "Success", "AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}',
        0.05,
    )
    collector = SSRFCollector(http_client=mock_client)

    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/fetch?url=http://public.com/image.png", "method": "GET"}],
    )

    evidence = collector.collect(mission)
    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.category == "ssrf"
    assert ev.severity == Severity.CRITICAL
    assert ev.metadata["parameter"] == "url"
    assert ev.metadata["parameter_type"] == "query"
    assert "AKIA" in ev.metadata["evidence_snippet"]


def test_collector_post_json_fuzzing():
    """Test SSRFCollector fuzzing POST JSON body detecting internal Redis service."""
    mock_client = MockSSRFHttpClient()
    mock_client.set_route(
        "6379",
        200,
        "+PONG\r\n",
        0.05,
    )
    collector = SSRFCollector(http_client=mock_client)

    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/api/webhook", "method": "POST", "body": {"callback_url": "http://default.com"}}],
    )

    evidence = collector.collect(mission)
    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.category == "ssrf"
    assert ev.metadata["parameter"] == "callback_url"
    assert ev.metadata["parameter_type"] == "json"
    assert ev.metadata["target_service"] == "redis"


def test_collector_post_form_fuzzing():
    """Test SSRFCollector fuzzing POST form-urlencoded fields detecting GCP metadata."""
    mock_client = MockSSRFHttpClient()
    mock_client.set_route(
        "computeMetadata",
        200,
        '{"project": {"projectId": "prod-gcp-cluster-42", "numericProjectId": 1234567890}}',
        0.05,
    )
    collector = SSRFCollector(http_client=mock_client)

    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/download", "method": "POST", "params": {"target": "http://public.site"}}],
    )

    evidence = collector.collect(mission)
    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.category == "ssrf"
    assert ev.metadata["parameter"] == "target"
    assert ev.metadata["parameter_type"] == "body"


def test_collector_header_fuzzing():
    """Test SSRFCollector fuzzing HTTP request headers (Referer, X-Forwarded-For)."""
    mock_client = MockSSRFHttpClient()
    mock_client.set_route(
        "header:X-Forwarded-For:http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        200,
        "security-credentials/internal-admin-role",
        0.05,
    )
    collector = SSRFCollector(http_client=mock_client)

    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/status", "method": "GET"}],
    )

    evidence = collector.collect(mission)
    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.metadata["parameter_type"] == "header"
    assert ev.metadata["parameter"] == "X-Forwarded-For"


def test_collector_path_segment_fuzzing():
    """Test SSRFCollector fuzzing RESTful path segments."""
    mock_client = MockSSRFHttpClient()
    mock_client.set_route(
        "169.254.169.254",
        200,
        '{"compute": {"vmId": "11223344-5566-7788-99aa-bbccddeeff00", "osType": "Linux"}}',
        0.05,
    )
    collector = SSRFCollector(http_client=mock_client)

    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/proxy/http%3A%2F%2Fexternal.com", "method": "GET"}],
    )

    evidence = collector.collect(mission)
    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.metadata["parameter_type"] == "path"


def test_collector_empty_mission():
    """Test SSRFCollector gracefully handles empty mission with no targets."""
    mock_client = MockSSRFHttpClient()
    collector = SSRFCollector(http_client=mock_client)
    mission = Mission(target="", endpoints=[], live_hosts=[])

    evidence = collector.collect(mission)
    assert evidence == []


def test_collector_knowledge_graph_expansion():
    """Test SSRFCollector connects live_host, endpoint, and vulnerability nodes with HAS_ENDPOINT and HAS_VULNERABILITY edges."""
    mock_client = MockSSRFHttpClient()
    mock_client.set_route(
        "169.254.169.254",
        200,
        "security-credentials/root-admin",
        0.05,
    )
    collector = SSRFCollector(http_client=mock_client)

    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/fetch?dest=http://example.org", "method": "GET"}],
    )

    evidence = collector.collect(mission)
    assert len(evidence) >= 1

    graph = mission.attack_surface_graph
    assert graph is not None
    assert len(graph.nodes_by_type("live_host")) >= 1
    assert len(graph.nodes_by_type("endpoint")) >= 1
    assert len(graph.nodes_by_type("vulnerability")) >= 1

    # Check edges
    has_endpoint_edges = [e for e in graph.edges if e.type == "HAS_ENDPOINT"]
    assert len(has_endpoint_edges) >= 1

    has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(has_vuln_edges) >= 2  # lh -> vuln and ep -> vuln



def test_collector_execute_plugin_adapter():
    """Test execute() method behaves identically to collect()."""
    mock_client = MockSSRFHttpClient()
    mock_client.set_route("169.254.169.254", 200, "security-credentials/role1", 0.05)
    collector = SSRFCollector(http_client=mock_client)

    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/load?url=test", "method": "GET"}],
    )
    evidence = collector.execute(mission)
    assert len(evidence) >= 1
    assert evidence[0].category == "ssrf"
