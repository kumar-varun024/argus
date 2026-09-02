"""
Unit and Integration Test Suite for Web Cache Poisoning & Cache Deception Detection Module.

Covers:
- Models, Enums, and Result structures
- CacheSecurityPayloadGenerator (unkeyed headers, unkeyed params, cloaking, WCD matrix, FAT GET, method overrides, mutation strategies)
- CacheSecurityAnalyzer (cache status evaluation, CDN fingerprinting, PII extraction)
- CacheSecurityProber (4-step differential confirmation sequences)
- CacheSecurityCollector lifecycle and Quadruple State Publishing
- ToolRegistry and alias resolution
- PluginExecutorAdapter fallback instantiation
- TaskGenerator DAG task generation and gap resolution
- AttackSurfaceGraphBuilder Section 24 graph expansion
- CVSS and CWE database mappings
- ControlledMission wrapper compatibility
"""
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import pytest

from argus.collectors.cache_security import (
    CacheSecurityCollector,
    WebCachePoisoningCollector,
    CachePoisoningCollector,
    WebCacheDeceptionCollector,
    CacheSecurityPayloadGenerator,
    CacheSecurityProber,
    CacheSecurityAnalyzer,
    CacheProbe,
    CacheProbeResponse,
    CacheSecurityResult,
    CacheVulnerabilityType,
    CacheSecurityTechnique,
    CacheEngineFamily,
    CacheEngine,
    CacheStatus,
    CacheMutationStrategy,
    CacheSecurityMutationStrategy,
    CacheSecuritySeverity,
)
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission
from argus.plugins.interfaces import ControlledMission
from argus.runtime.registry import registry
from argus.runtime.plugins import PluginExecutorAdapter
from argus.planning.task_generator import TaskGenerator, CoverageGap, TaskCategory
from argus.reporting.cvss import CVSSCalculator, ReportSeverity
from argus.reporting.processor import EvidenceProcessor


class MockCacheHttpClient:
    """Mock HTTP client simulating CDN caching and origin responses."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, Dict[str, str], str, float]]] = None):
        # routes: key -> (status_code, headers, body, elapsed)
        self.routes: Dict[str, Tuple[int, Dict[str, str], str, float]] = dict(routes or {})
        self.cache_storage: Dict[str, Tuple[int, Dict[str, str], str]] = {}
        self.request_log: List[Dict[str, Any]] = []

    def set_route(self, key: str, status_code: int, headers: Dict[str, str], body: str, elapsed: float = 0.05):
        self.routes[key] = (status_code, headers, body, elapsed)

    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[str] = None, **kwargs) -> HttpResponse:
        req_headers = {k.lower(): str(v) for k, v in (headers or {}).items()}
        self.request_log.append({
            "method": method,
            "url": url,
            "headers": req_headers,
            "data": data,
        })

        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        cb = params.get("cb", "default_cb")
        cache_key = f"{method}:{parsed.path}:{cb}"

        # 1. Direct key match in configured routes
        for route_key, (sc, rh, body, el) in self.routes.items():
            if route_key in url or route_key in cache_key:
                return HttpResponse(
                    success=(200 <= sc < 400),
                    status_code=sc,
                    headers=rh,
                    raw_body=body,
                    body=body,
                    url=url,
                    elapsed=el,
                )

        # 2. Check if cached
        if cache_key in self.cache_storage:
            sc, rh, body = self.cache_storage[cache_key]
            hit_headers = dict(rh)
            hit_headers["x-cache"] = "HIT"
            hit_headers["cf-cache-status"] = "HIT"
            hit_headers["age"] = "15"
            return HttpResponse(
                success=(200 <= sc < 400),
                status_code=sc,
                headers=hit_headers,
                raw_body=body,
                body=body,
                url=url,
                elapsed=0.01,
            )

        # 3. Simulate origin behavior
        origin_body = "Clean Origin Body"
        origin_headers = {
            "server": "cloudflare",
            "cf-cache-status": "MISS",
            "x-cache": "MISS",
            "content-type": "text/html; charset=utf-8",
        }

        # Check for unkeyed headers injection
        if "x-forwarded-host" in req_headers:
            canary = req_headers["x-forwarded-host"]
            origin_body = f'<html><script src="https://{canary}/app.js"></script></html>'
        elif "x-original-url" in req_headers:
            canary = req_headers["x-original-url"]
            origin_body = f'<html><meta route="{canary}"></html>'

        # Check for unkeyed params or cloaking
        if "utm_content" in params:
            canary = params["utm_content"]
            origin_body = f'<html><div id="analytics">{canary}</div></html>'

        # Check for FAT GET body
        if data and "utm_content=" in data:
            match = urllib.parse.parse_qs(data).get("utm_content")
            if match:
                origin_body = f'<html><div id="fat_get">{match[0]}</div></html>'

        # Store in cache
        self.cache_storage[cache_key] = (200, dict(origin_headers), origin_body)

        return HttpResponse(
            success=True,
            status_code=200,
            headers=origin_headers,
            raw_body=origin_body,
            body=origin_body,
            url=url,
            elapsed=0.05,
        )

    def get(self, url: str, **kwargs) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> HttpResponse:
        return self.request("POST", url, **kwargs)


def test_payload_generator_unkeyed_headers():
    """Verifies that CacheSecurityPayloadGenerator creates complete unkeyed header probes."""
    generator = CacheSecurityPayloadGenerator(canary_domain_suffix="argus.local")
    probes = generator.build_unkeyed_header_probes("https://target.com/home", canary="testcanary")

    assert len(probes) >= 10
    header_names = [p.vector_name for p in probes]
    assert "X-Forwarded-Host" in header_names
    assert "X-Forwarded-Scheme" in header_names
    assert "X-Original-URL" in header_names
    assert "Forwarded" in header_names
    assert "Base-Url" in header_names

    xfh_probe = next(p for p in probes if p.vector_name == "X-Forwarded-Host")
    assert xfh_probe.headers["X-Forwarded-Host"] == "testcanary.argus.local"
    assert xfh_probe.vulnerability_type == CacheVulnerabilityType.UNKEYED_HEADER_POISONING


def test_payload_generator_unkeyed_params_and_cloaking():
    """Verifies generation of unkeyed query parameters, JSONP callbacks, and parameter cloaking."""
    generator = CacheSecurityPayloadGenerator()
    probes = generator.build_unkeyed_param_probes("https://target.com/search", canary="paramcanary")

    assert len(probes) >= 8
    vector_names = [p.vector_name for p in probes]
    assert "utm_content" in vector_names
    assert "callback" in vector_names
    assert "parameter_cloaking_semicolon" in vector_names
    assert "parameter_cloaking_qmark" in vector_names
    assert "parameter_cloaking_encoded_amp" in vector_names
    assert "parameter_cloaking_hash" in vector_names
    assert "http_parameter_pollution" in vector_names


def test_payload_generator_cache_deception_matrix():
    """Verifies Web Cache Deception static extension and delimiter matrix generation."""
    generator = CacheSecurityPayloadGenerator()
    probes = generator.build_cache_deception_probes("https://target.com/account/settings", is_auth=True)

    assert len(probes) >= 15
    suffixes = [p.path_suffix for p in probes]
    assert "/nonexistent.css" in suffixes
    assert "/nonexistent.js" in suffixes
    assert "/nonexistent.png" in suffixes
    assert ";test.js" in suffixes
    assert "%0A.css" in suffixes
    assert "%00.js" in suffixes
    assert "%23.css" in suffixes
    assert "..;/static/style.css" in suffixes
    assert all(p.is_auth_required for p in probes)


def test_payload_generator_normalization_flaws():
    """Verifies FAT GET requests, method overrides, and duplicate header folding probes."""
    generator = CacheSecurityPayloadGenerator()
    probes = generator.build_normalization_flaw_probes("https://target.com/api/data", canary="normcanary")

    assert len(probes) >= 5
    vectors = [p.vector_name for p in probes]
    assert "FAT_GET_urlencoded" in vectors
    assert "FAT_GET_json" in vectors
    assert "X-HTTP-Method-Override" in vectors
    assert "_method_param" in vectors
    assert "duplicate_folded_X-Forwarded-Host" in vectors


def test_payload_generator_mutation_strategies():
    """Verifies application of all 5 mutation strategies."""
    generator = CacheSecurityPayloadGenerator()
    base_probe = CacheProbe(
        probe_id="base_1",
        target_url="https://target.com/profile",
        vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
        strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
        headers={"X-Forwarded-Host": "evil.com"},
        canary="canary123",
    )

    # 1. Dynamic Cache Buster Insertion
    m1 = generator.apply_mutation(base_probe, CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION)
    assert "__argus_cb" in m1.params or "X-Argus-Buster" in m1.headers

    # 2. Path Delimiter Variations
    m2 = generator.apply_mutation(base_probe, CacheMutationStrategy.PATH_DELIMITER_VARIATIONS)
    assert ";" in m2.path_suffix

    # 3. Request Normalization Inversion
    m3 = generator.apply_mutation(base_probe, CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION)
    assert m3.strategy == CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION

    # 4. Header Parameterization & Cloaking
    m4 = generator.apply_mutation(base_probe, CacheMutationStrategy.HEADER_PARAMETERIZATION_CLOAKING)
    assert any(";version=1" in v for v in m4.headers.values())

    # 5. Cache Rule Probe Variations
    m5 = generator.apply_mutation(base_probe, CacheMutationStrategy.CACHE_RULE_PROBE_VARIATIONS)
    assert m5.headers.get("Accept") == "text/css,*/*;q=0.1"


def test_cache_lifecycle_analyzer_cdn_fingerprinting():
    """Verifies CDN and cache proxy engine fingerprinting across major vendors."""
    analyzer = CacheSecurityAnalyzer()

    # Cloudflare
    s, e, _ = analyzer.analyze_cache_lifecycle({"cf-cache-status": "HIT", "server": "cloudflare"})
    assert s == CacheStatus.HIT
    assert e == CacheEngineFamily.CLOUDFLARE

    # CloudFront
    s, e, _ = analyzer.analyze_cache_lifecycle({"x-cache": "Hit from cloudfront", "via": "1.1 cloudfront"})
    assert s == CacheStatus.HIT
    assert e == CacheEngineFamily.CLOUDFRONT

    # Akamai
    s, e, _ = analyzer.analyze_cache_lifecycle({"x-check-cacheable": "YES", "server": "AkamaiGHost"})
    assert e == CacheEngineFamily.AKAMAI

    # Fastly
    s, e, _ = analyzer.analyze_cache_lifecycle({"x-served-by": "cache-iad-1234", "x-cache": "HIT"})
    assert s == CacheStatus.HIT
    assert e == CacheEngineFamily.FASTLY

    # Varnish
    s, e, _ = analyzer.analyze_cache_lifecycle({"x-varnish": "12345 67890", "server": "varnish"})
    assert s == CacheStatus.HIT
    assert e == CacheEngineFamily.VARNISH

    # Nginx
    s, e, _ = analyzer.analyze_cache_lifecycle({"x-cache-status": "HIT", "server": "nginx/1.24"})
    assert s == CacheStatus.HIT
    assert e == CacheEngineFamily.NGINX

    # Apache Traffic Server (ATS)
    s, e, _ = analyzer.analyze_cache_lifecycle({"server": "ATS/9.0.0", "x-cache": "HIT from ATS"})
    assert s == CacheStatus.HIT
    assert e == CacheEngineFamily.APACHE_TRAFFIC_SERVER


def test_cache_lifecycle_analyzer_status_and_age():
    """Verifies Age header monotonic progression and cache control directives."""
    analyzer = CacheSecurityAnalyzer()

    # Status from Age
    s, _, age = analyzer.analyze_cache_lifecycle({"age": "42"})
    assert s == CacheStatus.HIT
    assert age == 42

    # Status from Cache-Control private/no-store
    s, _, _ = analyzer.analyze_cache_lifecycle({"cache-control": "no-store, private"})
    assert s == CacheStatus.BYPASS


def test_pii_detection():
    """Verifies sensitive PII detection in response payloads."""
    analyzer = CacheSecurityAnalyzer()

    content_with_pii = """
    {
        "status": "success",
        "email": "victim_admin@company.internal",
        "api_key": "sec_key_9876543210abcdef",
        "session_id": "sess_abcdef1234567890"
    }
    """
    detected, matches = analyzer.detect_pii(content_with_pii)
    assert detected is True
    assert len(matches) >= 2

    clean_content = "<html><body><h1>Public Welcome Page</h1><p>No secrets here</p></body></html>"
    detected_clean, _ = analyzer.detect_pii(clean_content)
    assert detected_clean is False


def test_prober_differential_confirmation_unkeyed_header():
    """Verifies 4-step differential confirmation for Unkeyed Header Poisoning."""
    mock_client = MockCacheHttpClient()
    prober = CacheSecurityProber(http_client=mock_client)
    probe = CacheProbe(
        probe_id="p_xfh",
        target_url="https://target.com/page",
        vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
        strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
        headers={"X-Forwarded-Host": "poisoned-host.argus.local"},
        canary="poisoned-host.argus.local",
        vector_name="X-Forwarded-Host",
        payload_value="poisoned-host.argus.local",
    )

    responses = prober.execute_differential_sequence("https://target.com/page", probe)
    assert responses["baseline"].status_code == 200
    assert responses["perturbed"].canary_in_body is True
    assert responses["replay"].canary_in_body is True
    assert responses["replay"].cache_status == CacheStatus.HIT
    assert responses["control"].canary_in_body is False

    analyzer = CacheSecurityAnalyzer()
    res = analyzer.evaluate_unkeyed_header_poisoning(responses, probe)
    assert res is not None
    assert res.is_valid_finding is True
    assert res.vulnerability_type == CacheVulnerabilityType.UNKEYED_HEADER_POISONING
    assert res.severity == CacheSecuritySeverity.CRITICAL.value
    assert res.cwe_id == "CWE-444"
    assert res.cvss_score == 9.8


def test_prober_differential_confirmation_unkeyed_param():
    """Verifies 4-step differential confirmation for unkeyed query parameters."""
    mock_client = MockCacheHttpClient()
    prober = CacheSecurityProber(http_client=mock_client)
    probe = CacheProbe(
        probe_id="p_utm",
        target_url="https://target.com/shop",
        vulnerability_type=CacheVulnerabilityType.UNKEYED_PARAM_POISONING,
        strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
        params={"utm_content": "poison_token_99"},
        canary="poison_token_99",
        vector_name="utm_content",
        payload_value="poison_token_99",
    )

    responses = prober.execute_differential_sequence("https://target.com/shop", probe)
    assert responses["perturbed"].canary_in_body is True
    assert responses["replay"].canary_in_body is True
    assert responses["replay"].cache_status == CacheStatus.HIT

    analyzer = CacheSecurityAnalyzer()
    res = analyzer.evaluate_unkeyed_param_poisoning(responses, probe)
    assert res is not None
    assert res.is_valid_finding is True
    assert res.vulnerability_type == CacheVulnerabilityType.UNKEYED_PARAM_POISONING
    assert res.cwe_id == "CWE-444"


def test_prober_differential_confirmation_web_cache_deception():
    """Verifies 4-step differential confirmation for Web Cache Deception."""
    mock_client = MockCacheHttpClient()
    # Configure route where /account/settings/test.css stores and returns authenticated user PII
    mock_client.set_route(
        key="wcd_route",
        status_code=200,
        headers={"cf-cache-status": "HIT", "x-cache": "HIT", "content-type": "text/css"},
        body='{"user":"alice", "email":"alice@victim.com", "api_key":"secret_tok_12345678"}',
    )
    prober = CacheSecurityProber(http_client=mock_client)
    probe = CacheProbe(
        probe_id="p_wcd",
        target_url="https://target.com/account/settings",
        vulnerability_type=CacheVulnerabilityType.WEB_CACHE_DECEPTION,
        strategy=CacheMutationStrategy.CACHE_RULE_PROBE_VARIATIONS,
        path_suffix="/wcd_route.css",
        vector_name="wcd_extension_.css",
        payload_value="/wcd_route.css",
        is_auth_required=True,
    )

    # Manually configure responses to simulate authenticated prime -> unauthenticated replay leak
    baseline_resp = CacheProbeResponse(
        probe=probe, status_code=200, headers={"cf-cache-status": "MISS"}, body='{"email":"alice@victim.com"}', raw_body='{"email":"alice@victim.com"}',
        elapsed=0.05, cache_status=CacheStatus.MISS, engine=CacheEngineFamily.CLOUDFLARE, pii_detected=True, pii_matches=["email:1"]
    )
    perturbed_resp = CacheProbeResponse(
        probe=probe, status_code=200, headers={"cf-cache-status": "MISS"}, body='{"email":"alice@victim.com", "token":"eyJ123.456.789"}', raw_body='{"email":"alice@victim.com", "token":"eyJ123.456.789"}',
        elapsed=0.05, cache_status=CacheStatus.MISS, engine=CacheEngineFamily.CLOUDFLARE, pii_detected=True, pii_matches=["email:1", "jwt_token:1"]
    )
    replay_resp = CacheProbeResponse(
        probe=probe, status_code=200, headers={"cf-cache-status": "HIT", "x-cache": "HIT", "age": "20"}, body='{"email":"alice@victim.com", "token":"eyJ123.456.789"}', raw_body='{"email":"alice@victim.com", "token":"eyJ123.456.789"}',
        elapsed=0.01, cache_status=CacheStatus.HIT, engine=CacheEngineFamily.CLOUDFLARE, age=20, pii_detected=True, pii_matches=["email:1", "jwt_token:1"]
    )
    control_resp = CacheProbeResponse(
        probe=probe, status_code=200, headers={"cf-cache-status": "MISS"}, body='<html><body>Please Login</body></html>', raw_body='<html><body>Please Login</body></html>',
        elapsed=0.05, cache_status=CacheStatus.MISS, engine=CacheEngineFamily.CLOUDFLARE, pii_detected=False, pii_matches=[]
    )

    responses = {
        "baseline": baseline_resp,
        "perturbed": perturbed_resp,
        "replay": replay_resp,
        "control": control_resp,
    }

    analyzer = CacheSecurityAnalyzer()
    res = analyzer.evaluate_web_cache_deception(responses, probe)
    assert res is not None
    assert res.is_valid_finding is True
    assert res.vulnerability_type == CacheVulnerabilityType.WEB_CACHE_DECEPTION
    assert res.severity == CacheSecuritySeverity.HIGH.value
    assert res.cwe_id == "CWE-524"
    assert res.cvss_score == 8.5


def test_prober_differential_confirmation_fat_get():
    """Verifies 4-step differential confirmation for FAT GET normalization flaws."""
    mock_client = MockCacheHttpClient()
    prober = CacheSecurityProber(http_client=mock_client)
    probe = CacheProbe(
        probe_id="p_fat_get",
        target_url="https://target.com/feed",
        vulnerability_type=CacheVulnerabilityType.FAT_GET_POISONING,
        strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
        method="GET",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body="utm_content=fat_canary_token&x=1",
        canary="fat_canary_token",
        vector_name="FAT_GET_urlencoded",
        payload_value="utm_content=fat_canary_token&x=1",
    )

    responses = prober.execute_differential_sequence("https://target.com/feed", probe)
    assert responses["perturbed"].canary_in_body is True
    assert responses["replay"].canary_in_body is True
    assert responses["replay"].cache_status == CacheStatus.HIT

    analyzer = CacheSecurityAnalyzer()
    res = analyzer.evaluate_normalization_flaws(responses, probe)
    assert res is not None
    assert res.is_valid_finding is True
    assert res.vulnerability_type == CacheVulnerabilityType.FAT_GET_POISONING
    assert res.cwe_id == "CWE-444"


def test_cache_security_collector_lifecycle_and_quadruple_publishing():
    """Verifies that CacheSecurityCollector executes collection and mutates all 4 states."""
    mock_client = MockCacheHttpClient()
    prober = CacheSecurityProber(http_client=mock_client)
    collector = CacheSecurityCollector(prober=prober)

    mission = Mission(
        id="mission_cache_test",
        target="https://target.com",
        endpoints=[{"url": "https://target.com/index.html", "host": "target.com"}],
        live_hosts=["https://target.com"],
    )
    mission.attack_surface_graph = KnowledgeGraph()

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1

    # 1. raw_mission.evidence
    assert len(mission.evidence) >= 1
    ev = evidence_list[0]
    assert ev.category == "cache_security"
    assert ev.status == "CONFIRMED"

    # 2. raw_mission.vulnerabilities
    assert len(mission.vulnerabilities) >= 1
    assert mission.vulnerabilities[0]["cwe_id"] in ("CWE-444", "CWE-524")

    # 3. attack_surface_graph Node & Edge expansion
    graph = mission.attack_surface_graph
    assert len(graph.nodes) >= 3
    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) >= 1
    edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(edges) >= 1

    # 4. Plugin alias execution
    alias_ev = collector.execute(mission)
    assert len(alias_ev) >= 1


def test_tool_registry_and_aliases():
    """Verifies ToolRegistry registration and all synonyms/aliases for cache_security."""
    tool = registry.get("cache_security")
    assert tool is not None
    assert tool.id == "cache_security"
    assert tool.capability == "cache_security_detector"

    # Test aliases
    for alias in [
        "cache_security_collector",
        "cache_poisoning",
        "web_cache_poisoning",
        "cache_deception",
        "web_cache_deception",
        "wcd",
        "unkeyed_headers",
        "unkeyed_params",
        "cache_key_normalization",
        "web_cache",
    ]:
        resolved = registry.get(alias)
        assert resolved is not None
        assert resolved.id == "cache_security"


def test_plugin_executor_adapter_fallback():
    """Verifies PluginExecutorAdapter._instantiate_specialist_fallback returns CacheSecurityCollector."""
    adapter = PluginExecutorAdapter()
    for pid in ["cache_security", "web_cache_poisoning", "cache_poisoning", "cache_deception", "wcd", "unkeyed_headers", "cache"]:
        inst = adapter._instantiate_specialist_fallback(pid)
        assert inst is not None
        assert isinstance(inst, CacheSecurityCollector)


def test_task_generator_dag_scheduling_and_gap_resolution():
    """Verifies TaskGenerator DAG generation, recon template dependencies, and gap resolution."""
    mission = Mission(id="test_mission", target="target.com", endpoints=["https://target.com/app"])
    tg = TaskGenerator(mission)

    # Gap resolution
    gap = CoverageGap(area="web cache poisoning", category=TaskCategory.EVIDENCE_CORRELATION, description="Audit unkeyed headers and cache deception")
    tasks = tg.from_gaps([gap])
    assert len(tasks) >= 1
    cache_task = tasks[0]
    assert cache_task.metadata.get("tool_id") == "cache_security"
    assert "Discover API Endpoints" in cache_task.dependencies


def test_attack_surface_graph_builder_section_24():
    """Verifies AttackSurfaceGraphBuilder Section 24 parses Cache Security evidence."""
    ev = Evidence(
        category="cache_security",
        value="cache_security:web-cache-poisoning:https://app.target.com/profile:X-Forwarded-Host",
        source="cache_security",
        title="Web Cache Poisoning on https://app.target.com/profile",
        severity="critical",
        confidence=1.0,
        metadata={
            "url": "https://app.target.com/profile",
            "host": "https://app.target.com",
            "template_id": "web-cache-poisoning",
            "parameter": "X-Forwarded-Host",
            "technique": "unkeyed_header_poisoning",
            "cwe_id": "CWE-444",
            "cvss_score": 9.8,
        },
    )

    builder = AttackSurfaceGraphBuilder()
    graph = builder.build_from_evidence([ev])

    assert "live_host:https://app.target.com" in graph.nodes
    assert "endpoint:https://app.target.com/profile" in graph.nodes
    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) == 1
    edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(edges) >= 1


def test_cvss_and_cwe_mappings():
    """Verifies CVSSCalculator returns accurate CWEs and calibrated score vectors."""
    cwe_wcp = CVSSCalculator.get_cwe_for_category("web_cache_poisoning")
    assert cwe_wcp is not None
    assert cwe_wcp.id == "CWE-444"

    cwe_wcd = CVSSCalculator.get_cwe_for_category("web_cache_deception")
    assert cwe_wcd is not None
    assert cwe_wcd.id == "CWE-524"

    cvss_crit = CVSSCalculator.get_approximate_cvss("cache_security", severity="critical")
    assert cvss_crit.score == 9.8

    cvss_high = CVSSCalculator.get_approximate_cvss("web_cache_deception", severity="high")
    assert 8.0 <= cvss_high.score <= 8.5


def test_controlled_mission_wrapper_compatibility():
    """Verifies that ControlledMission correctly intercepts published findings."""
    raw_mission = Mission(id="raw_m", target="https://target.com", endpoints=["https://target.com/api"])
    controlled = ControlledMission(raw_mission)

    mock_client = MockCacheHttpClient()
    prober = CacheSecurityProber(http_client=mock_client)
    collector = CacheSecurityCollector(prober=prober)

    ev_list = collector.collect(controlled)
    assert len(ev_list) >= 1
    assert hasattr(raw_mission, "plugin_findings")
    assert len(raw_mission.plugin_findings) >= 1

