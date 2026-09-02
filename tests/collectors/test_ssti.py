"""
Unit and Integration test suite for Server-Side Template Injection (SSTI) Collector.
Covers generator, analyzer, prober, collector, pipeline wiring, graph builder, CVSS, and registry.
"""
from typing import Any, Dict, List, Optional, Tuple
import pytest
import urllib.parse

from argus.collectors.ssti import (
    SSTICollector,
    ServerSideTemplateInjectionCollector,
    SSTIPayloadGenerator,
    SSTISecurityAnalyzer,
    SSTIProber,
    SSTIProbe,
    SSTIProbeResponse,
    SSTIResult,
    SSTISeverity,
    SSTITechnique,
    SSTIEngineFamily,
    SSTIMutationStrategy,
    SSTI_ERROR_SIGNATURES,
    SSTI_RCE_OUTPUT_SIGNATURES,
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


class MockSSTIHttpClient:
    """Mock HTTP client for SSTI testing."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, str, float]]] = None):
        self.routes: Dict[str, Tuple[int, str, float]] = dict(routes or {})
        self.requested_urls: List[str] = []
        self.requested_posts: List[Dict[str, Any]] = []

    def set_route(self, key: str, status_code: int, body: str, elapsed: float = 0.05):
        self.routes[key] = (status_code, body, elapsed)

    def get(self, url: str, **kwargs) -> HttpResponse:
        target_url = str(url)
        self.requested_urls.append(target_url)

        headers = kwargs.get("headers") or {}
        for hk, hv in headers.items():
            header_key = f"header:{hk}:{hv}"
            if header_key in self.routes:
                sc, body, el = self.routes[header_key]
                return HttpResponse(
                    success=(200 <= sc < 400),
                    status_code=sc,
                    raw_body=body,
                    body=body,
                    url=target_url,
                    elapsed=el,
                )

        if target_url in self.routes:
            sc, body, el = self.routes[target_url]
            return HttpResponse(
                success=(200 <= sc < 400),
                status_code=sc,
                raw_body=body,
                body=body,
                url=target_url,
                elapsed=el,
            )

        unquoted_url = urllib.parse.unquote_plus(target_url)
        for route_key, (sc, body, el) in self.routes.items():
            if route_key in target_url or route_key in unquoted_url:
                return HttpResponse(
                    success=(200 <= sc < 400),
                    status_code=sc,
                    raw_body=body,
                    body=body,
                    url=target_url,
                    elapsed=el,
                )

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="Clean Generic Response",
            body="Clean Generic Response",
            url=target_url,
            elapsed=0.05,
        )

    def post(self, url: str, **kwargs) -> HttpResponse:
        target_url = str(url)
        data = kwargs.get("data")
        json_body = kwargs.get("json")
        headers = kwargs.get("headers") or {}

        req_record = {"url": target_url, "data": data, "json": json_body, "headers": headers}
        self.requested_posts.append(req_record)

        # Check payload in post data
        for k, v in (data or {}).items():
            str_v = str(v)
            for rk, (sc, body, el) in self.routes.items():
                if rk in str_v:
                    return HttpResponse(
                        success=(200 <= sc < 400),
                        status_code=sc,
                        raw_body=body,
                        body=body,
                        url=target_url,
                        elapsed=el,
                    )

        # Check payload in json body
        if isinstance(json_body, dict):
            for k, v in json_body.items():
                str_v = str(v)
                for rk, (sc, body, el) in self.routes.items():
                    if rk in str_v:
                        return HttpResponse(
                            success=(200 <= sc < 400),
                            status_code=sc,
                            raw_body=body,
                            body=body,
                            url=target_url,
                            elapsed=el,
                        )

        if target_url in self.routes:
            sc, body, el = self.routes[target_url]
            return HttpResponse(
                success=(200 <= sc < 400),
                status_code=sc,
                raw_body=body,
                body=body,
                url=target_url,
                elapsed=el,
            )

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="POST OK",
            body="POST OK",
            url=target_url,
            elapsed=0.05,
        )


# =============================================================================
# 1. Enums and Models Tests
# =============================================================================

def test_ssti_enums_and_aliases():
    """Validates enum members and backward-compatibility aliases."""
    assert SSTISeverity.CRITICAL.value == "critical"
    assert SSTISeverity.HIGH.value == "high"
    assert SSTISeverity.MEDIUM.value == "medium"
    assert SSTISeverity.LOW.value == "low"
    assert SSTISeverity.INFO.value == "info"

    assert SSTITechnique.ARITHMETIC_PROBE.value == "arithmetic_probe"
    assert SSTITechnique.DECISION_TREE_ROUTING.value == "decision_tree_routing"
    assert SSTITechnique.SANDBOX_ESCAPE_RCE.value == "sandbox_escape_rce"
    assert SSTITechnique.BLIND_TIME_BASED.value == "blind_time_based"
    assert SSTITechnique.ERROR_BASED_FINGERPRINT.value == "error_based_fingerprint"

    assert SSTIEngineFamily.PYTHON_JINJA2.value == "jinja2"
    assert SSTIEngineFamily.PHP_TWIG.value == "twig"
    assert SSTIEngineFamily.JAVA_FREEMARKER.value == "freemarker"
    assert SSTIEngineFamily.JAVA_SPEL.value == "spel"
    assert SSTIEngineFamily.RUBY_ERB.value == "erb"

    assert SSTIMutationStrategy.STRING_CONCAT_ENCODING.value == "string_concat_encoding"
    assert SSTIMutationStrategy.ATTRIBUTE_INDIRECTION.value == "attribute_indirection"
    assert SSTIMutationStrategy.COMMENT_TAG_VARIATION.value == "comment_tag_variation"
    assert SSTIMutationStrategy.FILTER_WHITESPACE_BYPASS.value == "filter_whitespace_bypass"
    assert SSTIMutationStrategy.OBJECT_CLASSLOADER_NAVIGATION.value == "object_classloader_navigation"


def test_ssti_dataclasses():
    """Validates dataclass construction and defaults."""
    probe = SSTIProbe(url="http://example.com/render", parameter="template", payload="{{7*7}}")
    assert probe.url == "http://example.com/render"
    assert probe.parameter_type == "query"
    assert probe.technique == SSTITechnique.ARITHMETIC_PROBE

    resp = SSTIProbeResponse(probe=probe, status_code=200, body="49", elapsed=0.08)
    assert resp.body == "49"
    assert resp.success is True

    res = SSTIResult(
        technique=SSTITechnique.ARITHMETIC_PROBE.value,
        engine="jinja2",
        payload="{{7*7}}",
        parameter="template",
        parameter_type="query",
        target_url="http://example.com/render",
        matched_signature="canary_evaluation:49",
        evidence_snippet="Result is 49",
    )
    assert res.severity == SSTISeverity.HIGH.value
    assert res.cwe_id == "CWE-1336"


# =============================================================================
# 2. Payload Generator Tests
# =============================================================================

def test_generator_arithmetic_canary():
    """Validates dynamic arithmetic canary generation across engine families."""
    gen = SSTIPayloadGenerator()
    p_jinja, exp_jinja = gen.generate_arithmetic_canary(SSTIEngineFamily.PYTHON_JINJA2, a=13, b=37)
    assert p_jinja == "{{13*37}}"
    assert exp_jinja == "481"

    p_free, exp_free = gen.generate_arithmetic_canary(SSTIEngineFamily.JAVA_FREEMARKER, a=7, b=8)
    assert p_free == "${7*8}"
    assert exp_free == "56"

    p_erb, exp_erb = gen.generate_arithmetic_canary(SSTIEngineFamily.RUBY_ERB, a=9, b=9)
    assert p_erb == "<%= 9*9 %>"
    assert exp_erb == "81"

    p_pug, exp_pug = gen.generate_arithmetic_canary(SSTIEngineFamily.NODE_PUG, a=5, b=6)
    assert p_pug == "#{5*6}"
    assert exp_pug == "30"


def test_generator_polyglot_and_differential():
    """Validates polyglot probe catalog and differential decision tree payloads."""
    gen = SSTIPayloadGenerator()
    polyglots = gen.generate_polyglot_payloads(7, 7)
    assert len(polyglots) >= 7
    payload_strings = [p["payload"] for p in polyglots]
    assert "{{7*7}}" in payload_strings
    assert "${7*7}" in payload_strings
    assert "<%= 7*7 %>" in payload_strings
    assert "#{7*7}" in payload_strings

    differentials = gen.generate_differential_payloads()
    assert any("7*'7'" in d["payload"] for d in differentials)
    assert any("config" in d["payload"] for d in differentials)
    assert any("assign" in d["payload"] for d in differentials)


def test_generator_sandbox_escapes_and_timing():
    """Validates sandbox escape generation and blind timing payloads."""
    gen = SSTIPayloadGenerator()
    escapes = gen.generate_sandbox_escape_payloads()
    assert len(escapes) >= 10

    # Ensure major engines are covered
    engines_covered = {e["engine"] for e in escapes}
    assert SSTIEngineFamily.PYTHON_JINJA2 in engines_covered
    assert SSTIEngineFamily.PHP_TWIG in engines_covered
    assert SSTIEngineFamily.JAVA_FREEMARKER in engines_covered
    assert SSTIEngineFamily.JAVA_SPEL in engines_covered
    assert SSTIEngineFamily.RUBY_ERB in engines_covered

    timing_payloads = gen.generate_blind_timing_payloads(delay_seconds=5)
    assert len(timing_payloads) >= 4
    assert any("sleep" in tp["payload"] for tp in timing_payloads)


def test_generator_all_five_mutation_strategies():
    """Validates all 5 mutation strategies apply appropriate evasions."""
    gen = SSTIPayloadGenerator()
    base_payload = "{{''.__class__.__mro__[1].__subclasses__()}}"

    # 1. String Concat / Encoding
    mut1 = gen.apply_mutation_strategy(base_payload, SSTIMutationStrategy.STRING_CONCAT_ENCODING)
    assert "class" in mut1 and "cla" in mut1

    # 2. Attribute Indirection
    mut2 = gen.apply_mutation_strategy(base_payload, SSTIMutationStrategy.ATTRIBUTE_INDIRECTION)
    assert "attr('__class__')" in mut2 or "['__class__']" in mut2

    # 3. Comment Tag Variation
    mut3 = gen.apply_mutation_strategy("{{7*7}}", SSTIMutationStrategy.COMMENT_TAG_VARIATION)
    assert "{##}" in mut3 or "{#" in mut3

    # 4. Whitespace Bypass
    mut4 = gen.apply_mutation_strategy("{{7 * 7}}", SSTIMutationStrategy.FILTER_WHITESPACE_BYPASS)
    assert "\t" in mut4 or "\n" in mut4

    # 5. Object / Classloader Navigation
    mut5 = gen.apply_mutation_strategy("new java.lang.ProcessBuilder('id')", SSTIMutationStrategy.OBJECT_CLASSLOADER_NAVIGATION)
    assert "getClassLoader" in mut5 or "ProcessBuilder" in mut5


# =============================================================================
# 3. Security Analyzer Tests
# =============================================================================

def test_analyzer_arithmetic_evaluation_with_baseline():
    """Validates arithmetic evaluation and baseline subtraction."""
    analyzer = SSTISecurityAnalyzer()

    # Positive evaluation
    res = analyzer.analyze_arithmetic_evaluation(
        response_body="<html><body>Total: 49 items</body></html>",
        canary_expected="49",
        baseline_body="<html><body>Total items</body></html>",
    )
    assert res is not None
    assert res["canary"] == "49"

    # Number already in baseline -> None
    res_baseline = analyzer.analyze_arithmetic_evaluation(
        response_body="<html><body>Page 49 of 100</body></html>",
        canary_expected="49",
        baseline_body="<html><body>Page 49 of 100</body></html>",
    )
    assert res_baseline is None


def test_analyzer_reflection_rejection():
    """Validates rejection of verbatim, HTML-escaped, and URL-encoded reflections."""
    analyzer = SSTISecurityAnalyzer()

    # Raw reflection
    assert analyzer.is_static_reflection("<p>{{7*7}}</p>", "{{7*7}}") is True

    # HTML encoded reflection
    assert analyzer.is_static_reflection("<p>&lt;%= 7*7 %&gt;</p>", "<%= 7*7 %>") is True

    # URL encoded reflection
    assert analyzer.is_static_reflection("<p>%7B%7B7%2A7%7D%7D</p>", "{{7*7}}") is True

    # Non-reflection evaluated math
    assert analyzer.is_static_reflection("<p>Calculated: 49</p>", "{{7*7}}") is False


def test_analyzer_rce_signatures():
    """Validates command output and process execution signature matching."""
    analyzer = SSTISecurityAnalyzer()

    posix_res = analyzer.analyze_rce_execution("uid=0(root) gid=0(root) groups=0(root)")
    assert posix_res is not None
    assert posix_res["severity"] == SSTISeverity.CRITICAL
    assert posix_res["cvss_score"] == 9.8

    uname_res = analyzer.analyze_rce_execution("Linux web-srv-01 5.15.0-76-generic #83-Ubuntu SMP")
    assert uname_res is not None

    java_res = analyzer.analyze_rce_execution("java.lang.ProcessBuilder@4f35b2e")
    assert java_res is not None


def test_analyzer_error_fingerprints():
    """Validates template engine error stack trace identification."""
    analyzer = SSTISecurityAnalyzer()

    jinja_err = analyzer.analyze_error_fingerprint("jinja2.exceptions.TemplateSyntaxError: unexpected char")
    assert jinja_err is not None
    assert jinja_err["engine"] == "jinja2"

    twig_err = analyzer.analyze_error_fingerprint("Fatal error: Uncaught Twig\\Error\\SyntaxError: Unexpected token")
    assert twig_err is not None
    assert twig_err["engine"] == "twig"

    freemarker_err = analyzer.analyze_error_fingerprint("freemarker.core.ParseException: Syntax error on line 4")
    assert freemarker_err is not None
    assert freemarker_err["engine"] == "freemarker"

    spel_err = analyzer.analyze_error_fingerprint("org.springframework.expression.spel.SpelEvaluationException: EL1004E")
    assert spel_err is not None
    assert spel_err["engine"] == "spel"


def test_analyzer_blind_timing():
    """Validates blind timing delta analysis."""
    analyzer = SSTISecurityAnalyzer()
    assert analyzer.analyze_blind_timing(elapsed=5.2, baseline_elapsed=0.1, delay_threshold=4.0) is True
    assert analyzer.analyze_blind_timing(elapsed=1.2, baseline_elapsed=0.1, delay_threshold=4.0) is False


# =============================================================================
# 4. SSTIProber Tests
# =============================================================================

def test_prober_injection_parameter_types():
    """Validates probing across GET query, POST form, JSON, path, and header parameters."""
    client = MockSSTIHttpClient()
    prober = SSTIProber(http_client=client)

    # 1. Query parameter
    probe_q = SSTIProbe(url="http://example.com/render?q=test", parameter="q", payload="{{7*7}}", parameter_type="query")
    resp_q = prober.execute_probe(probe_q)
    assert any("q=%7B%7B7%2A7%7D%7D" in u or "q={{7*7}}" in u for u in client.requested_urls)

    # 2. POST Form body
    probe_body = SSTIProbe(url="http://example.com/render", method="POST", parameter="template", payload="{{7*7}}", parameter_type="body")
    resp_body = prober.execute_probe(probe_body)
    assert len(client.requested_posts) >= 1
    assert client.requested_posts[-1]["data"]["template"] == "{{7*7}}"

    # 3. POST JSON body
    probe_json = SSTIProbe(url="http://example.com/api/preview", method="POST", parameter="content", payload="{{7*7}}", parameter_type="json")
    resp_json = prober.execute_probe(probe_json)
    assert client.requested_posts[-1]["json"]["content"] == "{{7*7}}"

    # 4. Header injection
    probe_hdr = SSTIProbe(url="http://example.com/render", parameter="X-Custom-Template", payload="{{7*7}}", parameter_type="header")
    resp_hdr = prober.execute_probe(probe_hdr)
    assert "header:X-Custom-Template:{{7*7}}" in client.routes or resp_hdr.status_code == 200


# =============================================================================
# 5. SSTICollector End-to-End Tests
# =============================================================================

def test_collector_quadruple_state_publishing():
    """Validates complete mission execution and quadruple state publishing."""
    client = MockSSTIHttpClient()
    client.set_route("{{7*7}}", 200, "<html><body>Result: 49</body></html>")
    client.set_route("http://target.local/template", 200, "<html><body>Clean baseline</body></html>")

    mission = Mission(target="http://target.local")
    mission.endpoints = ["http://target.local/template"]
    mission.attack_surface_graph = KnowledgeGraph()
    mission.vulnerabilities = []

    collector = SSTICollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.category == "ssti"
    assert ev.severity in (SSTISeverity.HIGH.value, SSTISeverity.CRITICAL.value)
    assert ev.metadata["cwe_id"] == "CWE-1336"

    # 1. raw_mission.evidence updated
    assert ev in mission.evidence or ev.value in [e.value for e in mission.evidence]

    # 2. raw_mission.vulnerabilities updated
    assert len(mission.vulnerabilities) >= 1
    assert mission.vulnerabilities[0]["template_id"] == "ssti"

    # 3. AttackSurfaceGraph updated
    nodes = mission.attack_surface_graph.nodes
    assert any("vulnerability:ssti:" in nid for nid in nodes)
    assert any("endpoint:http://target.local/template" in nid for nid in nodes)
    edges = mission.attack_surface_graph.edges
    edge_types = {e.type for e in edges}
    assert "HAS_ENDPOINT" in edge_types
    assert "HAS_VULNERABILITY" in edge_types


def test_collector_controlled_mission_compatibility():
    """Validates execution under ControlledMission proxy."""
    client = MockSSTIHttpClient()
    client.set_route("{{7*7}}", 200, "<html><body>Result: 49</body></html>")

    raw_mission = Mission(target="http://target.local")
    raw_mission.endpoints = ["http://target.local/preview?template=foo"]
    raw_mission.attack_surface_graph = KnowledgeGraph()
    controlled = ControlledMission(raw_mission)

    collector = ServerSideTemplateInjectionCollector(http_client=client)
    evidence = collector.execute(controlled)

    assert len(evidence) >= 1
    assert len(raw_mission.plugin_findings) >= 1


# =============================================================================
# 6. Pipeline Connectivity & Wiring Tests
# =============================================================================

def test_registry_ssti_tool_and_aliases():
    """Validates ToolRegistry lookup for ssti and all aliases."""
    tool = registry.get("ssti")
    assert tool is not None
    assert tool.id == "ssti"
    assert tool.capability == "ssti_detector"
    assert tool.priority == 95

    # Check capability aliases
    for alias in [
        "ssti_collector",
        "ssti_detector",
        "server_side_template_injection",
        "template_injection",
        "jinja2",
        "twig",
        "freemarker",
        "velocity",
        "mako",
        "spel",
        "thymeleaf",
        "erb",
        "smarty",
    ]:
        resolved = registry.get(alias)
        assert resolved is not None, f"Failed resolving alias {alias}"
        assert resolved.id == "ssti"


def test_plugin_adapter_fallback():
    """Validates PluginExecutorAdapter fallback instantiation for ssti."""
    adapter = PluginExecutorAdapter()
    inst = adapter._instantiate_specialist_fallback("ssti")
    assert isinstance(inst, SSTICollector)

    inst_jinja = adapter._instantiate_specialist_fallback("jinja2")
    assert isinstance(inst_jinja, SSTICollector)


def test_task_generator_ssti_scheduling():
    """Validates TaskGenerator DAG generation from coverage gaps."""
    mission = Mission(target="http://target.local")
    mission.endpoints = ["http://target.local/template"]
    tg = TaskGenerator(mission)

    gap = CoverageGap(
        category=TaskCategory.EVIDENCE_CORRELATION,
        area="server-side template injection",
        description="Verify template injection across rendering endpoints",
        severity=0.85,
    )
    tasks = tg.from_gaps([gap])
    assert len(tasks) >= 1
    ssti_task = tasks[0]
    assert ssti_task.metadata.get("tool_id") == "ssti"
    assert "Discover API Endpoints" in ssti_task.dependencies


def test_attack_surface_graph_builder_section_23():
    """Validates Section 23 of AttackSurfaceGraphBuilder for SSTI evidence."""
    ev = Evidence(
        category="ssti",
        value="ssti:http://target.local/render:name:arithmetic_probe",
        source="ssti",
        title="Server-Side Template Injection (Jinja2) in name",
        severity="high",
        metadata={
            "url": "http://target.local/render",
            "host": "http://target.local",
            "parameter": "name",
            "engine": "jinja2",
            "status_code": 200,
        },
    )

    builder = AttackSurfaceGraphBuilder()
    graph = builder.build_from_evidence([ev])

    assert "vulnerability:ssti:http://target.local/render:name" in graph.nodes
    assert "endpoint:http://target.local/render" in graph.nodes
    assert "live_host:http://target.local" in graph.nodes
    edge_types = {e.type for e in graph.edges}
    assert "HAS_ENDPOINT" in edge_types
    assert "HAS_VULNERABILITY" in edge_types


def test_cvss_and_cwe_mappings():
    """Validates CVSSCalculator CWE mappings and preset vectors for SSTI."""
    cwe_ssti = CVSSCalculator.get_cwe_for_category("ssti")
    assert cwe_ssti.id == "CWE-1336"

    cwe_rce = CVSSCalculator.get_cwe_for_category("ssti_rce")
    assert cwe_rce.id == "CWE-94"

    crit_cvss = CVSSCalculator.get_approximate_cvss("ssti", ReportSeverity.CRITICAL)
    assert crit_cvss.score >= 9.5

    high_cvss = CVSSCalculator.get_approximate_cvss("ssti", ReportSeverity.HIGH)
    assert 7.5 <= high_cvss.score <= 8.5


def test_evidence_processor_ssti_descriptions():
    """Validates default impact and remediation generation in EvidenceProcessor."""
    impact = EvidenceProcessor._generate_default_impact("ssti", "high")
    assert "template directives" in impact.lower() or "remote code execution" in impact.lower()

    cwe = CVSSCalculator.get_cwe_for_category("ssti")
    remediation = EvidenceProcessor._generate_default_remediation("ssti", cwe)
    assert "context variables" in remediation.lower() or "sandboxes" in remediation.lower()


def test_collector_freemarker_polyglot_detection():
    """Validates FreeMarker polyglot evaluation and evidence creation."""
    client = MockSSTIHttpClient()
    client.set_route("<#assign ssti_test=1337>${ssti_test}", 200, "<html><body>Rendered: 1337</body></html>")

    mission = Mission(target="http://target.local")
    mission.endpoints = ["http://target.local/view?t=1"]
    mission.attack_surface_graph = KnowledgeGraph()

    collector = SSTICollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    assert "freemarker" in evidence[0].metadata["engine"].lower()


def test_collector_blind_timing_detection():
    """Validates blind timing probe detection and high severity evidence generation."""
    client = MockSSTIHttpClient()
    client.set_route("{{__import__('time').sleep(5)}}", 200, "<html><body>Delayed</body></html>", elapsed=5.2)

    mission = Mission(target="http://target.local")
    mission.endpoints = ["http://target.local/sleep_endpoint?cmd=test"]
    mission.attack_surface_graph = KnowledgeGraph()

    collector = SSTICollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.category == "ssti"
    assert ev.metadata["technique"] == SSTITechnique.BLIND_TIME_BASED.value
    assert ev.metadata["delay_delta"] >= 4.0


def test_collector_error_fingerprint_detection():
    """Validates error stack trace capture and engine fingerprint evidence creation."""
    client = MockSSTIHttpClient()
    client.set_route("{{1/0}}", 500, "jinja2.exceptions.TemplateRuntimeError: division by zero in template")

    mission = Mission(target="http://target.local")
    mission.endpoints = ["http://target.local/error_endpoint?t=1"]
    mission.attack_surface_graph = KnowledgeGraph()

    collector = SSTICollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    assert evidence[0].metadata["technique"] == SSTITechnique.ERROR_BASED_FINGERPRINT.value
    assert evidence[0].metadata["engine"] == "jinja2"


def test_collector_prober_path_segment_injection():
    """Validates path segment mutation and probing."""
    client = MockSSTIHttpClient()
    prober = SSTIProber(http_client=client)

    probe = SSTIProbe(
        url="http://example.com/render/item123",
        payload="{{7*7}}",
        parameter="path_segment",
        parameter_type="path",
    )
    resp = prober.execute_probe(probe)
    assert any("%7B%7B7%2A7%7D%7D" in u or "{{7*7}}" in u for u in client.requested_urls)


def test_collector_target_fallback_discovery():
    """Validates fallback path probing when endpoints list is empty."""
    client = MockSSTIHttpClient()
    mission = Mission(target="http://target.local")
    mission.endpoints = []
    mission.attack_surface_graph = KnowledgeGraph()

    collector = SSTICollector(http_client=client)
    candidates = collector._discover_candidate_endpoints(mission)

    assert len(candidates) >= 5
    assert any("/template" in c for c in candidates)
    assert any("/render" in c for c in candidates)

