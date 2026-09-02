"""
Comprehensive Unit and Integration Tests for XMLParserSecurityCollector, XMLPayloadGenerator,
XMLParserAnalyzer, AttackSurfaceGraph integration, TaskGenerator DAG wiring, and ToolRegistry.
"""
from typing import Any, Dict, List, Optional, Tuple
import pytest
import urllib.parse

from argus.collectors.xml_parser import (
    XMLParserSecurityCollector,
    XMLParserValidationCollector,
    XXECollector,
    XMLPayloadGenerator,
    XMLParserAnalyzer,
    XMLValidationResult,
    XMLTechnique,
    XMLMutationStrategy,
    TARGET_FILE_SIGNATURES,
    PARSER_ERROR_SIGNATURES,
)
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.plugins.interfaces import ControlledMission
from argus.reporting.cvss import CVSSCalculator
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry


class MockXMLHttpClient:
    """Mock HTTP client for XML parser tests supporting customizable routes and response payloads."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, str, float]]] = None):
        self.routes: Dict[str, Tuple[int, str, float]] = routes or {}
        self.requested_urls: List[str] = []
        self.requested_posts: List[Dict[str, Any]] = []

    def set_route(self, key: str, status_code: int, body: str, elapsed: float = 0.05):
        self.routes[key] = (status_code, body, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        self.requested_urls.append(target_url)

        # Check exact url
        if target_url in self.routes:
            code, body, el = self.routes[target_url]
            return HttpResponse(success=(200 <= code < 300), status_code=code, raw_body=body, body=body, url=target_url, elapsed=el)

        # Match payload keywords inside query
        for k, (code, body, el) in self.routes.items():
            if k in target_url:
                return HttpResponse(success=(200 <= code < 300), status_code=code, raw_body=body, body=body, url=target_url, elapsed=el)

        return HttpResponse(success=True, status_code=200, raw_body="<ok/>", body="<ok/>", url=target_url, elapsed=0.05)

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        data = kwargs.get("data")
        json_data = kwargs.get("json")
        headers = kwargs.get("headers") or {}
        self.requested_posts.append({"url": target_url, "data": data, "json": json_data, "headers": headers})

        # Match based on data or json
        payload_str = ""
        if isinstance(data, (bytes, bytearray)):
            payload_str = data.decode("latin1", errors="ignore")
        elif isinstance(data, str):
            payload_str = data
        elif isinstance(json_data, dict):
            payload_str = json_data.get("xml", "") or json_data.get("data", "") or str(json_data)

        # 1. Check exact key match
        for key, (code, body, el) in self.routes.items():
            if key in payload_str or key == target_url:
                return HttpResponse(success=(200 <= code < 300), status_code=code, raw_body=body, body=body, url=target_url, elapsed=el)

        # 2. Check if baseline probe
        if "argus_baseline_probe" in payload_str:
            return HttpResponse(success=True, status_code=200, raw_body="<response><status>baseline_ok</status></response>", body="<response><status>baseline_ok</status></response>", url=target_url, elapsed=0.04)

        return HttpResponse(success=True, status_code=200, raw_body="<root><result>parsed</result></root>", body="<root><result>parsed</result></root>", url=target_url, elapsed=0.05)


# -----------------------------------------------------------------------------
# 1. Payload Generator Tests
# -----------------------------------------------------------------------------

def test_payload_generator_entity_resolution():
    """Verify entity resolution payload generation for safe local files and canary tokens."""
    gen = XMLPayloadGenerator()
    payloads = gen.generate_entity_resolution_payloads()
    assert len(payloads) >= 6

    # Verify /etc/passwd payload
    passwd_probes = [p for p in payloads if p["target_file"] == "/etc/passwd"]
    assert len(passwd_probes) == 1
    assert "file:///etc/passwd" in passwd_probes[0]["payload"]
    assert passwd_probes[0]["technique"] == XMLTechnique.ENTITY_RESOLUTION.value

    # Verify canary payload
    canary_probes = [p for p in payloads if p["file_type"] == "canary"]
    assert len(canary_probes) == 1
    assert gen.CANARY_TOKEN in canary_probes[0]["payload"]


def test_payload_generator_parameter_entities():
    """Verify parameter entity and error-based DTD wrapper payload generation."""
    gen = XMLPayloadGenerator()
    payloads = gen.generate_parameter_entity_payloads()
    assert len(payloads) >= 4

    # Verify standard %pe; probe
    pe_probes = [p for p in payloads if "%pe;" in p["payload"]]
    assert len(pe_probes) >= 1
    assert pe_probes[0]["technique"] == XMLTechnique.PARAMETER_ENTITY.value

    # Verify error-based %eval; probe
    eval_probes = [p for p in payloads if "%eval;" in p["payload"]]
    assert len(eval_probes) >= 1
    assert "nonexistent" in eval_probes[0]["payload"]


def test_payload_generator_recursive_expansion():
    """Verify calibrated safe Billion Laughs and quadratic expansion payloads."""
    gen = XMLPayloadGenerator()
    payloads = gen.generate_recursive_entity_payloads(depth=4)
    assert len(payloads) == 2

    # Billion laughs
    bl = payloads[0]
    assert bl["technique"] == XMLTechnique.RECURSIVE_ENTITY.value
    assert "&lol4;" in bl["payload"]
    assert "argus_laugh_token_0123456789" in bl["payload"]

    # Quadratic
    quad = payloads[1]
    assert quad["technique"] == XMLTechnique.RECURSIVE_ENTITY.value
    assert "&quad_all;" in quad["payload"]


def test_payload_generator_mutation_strategies():
    """Verify all 5+ parser bypass mutation strategies."""
    gen = XMLPayloadGenerator()
    mutations = gen.generate_mutated_payloads()
    assert len(mutations) >= 9

    # Strategy 1: UTF-16 with BOM and UTF-7
    utf16_probes = [m for m in mutations if m["mutation_strategy"] == XMLMutationStrategy.UTF16_ENCODING.value]
    assert len(utf16_probes) >= 2
    assert "raw_bytes" in utf16_probes[0]
    assert "UTF-16" in utf16_probes[0]["content_type"]

    utf7_probes = [m for m in mutations if m["mutation_strategy"] == XMLMutationStrategy.UTF7_ENCODING.value]
    assert len(utf7_probes) >= 1
    assert "UTF-7" in utf7_probes[0]["payload"] or "charset=utf-7" in utf7_probes[0]["content_type"]

    # Strategy 2: CDATA Parameter Entity Wrapping
    cdata_probes = [m for m in mutations if m["mutation_strategy"] == XMLMutationStrategy.CDATA_WRAPPING.value]
    assert len(cdata_probes) >= 1
    assert "<![CDATA[" in cdata_probes[0]["payload"]
    assert "%start;" in cdata_probes[0]["payload"]

    # Strategy 3: DOCTYPE Variations (PUBLIC, comments, case)
    doctype_probes = [m for m in mutations if m["mutation_strategy"] in (XMLMutationStrategy.DOCTYPE_PUBLIC.value, XMLMutationStrategy.DOCTYPE_VARIATIONS.value)]
    assert len(doctype_probes) >= 3

    # Strategy 4: XML Namespaces and SOAP 1.1 / 1.2 Envelopes
    soap_probes = [m for m in mutations if m["mutation_strategy"] == XMLMutationStrategy.NAMESPACE_SOAP.value]
    assert len(soap_probes) >= 3
    assert any("soapenv:Envelope" in s["payload"] for s in soap_probes)
    assert any("application/soap+xml" in s["content_type"] for s in soap_probes)

    # Strategy 5: XInclude Directives
    xinc_probes = [m for m in mutations if m["mutation_strategy"] == XMLMutationStrategy.XINCLUDE.value]
    assert len(xinc_probes) >= 2
    assert any("xmlns:xi=" in x["payload"] for x in xinc_probes)


def test_payload_generator_generate_all():
    """Verify generate_all_payloads aggregates all validation probes."""
    gen = XMLPayloadGenerator()
    all_p = gen.generate_all_payloads()
    assert len(all_p) >= 20
    for p in all_p:
        assert "payload" in p
        assert "technique" in p
        assert "mutation_strategy" in p
        assert "target_file" in p


# -----------------------------------------------------------------------------
# 2. Analyzer Tests
# -----------------------------------------------------------------------------

def test_analyzer_unix_file_reflection():
    """Verify analyzer identifies Unix /etc/passwd and /etc/hosts reflections as Critical findings."""
    analyzer = XMLParserAnalyzer()
    payload_info = {
        "technique": XMLTechnique.ENTITY_RESOLUTION.value,
        "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
        "target_file": "/etc/passwd",
        "file_type": "unix_passwd",
        "payload": '<!ENTITY xxe SYSTEM "file:///etc/passwd"><root>&xxe;</root>',
    }

    # Positive detection: genuine passwd file content
    resp = HttpResponse(
        success=True,
        status_code=200,
        body="<response><data>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</data></response>",
        elapsed=0.06,
    )
    result = analyzer.analyze_response(resp, payload_info)
    assert result is not None
    assert result.is_valid_finding is True
    assert result.severity == "critical"
    assert result.confidence == 0.95
    assert result.matched_signature == "unix_passwd"
    assert "root:x:0:0" in result.evidence_snippet


def test_analyzer_windows_file_reflection():
    """Verify analyzer identifies Windows win.ini reflection as Critical finding."""
    analyzer = XMLParserAnalyzer()
    payload_info = {
        "technique": XMLTechnique.ENTITY_RESOLUTION.value,
        "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
        "target_file": "win.ini",
        "file_type": "windows_win_ini",
        "payload": '<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"><root>&xxe;</root>',
    }

    resp = HttpResponse(
        success=True,
        status_code=200,
        body="<config>[fonts]\r\nArial=arial.ttf\r\n[extensions]\r\n[mci extensions]</config>",
        elapsed=0.08,
    )
    result = analyzer.analyze_response(resp, payload_info)
    assert result is not None
    assert result.severity == "critical"
    assert result.matched_signature == "windows_win_ini"
    assert "[fonts]" in result.evidence_snippet


def test_analyzer_canary_token_detection():
    """Verify analyzer detects injected canary token reflection."""
    analyzer = XMLParserAnalyzer()
    payload_info = {
        "technique": XMLTechnique.ENTITY_RESOLUTION.value,
        "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
        "target_file": "canary_token",
        "file_type": "canary",
        "payload": f'<!ENTITY xxe "{XMLPayloadGenerator.CANARY_TOKEN}"><root>&xxe;</root>',
    }

    resp = HttpResponse(
        success=True,
        status_code=200,
        body=f"<root><item>{XMLPayloadGenerator.CANARY_TOKEN}</item></root>",
        elapsed=0.05,
    )
    result = analyzer.analyze_response(resp, payload_info)
    assert result is not None
    assert result.matched_signature == "canary_token"
    assert result.severity == "critical"


def test_analyzer_parameter_entity_error_leak():
    """Verify analyzer detects parameter entity error leaks (FileNotFoundException disclosing path)."""
    analyzer = XMLParserAnalyzer()
    payload_info = {
        "technique": XMLTechnique.PARAMETER_ENTITY.value,
        "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
        "target_file": "/etc/hostname",
        "file_type": "unix_hostname",
        "payload": '<!ENTITY % pe SYSTEM "file:///etc/hostname">%pe;',
    }

    resp = HttpResponse(
        success=False,
        status_code=500,
        body="java.io.FileNotFoundException: /nonexistent/prod-worker-node-01.internal (No such file or directory)",
        elapsed=0.09,
    )
    result = analyzer.analyze_response(resp, payload_info)
    assert result is not None
    assert result.technique == XMLTechnique.PARAMETER_ENTITY.value
    assert result.matched_signature == "parameter_entity_error_leak"
    assert result.severity in ("critical", "high")


def test_analyzer_recursive_expansion_latency():
    """Verify analyzer flags recursive entity expansion latency differential >= 3.0s."""
    analyzer = XMLParserAnalyzer()
    payload_info = {
        "technique": XMLTechnique.RECURSIVE_ENTITY.value,
        "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
        "target_file": "recursive_expansion",
        "file_type": "recursive_expansion",
        "payload": '<!ENTITY lol4 "..."><root>&lol4;</root>',
    }

    baseline = HttpResponse(success=True, status_code=200, body="<ok/>", elapsed=0.05)
    injected_resp = HttpResponse(success=True, status_code=200, body="<ok/>", elapsed=3.50)

    result = analyzer.analyze_response(injected_resp, payload_info, baseline_response=baseline)
    assert result is not None
    assert result.technique == XMLTechnique.RECURSIVE_ENTITY.value
    assert result.severity == "high"
    assert result.matched_signature == "latency_differential_delay"
    assert result.delay_delta >= 3.0


def test_analyzer_parser_limit_errors():
    """Verify analyzer flags parser entity expansion limit exceptions."""
    analyzer = XMLParserAnalyzer()
    payload_info = {
        "technique": XMLTechnique.RECURSIVE_ENTITY.value,
        "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
        "target_file": "recursive_expansion",
        "file_type": "recursive_expansion",
        "payload": '<!ENTITY lol4 "..."><root>&lol4;</root>',
    }

    # Xerces limit error
    resp = HttpResponse(
        success=False,
        status_code=500,
        body="org.xml.sax.SAXParseException: The parser has reached the entity expansion limit \"64,000\" set by the application.",
        elapsed=0.10,
    )
    result = analyzer.analyze_response(resp, payload_info)
    assert result is not None
    assert result.severity == "medium"
    assert result.matched_signature == "java_entity_expansion_limit"


def test_analyzer_echo_guard_unexpanded_entities():
    """Verify echo guard rejects responses that merely echo unexpanded entities or raw payload."""
    analyzer = XMLParserAnalyzer()
    payload_info = {
        "technique": XMLTechnique.ENTITY_RESOLUTION.value,
        "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
        "target_file": "/etc/passwd",
        "file_type": "unix_passwd",
        "payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><item>&xxe;</item></root>',
    }

    # 1. Unexpanded literal &xxe; echo without resolved file contents
    resp_unexpanded = HttpResponse(
        success=True,
        status_code=200,
        body="<root><item>&xxe;</item></root>",
        elapsed=0.05,
    )
    result_unexpanded = analyzer.analyze_response(resp_unexpanded, payload_info)
    assert result_unexpanded is None

    # 2. Verbatim payload reflection echo
    resp_verbatim = HttpResponse(
        success=True,
        status_code=200,
        body='You sent: <?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><item>&xxe;</item></root>',
        elapsed=0.05,
    )
    result_verbatim = analyzer.analyze_response(resp_verbatim, payload_info)
    assert result_verbatim is None


def test_analyzer_baseline_subtraction():
    """Verify baseline subtraction suppresses false positives already present in baseline."""
    analyzer = XMLParserAnalyzer()
    payload_info = {
        "technique": XMLTechnique.ENTITY_RESOLUTION.value,
        "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
        "target_file": "/proc/version",
        "file_type": "unix_version",
        "payload": '<!ENTITY xxe SYSTEM "file:///proc/version"><root>&xxe;</root>',
    }

    server_banner = "Server running on Linux version 5.15.0-generic (buildd@glacier)"
    baseline = HttpResponse(success=True, status_code=200, body=f"<info>{server_banner}</info>", elapsed=0.05)
    injected_resp = HttpResponse(success=True, status_code=200, body=f"<response>{server_banner}</response>", elapsed=0.05)

    result = analyzer.analyze_response(injected_resp, payload_info, baseline_response=baseline)
    assert result is None  # Suppressed because signature was in baseline


# -----------------------------------------------------------------------------
# 3. Collector Integration Tests with Mock HTTP Client
# -----------------------------------------------------------------------------

def test_collector_critical_entity_resolution():
    """Verify collector identifies external entity resolution vulnerability and creates Critical Evidence."""
    mock_http = MockXMLHttpClient()
    mock_http.set_route(
        "file:///etc/passwd",
        200,
        "<response><user>root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin</user></response>",
    )

    collector = XMLParserSecurityCollector(http_client=mock_http)
    mission = Mission(
        target="https://vuln-app.local",
        endpoints=[{"url": "https://vuln-app.local/api/xml", "method": "POST"}],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "xml_parser_validation"
    assert ev.severity == "critical"
    assert ev.confidence == 0.95
    assert ev.status == "CONFIRMED"
    assert "root:x:0:0" in ev.description or "root:x:0:0" in ev.metadata.get("evidence_snippet", "")
    assert len(mission.vulnerabilities) >= 1


def test_collector_recursive_entity_expansion():
    """Verify collector detects recursive entity expansion susceptibility."""
    mock_http = MockXMLHttpClient()
    mock_http.set_route(
        "argus_laugh_token_0123456789",
        200,
        "org.xml.sax.SAXParseException: The parser has reached the entity expansion limit \"64,000\"",
        elapsed=0.1,
    )

    collector = XMLParserSecurityCollector(http_client=mock_http)
    mission = Mission(
        target="https://dos-app.local",
        endpoints=[{"url": "https://dos-app.local/api/parse", "method": "POST"}],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.metadata.get("technique") == XMLTechnique.RECURSIVE_ENTITY.value
    assert ev.severity in ("medium", "high")


def test_collector_clean_endpoint_no_findings():
    """Verify collector on properly configured XML parser emits zero findings."""
    mock_http = MockXMLHttpClient()  # Returns benign <root><result>parsed</result></root>
    collector = XMLParserSecurityCollector(http_client=mock_http)
    mission = Mission(
        target="https://secure-app.local",
        endpoints=[{"url": "https://secure-app.local/api/xml", "method": "POST"}],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) == 0
    assert len(mission.vulnerabilities) == 0


def test_collector_parameter_based_xml_query():
    """Verify collector tests query parameters containing structured XML."""
    mock_http = MockXMLHttpClient()
    mock_http.set_route(
        "file%3A%2F%2F%2Fetc%2Fpasswd",
        200,
        "<res>root:x:0:0:root:/root:/bin/sh</res>",
    )
    # Also handle direct decoded route in case url contains decoded payload
    mock_http.set_route(
        "file:///etc/passwd",
        200,
        "<res>root:x:0:0:root:/root:/bin/sh</res>",
    )

    collector = XMLParserSecurityCollector(http_client=mock_http)
    mission = Mission(
        target="https://query-app.local",
        endpoints=[{"url": "https://query-app.local/process?xml=test", "method": "GET"}],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    assert evidence_list[0].metadata.get("parameter") == "xml"
    assert evidence_list[0].metadata.get("parameter_type") == "query_parameter"


def test_collector_parameter_based_xml_json():
    """Verify collector tests JSON fields containing XML strings."""
    mock_http = MockXMLHttpClient()
    mock_http.set_route(
        "file:///etc/passwd",
        200,
        '{"status": "ok", "result": "root:x:0:0:root:/root:/bin/bash"}',
    )

    collector = XMLParserSecurityCollector(http_client=mock_http)
    mission = Mission(
        target="https://json-app.local",
        endpoints=[{
            "url": "https://json-app.local/api/import",
            "method": "POST",
            "body": {"doc": "<root></root>"},
        }],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    assert evidence_list[0].metadata.get("parameter") == "doc"
    assert evidence_list[0].metadata.get("parameter_type") == "json_field"


def test_collector_soap_envelope():
    """Verify collector validates SOAP envelopes."""
    mock_http = MockXMLHttpClient()
    mock_http.set_route(
        "soapenv:Envelope",
        200,
        "<soapenv:Envelope><soapenv:Body><Response>root:x:0:0:root:/root:/bin/bash</Response></soapenv:Body></soapenv:Envelope>",
    )

    collector = XMLParserSecurityCollector(http_client=mock_http)
    mission = Mission(
        target="https://soap-app.local",
        endpoints=[{"url": "https://soap-app.local/ws", "method": "POST", "headers": {"Content-Type": "text/xml"}}],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    assert evidence_list[0].severity == "critical"


def test_collector_xinclude_directive():
    """Verify collector tests and validates XInclude directives."""
    mock_http = MockXMLHttpClient()
    mock_http.set_route(
        "xmlns:xi=",
        200,
        "<root><item>root:x:0:0:root:/root:/bin/bash</item></root>",
    )

    collector = XMLParserSecurityCollector(http_client=mock_http)
    mission = Mission(
        target="https://xinclude-app.local",
        endpoints=[{"url": "https://xinclude-app.local/upload", "method": "POST"}],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    assert evidence_list[0].metadata.get("technique") == XMLTechnique.XINCLUDE.value


# -----------------------------------------------------------------------------
# 4. Attack Surface Graph & KnowledgeGraph Tests
# -----------------------------------------------------------------------------

def test_collector_knowledge_graph_expansion():
    """Verify in-collector direct expansion of KnowledgeGraph with HAS_ENDPOINT and HAS_VULNERABILITY edges."""
    mock_http = MockXMLHttpClient()
    mock_http.set_route(
        "file:///etc/passwd",
        200,
        "<root>root:x:0:0:root:/root:/bin/bash</root>",
    )

    collector = XMLParserSecurityCollector(http_client=mock_http)
    graph = KnowledgeGraph()
    mission = Mission(
        target="https://graph-app.local",
        endpoints=[{"url": "https://graph-app.local/api/xml", "method": "POST"}],
    )
    mission.attack_surface_graph = graph

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1

    # Check nodes
    nodes = list(graph.nodes.values())
    node_types = {n.type for n in nodes}
    assert "live_host" in node_types
    assert "endpoint" in node_types
    assert "vulnerability" in node_types

    # Check edges
    has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    has_ep_edges = [e for e in graph.edges if e.type == "HAS_ENDPOINT"]
    assert len(has_vuln_edges) >= 2  # from live_host and from endpoint
    assert len(has_ep_edges) >= 1


def test_collector_controlled_mission_publish():
    """Verify collector safely publishes findings through ControlledMission wrapper."""
    mock_http = MockXMLHttpClient()
    mock_http.set_route(
        "file:///etc/passwd",
        200,
        "<root>root:x:0:0:root:/root:/bin/bash</root>",
    )

    collector = XMLParserSecurityCollector(http_client=mock_http)
    mission = Mission(
        target="https://controlled-app.local",
        endpoints=[{"url": "https://controlled-app.local/api/xml", "method": "POST"}],
    )
    controlled = ControlledMission(mission)

    evidence_list = collector.collect(controlled)
    assert len(evidence_list) >= 1
    assert len(mission.evidence) >= 1
    assert len(mission.vulnerabilities) >= 1


# -----------------------------------------------------------------------------
# 5. Tool Registry & Plugin Adapter Tests
# -----------------------------------------------------------------------------

def test_tool_registry_lookup_and_aliases():
    """Verify tool registry lookup by ID and aliases."""
    tool_by_id = registry.get("xml_parser_validation")
    assert tool_by_id is not None
    assert tool_by_id.id == "xml_parser_validation"
    assert tool_by_id.priority == 95
    assert "xml_parser_security_validator" in tool_by_id.capabilities

    # Test aliases
    for alias in ["xxe", "xml_parser", "xml_external_entity", "xml_parser_validator", "xxe_collector"]:
        tool_alias = registry.get(alias)
        assert tool_alias is not None
        assert tool_alias.id == "xml_parser_validation"


def test_plugin_executor_adapter_fallback():
    """Verify PluginExecutorAdapter fallback instantiates XMLParserSecurityCollector."""
    adapter = PluginExecutorAdapter()
    for plugin_id in ["xml_parser_validation", "xxe", "xml_external_entity", "xml_security"]:
        instance = adapter._instantiate_specialist_fallback(plugin_id)
        assert instance is not None
        assert isinstance(instance, XMLParserSecurityCollector)
        assert hasattr(instance, "collect")
        assert hasattr(instance, "execute")


# -----------------------------------------------------------------------------
# 6. TaskGenerator DAG Wiring Tests
# -----------------------------------------------------------------------------

def test_task_generator_dag_wiring():
    """Verify XML parser task template in TaskGenerator has correct DAG dependencies and inputs."""
    assert "xml_parser_validation" in _RECON_TEMPLATES
    tmpl = _RECON_TEMPLATES["xml_parser_validation"]
    assert tmpl["dependencies"] == ["Discover API Endpoints"]
    assert tmpl["required_inputs"] == ["endpoints"]
    assert tmpl["category"] == TaskCategory.EVIDENCE_CORRELATION
    assert tmpl["metadata"]["tool_id"] == "xml_parser_validation"


def test_task_generator_gap_resolution():
    """Verify TaskGenerator resolves CoverageGaps for XML parser validation."""
    mission = Mission(target="https://target.local", endpoints=["https://target.local/api/xml"])
    tg = TaskGenerator(mission=mission)

    # 1. Explicit gap area
    gap1 = CoverageGap(area="xml parser validation", description="Audit XML parsing configurations", severity=0.85)
    tmpl1 = tg._resolve_template_for_gap(gap1)
    assert tmpl1["metadata"]["tool_id"] == "xml_parser_validation"

    gap2 = CoverageGap(area="xxe", description="XXE detection gap", severity=0.9)
    tmpl2 = tg._resolve_template_for_gap(gap2)
    assert tmpl2["metadata"]["tool_id"] == "xml_parser_validation"

    # 2. Category-based fallback
    gap3 = CoverageGap(area="unknown", category=TaskCategory.EVIDENCE_CORRELATION, description="Audit external entity resolution", severity=0.8)
    tmpl3 = tg._resolve_template_for_gap(gap3)
    assert tmpl3["metadata"]["tool_id"] == "xml_parser_validation"

    # 3. from_gaps() generation
    tasks = tg.from_gaps([gap1])
    assert len(tasks) == 1
    assert tasks[0].dependencies == ["Discover API Endpoints"]
    assert tasks[0].metadata["tool_id"] == "xml_parser_validation"


# -----------------------------------------------------------------------------
# 7. AttackSurfaceGraphBuilder & CVSS / CWE Mapping Tests
# -----------------------------------------------------------------------------

def test_attack_surface_graph_builder_reconstruction():
    """Verify AttackSurfaceGraphBuilder reconstructs vulnerability nodes and HAS_VULNERABILITY edges."""
    builder = AttackSurfaceGraphBuilder()
    store = EvidenceStore()

    ev = Evidence(
        title="XML Parser Misconfiguration: xml on https://app.local/api/xml",
        category="xml_parser_validation",
        severity="critical",
        confidence=0.95,
        metadata={
            "url": "https://app.local/api/xml",
            "host": "https://app.local",
            "parameter": "xml",
            "technique": "entity_resolution",
            "template_id": "xxe_passwd",
            "status_code": 200,
        },
    )
    store.add(ev)

    graph = builder.build_from_evidence(
        evidence=store,
        target="https://app.local",
        graph=KnowledgeGraph(),
    )

    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) >= 1
    assert any("xxe_passwd" in n.id for n in vuln_nodes)

    vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(vuln_edges) >= 2  # from live_host and from endpoint


def test_cvss_cwe_mapping():
    """Verify CVSSCalculator maps XXE and XML parser categories to CWE-611."""
    for cat in ["xxe", "xml_parser_validation", "xml_external_entity"]:
        cwe_info = CVSSCalculator.CWE_DATABASE.get(cat)
        assert cwe_info is not None
        assert cwe_info.id == "CWE-611"
        assert "XML External Entity" in cwe_info.name
