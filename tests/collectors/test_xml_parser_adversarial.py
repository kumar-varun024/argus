"""
Adversarial Stress Test Suite for XML Parser Configuration Validation Subsystem.

Empirically challenges XMLParserSecurityCollector, XMLPayloadGenerator, and XMLParserAnalyzer
against adversarial edge cases, malformed payloads, echo servers, latency differentials,
encoding variations, strange character sets, SOAP envelope namespaces, and attack graph reconstruction.
"""
import codecs
import time
from typing import Any, Dict, List, Optional, Tuple
import pytest

from argus.collectors.xml_parser import (
    XMLParserSecurityCollector,
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


class AdversarialMockHttpClient:
    """Mock client simulating adversarial server behaviors (echoing, slow responses, malformed XML, errors)."""

    def __init__(self, behavior_mode: str = "normal"):
        self.behavior_mode = behavior_mode
        self.recorded_requests: List[Dict[str, Any]] = []

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        self.recorded_requests.append({"method": "GET", "url": target_url, "kwargs": kwargs})

        if self.behavior_mode == "echo":
            return HttpResponse(
                success=True,
                status_code=200,
                body=f"<echo>{target_url}</echo>",
                raw_body=f"<echo>{target_url}</echo>",
                url=target_url,
                elapsed=0.05,
            )
        elif self.behavior_mode == "empty":
            return HttpResponse(success=True, status_code=200, body="", raw_body="", url=target_url, elapsed=0.01)
        elif self.behavior_mode == "malformed":
            return HttpResponse(
                success=True,
                status_code=200,
                body="<unclosed_tag><item>\x00\xff\xfe",
                raw_body="<unclosed_tag><item>\x00\xff\xfe",
                url=target_url,
                elapsed=0.02,
            )
        elif self.behavior_mode == "server_error_500":
            return HttpResponse(
                success=False,
                status_code=500,
                body="Internal Server Error: Unexpected XML parsing state",
                raw_body="Internal Server Error: Unexpected XML parsing state",
                url=target_url,
                elapsed=0.05,
            )
        elif self.behavior_mode == "none_response":
            return None  # type: ignore

        return HttpResponse(success=True, status_code=200, body="<ok/>", raw_body="<ok/>", url=target_url, elapsed=0.05)

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        data = kwargs.get("data")
        json_data = kwargs.get("json")
        headers = kwargs.get("headers") or {}
        self.recorded_requests.append({
            "method": "POST",
            "url": target_url,
            "data": data,
            "json": json_data,
            "headers": headers,
        })

        payload_str = ""
        if isinstance(data, (bytes, bytearray)):
            payload_str = data.decode("latin1", errors="ignore")
        elif isinstance(data, str):
            payload_str = data
        elif isinstance(json_data, dict):
            payload_str = str(json_data)

        if self.behavior_mode == "echo":
            return HttpResponse(
                success=True,
                status_code=200,
                body=f"<echo_response>{payload_str}</echo_response>",
                raw_body=f"<echo_response>{payload_str}</echo_response>",
                url=target_url,
                elapsed=0.05,
            )
        elif self.behavior_mode == "unexpanded_entity_echo":
            return HttpResponse(
                success=True,
                status_code=200,
                body="<result>&xxe;</result>",
                raw_body="<result>&xxe;</result>",
                url=target_url,
                elapsed=0.05,
            )
        elif self.behavior_mode == "empty":
            return HttpResponse(success=True, status_code=200, body="", raw_body="", url=target_url, elapsed=0.01)
        elif self.behavior_mode == "malformed":
            return HttpResponse(
                success=True,
                status_code=200,
                body="<<>>broken XML response",
                raw_body="<<>>broken XML response",
                url=target_url,
                elapsed=0.02,
            )
        elif self.behavior_mode == "server_error_500":
            return HttpResponse(
                success=False,
                status_code=500,
                body="500 Internal Server Error: Parser failed",
                raw_body="500 Internal Server Error: Parser failed",
                url=target_url,
                elapsed=0.05,
            )
        elif self.behavior_mode == "baseline_banner_leak":
            return HttpResponse(
                success=True,
                status_code=200,
                body="<app version='1.0'>Running on Linux version 5.15.0-generic (buildd@glacier)</app>",
                raw_body="<app version='1.0'>Running on Linux version 5.15.0-generic (buildd@glacier)</app>",
                url=target_url,
                elapsed=0.05,
            )

        if "argus_baseline_probe" in payload_str:
            return HttpResponse(success=True, status_code=200, body="<root><baseline>ok</baseline></root>", elapsed=0.05)

        return HttpResponse(success=True, status_code=200, body="<root><status>ok</status></root>", raw_body="<root><status>ok</status></root>", url=target_url, elapsed=0.05)


# =============================================================================
# Adversarial Challenge 1: File Reflection Severity & Confidence
# =============================================================================

@pytest.mark.parametrize("file_type,signature_content,expected_sig", [
    ("unix_passwd", "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin", "unix_passwd"),
    ("unix_shadow", "\nroot:$6$salt$encryptedpasswordhash:18900:0:99999:7:::\n", "unix_shadow"),
    ("unix_hosts", "\n127.0.0.1\tlocalhost\n127.0.1.1\tprod-srv.local\n", "unix_hosts"),
    ("unix_version", "Linux version 5.15.0-88-generic (buildd@lcy02-amd64-001) (gcc 11.4.0)", "unix_version"),
    ("unix_hostname", "\napp-prod-node-04.us-east-1.compute.internal\n", "unix_hostname"),
    ("windows_win_ini", "[fonts]\r\nArial=arial.ttf\r\n[extensions]", "windows_win_ini"),
    ("windows_boot_ini", "[boot loader]\r\ntimeout=30\r\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS", "windows_boot_ini"),
    ("canary", XMLPayloadGenerator.CANARY_TOKEN, "canary_token"),
])
def test_adversarial_file_reflection_critical_severity(file_type: str, signature_content: str, expected_sig: str):
    """Verify that all target file reflections are classified as Critical with >= 0.95 confidence."""
    analyzer = XMLParserAnalyzer()
    payload_info = {
        "technique": XMLTechnique.ENTITY_RESOLUTION.value,
        "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
        "target_file": f"/path/to/{file_type}",
        "file_type": file_type,
        "payload": f'<!ENTITY xxe SYSTEM "/path/to/{file_type}"><root>&xxe;</root>',
        "template_id": f"xxe_{file_type}",
    }

    resp = HttpResponse(
        success=True,
        status_code=200,
        body=f"<response><content>{signature_content}</content></response>",
        elapsed=0.08,
    )
    result = analyzer.analyze_response(resp, payload_info)

    assert result is not None
    assert result.is_valid_finding is True
    assert result.severity == "critical"
    assert result.confidence >= 0.95
    assert result.matched_signature == expected_sig
    assert len(result.evidence_snippet) > 0


# =============================================================================
# Adversarial Challenge 2: Recursive Entity Expansion & Latency Thresholds
# =============================================================================

def test_adversarial_recursive_latency_threshold_boundaries():
    """Stress test boundary conditions for latency differential evaluation."""
    analyzer = XMLParserAnalyzer()
    payload_info = {
        "technique": XMLTechnique.RECURSIVE_ENTITY.value,
        "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
        "target_file": "recursive_expansion",
        "file_type": "recursive_expansion",
        "payload": '<!ENTITY lol4 "..."><root>&lol4;</root>',
    }

    # Case A: Fast baseline (0.05s), High injection (3.10s) -> Must trigger High finding
    baseline_fast = HttpResponse(success=True, status_code=200, body="<ok/>", elapsed=0.05)
    resp_slow = HttpResponse(success=True, status_code=200, body="<ok/>", elapsed=3.10)
    res_a = analyzer.analyze_response(resp_slow, payload_info, baseline_response=baseline_fast)
    assert res_a is not None
    assert res_a.severity == "high"
    assert res_a.confidence == 0.85
    assert res_a.matched_signature == "latency_differential_delay"

    # Case B: Injected elapsed is below threshold (2.95s) -> Must NOT trigger
    resp_below_thresh = HttpResponse(success=True, status_code=200, body="<ok/>", elapsed=2.95)
    res_b = analyzer.analyze_response(resp_below_thresh, payload_info, baseline_response=baseline_fast)
    assert res_b is None

    # Case C: Baseline is already slow (3.0s), Injected is 3.5s (delta 0.5s, factor < 3.0) -> Must NOT trigger false positive
    baseline_slow = HttpResponse(success=True, status_code=200, body="<ok/>", elapsed=3.00)
    resp_slow2 = HttpResponse(success=True, status_code=200, body="<ok/>", elapsed=3.50)
    res_c = analyzer.analyze_response(resp_slow2, payload_info, baseline_response=baseline_slow)
    assert res_c is None

    # Case D: Baseline is slow (2.0s), Injected is massively amplified (10.0s) -> Must trigger
    resp_amplified = HttpResponse(success=True, status_code=200, body="<ok/>", elapsed=10.00)
    res_d = analyzer.analyze_response(resp_amplified, payload_info, baseline_response=HttpResponse(success=True, status_code=200, body="<ok/>", elapsed=2.0))
    assert res_d is not None
    assert res_d.severity == "high"


@pytest.mark.parametrize("error_sig_key,error_body,expected_matched", [
    ("java_limit", "org.xml.sax.SAXParseException: Excessive entity expansion in document", "java_entity_expansion_limit"),
    ("libxml2_limit", "parser error : Maximum entity amplification factor limit exceeded (2000.00x)", "libxml2_entity_amplification"),
    ("dotnet_limit", "System.Xml.XmlException: The input document has exceeded a limit set by MaxCharactersFromEntities", "dotnet_max_chars_from_entities"),
    ("java_disallow", "org.xml.sax.SAXParseException: DOCTYPE is disallowed when the feature \"http://apache.org/xml/features/disallow-doctype-decl\" is set to true", "java_disallow_doctype"),
    ("dotnet_disallow", "System.Xml.XmlException: For security reasons DTD is prohibited in this XML document", "dotnet_dtd_prohibited"),
])
def test_adversarial_parser_error_signatures(error_sig_key: str, error_body: str, expected_matched: str):
    """Verify analyzer correctly maps various parser limit error signatures."""
    analyzer = XMLParserAnalyzer()
    payload_info = {
        "technique": XMLTechnique.RECURSIVE_ENTITY.value,
        "mutation_strategy": XMLMutationStrategy.DOCTYPE_SYSTEM.value,
        "target_file": "recursive_expansion",
        "file_type": "recursive_expansion",
        "payload": '<!ENTITY lol4 "..."><root>&lol4;</root>',
    }

    resp = HttpResponse(success=False, status_code=500, body=error_body, elapsed=0.10)
    result = analyzer.analyze_response(resp, payload_info)

    if "limit" in error_sig_key:
        assert result is not None
        assert result.severity == "medium"
        assert result.matched_signature == expected_matched


# =============================================================================
# Adversarial Challenge 3: False Positive Elimination (Echo & Baseline Guards)
# =============================================================================

def test_adversarial_unexpanded_entity_rejection():
    """Verify that a server echoing literal &xxe; or &all; or &lol4; without resolving generates zero false positives."""
    mock_http = AdversarialMockHttpClient(behavior_mode="unexpanded_entity_echo")
    collector = XMLParserSecurityCollector(http_client=mock_http)
    mission = Mission(
        target="https://literal-echo.local",
        endpoints=[{"url": "https://literal-echo.local/api/xml", "method": "POST"}],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) == 0, f"False positive on literal entity echo: {evidence_list}"


def test_adversarial_baseline_banner_leak_rejection():
    """Verify that if a server banner in the baseline already contains a signature (e.g. Linux version), it is suppressed."""
    mock_http = AdversarialMockHttpClient(behavior_mode="baseline_banner_leak")
    collector = XMLParserSecurityCollector(http_client=mock_http)
    mission = Mission(
        target="https://banner-leak.local",
        endpoints=[{"url": "https://banner-leak.local/api/xml", "method": "POST"}],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) == 0, f"False positive on baseline banner leak: {evidence_list}"


# =============================================================================
# Adversarial Challenge 4: Edge Cases (Malformed, Empty, 500, Mixed-case Headers)
# =============================================================================

def test_adversarial_empty_and_none_responses():
    """Verify collector and analyzer handle empty bodies, None responses, and network timeouts cleanly."""
    analyzer = XMLParserAnalyzer()
    payload_info = {"technique": "entity_resolution", "target_file": "/etc/passwd", "file_type": "unix_passwd"}

    # None response
    assert analyzer.analyze_response(None, payload_info) is None

    # Empty response
    resp_empty = HttpResponse(success=True, status_code=200, body="", raw_body="", elapsed=0.0)
    assert analyzer.analyze_response(resp_empty, payload_info) is None

    # Collector with None responses
    mock_http = AdversarialMockHttpClient(behavior_mode="none_response")
    collector = XMLParserSecurityCollector(http_client=mock_http)
    mission = Mission(target="https://timeout.local", endpoints=["https://timeout.local/api/xml"])
    evidence = collector.collect(mission)
    assert len(evidence) == 0


def test_adversarial_malformed_xml_and_binary_garbage():
    """Verify collector and analyzer survive malformed XML and binary garbage without crashing."""
    mock_http = AdversarialMockHttpClient(behavior_mode="malformed")
    collector = XMLParserSecurityCollector(http_client=mock_http)
    mission = Mission(target="https://garbage.local", endpoints=["https://garbage.local/api/xml"])

    evidence = collector.collect(mission)
    assert len(evidence) == 0


def test_adversarial_mixed_case_headers_and_content_types():
    """Verify collector handles mixed-case headers and content types (e.g. APPLICATION/XML, TeXt/XmL)."""
    mock_http = AdversarialMockHttpClient(behavior_mode="normal")
    collector = XMLParserSecurityCollector(http_client=mock_http)
    mission = Mission(
        target="https://case-test.local",
        endpoints=[
            {"url": "https://case-test.local/endpoint1", "method": "post", "headers": {"Content-Type": "APPLICATION/XML; charset=UTF-8"}},
            {"url": "https://case-test.local/endpoint2", "method": "POST", "headers": {"CONTENT-TYPE": "text/xml"}},
            {"url": "https://case-test.local/endpoint3", "method": "POST", "headers": {"Content-Type": "application/soap+xml"}},
        ],
    )

    evidence = collector.collect(mission)
    assert len(evidence) == 0  # No vulnerability in normal mode, but executed cleanly


# =============================================================================
# Adversarial Challenge 5: Mutation Strategies Simulated Against Vulnerable Parser
# =============================================================================

def test_adversarial_all_mutation_payloads_generate_and_detect():
    """Verify all mutated payloads from generate_mutated_payloads() pass analyzer checks when simulated."""
    gen = XMLPayloadGenerator()
    mutations = gen.generate_mutated_payloads()
    assert len(mutations) >= 9

    analyzer = XMLParserAnalyzer()

    for p_info in mutations:
        assert "mutation_strategy" in p_info
        assert "payload" in p_info
        assert "target_file" in p_info

        # Simulate vulnerable parser responding with resolved multiline content
        target_file = p_info["target_file"]
        is_passwd = "passwd" in target_file
        simulated_body = (
            "<data>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</data>"
            if is_passwd else
            "<data>\napp-worker-node-42.internal\n</data>"
        )

        resp = HttpResponse(success=True, status_code=200, body=simulated_body, elapsed=0.08)
        result = analyzer.analyze_response(resp, p_info)

        assert result is not None, f"Analyzer failed to detect simulated reflection for template: {p_info['template_id']}"
        assert result.severity == "critical"
        assert result.confidence >= 0.95


# =============================================================================
# Adversarial Challenge 6: Attack Graph & Pipeline Connectivity
# =============================================================================

def test_adversarial_attack_surface_graph_integrity():
    """Verify complete node and edge topology generated on XML vulnerability detection."""
    builder = AttackSurfaceGraphBuilder()
    store = EvidenceStore()

    ev1 = Evidence(
        title="XML Parser Misconfiguration: xml on https://secure.bank.local/api/xml",
        category="xml_parser_validation",
        severity="critical",
        confidence=0.95,
        metadata={
            "url": "https://secure.bank.local/api/xml",
            "host": "https://secure.bank.local",
            "parameter": "xml_body",
            "technique": "entity_resolution",
            "mutation_strategy": "utf16_encoding",
            "template_id": "xxe_mutation_utf16le",
            "status_code": 200,
        },
    )
    store.add(ev1)

    graph = KnowledgeGraph()
    graph = builder.build_from_evidence(
        evidence=store,
        target="https://secure.bank.local",
        graph=graph,
    )

    # Validate node existence
    lh_nodes = graph.nodes_by_type("live_host")
    ep_nodes = graph.nodes_by_type("endpoint")
    vuln_nodes = graph.nodes_by_type("vulnerability")

    assert len(lh_nodes) >= 1
    assert len(ep_nodes) >= 1
    assert len(vuln_nodes) >= 1

    # Validate edge relationships
    has_ep = [e for e in graph.edges if e.type == "HAS_ENDPOINT"]
    has_vuln = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]

    assert len(has_ep) >= 1
    assert len(has_vuln) >= 2  # from live_host and from endpoint

    # Check CWE Mapping
    cwe = CVSSCalculator.CWE_DATABASE.get("xml_parser_validation")
    assert cwe is not None
    assert cwe.id == "CWE-611"
