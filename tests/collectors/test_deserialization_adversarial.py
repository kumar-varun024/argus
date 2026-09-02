"""
Adversarial Stress Test Suite for Insecure Deserialization Validation Subsystem.

Empirically challenges DeserializationCollector, DeserializationPayloadGenerator,
and DeserializationAnalyzer against adversarial edge cases, malformed payloads,
echo servers, latency differentials, mixed-case encodings, nested JSON,
and attack surface graph idempotency.
"""
import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import pytest

from argus.collectors.deserialization import (
    DeserializationCollector,
    InsecureDeserializationCollector,
    DeserializationValidationCollector,
    DeserializationPayloadGenerator,
    DeserializationAnalyzer,
    DeserializationResult,
    DeserializationFormat,
    DeserializationTechnique,
    DeserializationMutationStrategy,
    Severity,
    JAVA_DESERIALIZATION_SIGNATURES,
    PYTHON_PICKLE_SIGNATURES,
    PHP_UNSERIALIZE_SIGNATURES,
    RUBY_MARSHAL_SIGNATURES,
    DOTNET_DESERIALIZATION_SIGNATURES,
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
    """Mock HTTP client simulating adversarial server behaviors and responses."""

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
                body=f"<html><body>Echo: {target_url}</body></html>",
                raw_body=f"<html><body>Echo: {target_url}</body></html>",
                url=target_url,
                elapsed=0.05,
            )
        elif self.behavior_mode == "empty":
            return HttpResponse(success=True, status_code=200, body="", raw_body="", url=target_url, elapsed=0.01)
        elif self.behavior_mode == "malformed":
            return HttpResponse(
                success=True,
                status_code=200,
                body="\x00\xff\xfe\xca\xfe\xba\xbe",
                raw_body="\x00\xff\xfe\xca\xfe\xba\xbe",
                url=target_url,
                elapsed=0.02,
            )
        elif self.behavior_mode == "server_error_500":
            return HttpResponse(
                success=False,
                status_code=500,
                body="500 Internal Server Error: General database connection failure.",
                raw_body="500 Internal Server Error: General database connection failure.",
                url=target_url,
                elapsed=0.05,
            )
        elif self.behavior_mode == "raise_exception":
            raise RuntimeError("Connection timed out to remote host")

        return HttpResponse(success=True, status_code=200, body="OK Benign", raw_body="OK Benign", url=target_url, elapsed=0.05)

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        data = kwargs.get("data")
        json_data = kwargs.get("json")
        headers = kwargs.get("headers") or {}
        cookies = kwargs.get("cookies") or {}
        self.recorded_requests.append({
            "method": "POST",
            "url": target_url,
            "data": data,
            "json": json_data,
            "headers": headers,
            "cookies": cookies,
        })

        if self.behavior_mode == "echo":
            payload_str = str(data or json_data or "")
            return HttpResponse(
                success=True,
                status_code=200,
                body=f"<html><body>Payload received: {payload_str}</body></html>",
                raw_body=f"<html><body>Payload received: {payload_str}</body></html>",
                url=target_url,
                elapsed=0.05,
            )
        elif self.behavior_mode == "raise_exception":
            raise ConnectionResetError("Connection reset by peer")

        return HttpResponse(success=True, status_code=200, body="OK Benign POST", raw_body="OK Benign POST", url=target_url, elapsed=0.05)


def test_adversarial_corrupted_magic_bytes():
    """Verify analyzer correctly ignores responses to corrupted streams if no valid exception is produced."""
    analyzer = DeserializationAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=200,
        body="Normal page content without errors",
        url="http://example.com/test",
    )
    result = analyzer.analyze_response(resp, {"payload": "\xac\xed\x00\x00corrupt", "format": "java"})
    assert result is None


def test_adversarial_high_baseline_latency_no_false_positive():
    """Verify that a slow baseline response does not cause false positives."""
    analyzer = DeserializationAnalyzer()
    baseline = HttpResponse(success=True, status_code=200, body="OK Slow Baseline", url="http://example.com/slow", elapsed=4.5)
    injected = HttpResponse(success=True, status_code=200, body="OK Slow Injected", url="http://example.com/slow", elapsed=4.8)
    result = analyzer.analyze_response(injected, {"payload": "rO0AB", "format": "java"}, baseline_response=baseline)
    assert result is None


def test_adversarial_mixed_case_headers_and_cookies():
    """Verify collector handles mixed-case headers and cookies without raising exceptions."""
    mock_client = AdversarialMockHttpClient(behavior_mode="normal")
    collector = DeserializationCollector(http_client=mock_client)
    mission = Mission(
        target="http://example.com",
        endpoints=[
            {
                "url": "http://example.com/api/test",
                "method": "GET",
                "headers": {"X-VIEWSTATE": "dummy", "AUTHORIZATION": "Bearer token"},
                "cookies": {"SESSION_ID": "abc123xyz"},
            }
        ],
    )
    evs = collector.collect(mission)
    assert isinstance(evs, list)
    assert len(mock_client.recorded_requests) > 0


def test_adversarial_nested_json_payloads():
    """Verify collector handles deep nested JSON structures gracefully."""
    mock_client = AdversarialMockHttpClient(behavior_mode="normal")
    collector = DeserializationCollector(http_client=mock_client)
    nested_body = {
        "user": {
            "profile": {
                "settings": {
                    "serialized_blob": "data_here",
                }
            }
        }
    }
    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/api/user/settings", "method": "POST", "body": nested_body}],
    )
    evs = collector.collect(mission)
    assert isinstance(evs, list)


def test_adversarial_multiple_endpoints_isolation():
    """Verify that multiple vulnerable endpoints across different formats are isolated and reported."""
    class MultiFormatMockClient:
        def get(self, *args, **kwargs):
            return HttpResponse(success=True, status_code=200, body="OK", url="http://example.com")

        def post(self, mission_or_url, url=None, **kwargs):
            target_url = url or mission_or_url
            data = kwargs.get("data")
            json_data = kwargs.get("json")
            if "java-app" in str(target_url) and "rO0AB" in str(data or json_data):
                return HttpResponse(
                    success=False,
                    status_code=500,
                    body="java.lang.ClassNotFoundException: org.argus.Probe",
                    url=str(target_url),
                )
            if "python-app" in str(target_url) and "gASV" in str(data or json_data):
                return HttpResponse(
                    success=False,
                    status_code=500,
                    body="_pickle.UnpicklingError: invalid load key, 'X'",
                    url=str(target_url),
                )
            return HttpResponse(success=True, status_code=200, body="OK", url=str(target_url))

    collector = DeserializationCollector(http_client=MultiFormatMockClient())
    mission = Mission(
        target="http://example.com",
        endpoints=[
            {"url": "http://example.com/java-app/upload", "method": "POST", "body": "test"},
            {"url": "http://example.com/python-app/session", "method": "POST", "body": {"token": "test"}},
        ],
    )
    evs = collector.collect(mission)
    assert len(evs) == 2
    formats = {ev.metadata["format"] for ev in evs}
    assert "java" in formats
    assert "python_pickle" in formats


def test_adversarial_graph_idempotency():
    """Verify that building the attack surface graph multiple times from the same evidence is idempotent."""
    builder = AttackSurfaceGraphBuilder()
    store = EvidenceStore()
    ev = Evidence(
        title="Insecure Deserialization (Python Pickle): token on http://example.com/api",
        category="deserialization",
        severity="critical",
        confidence=0.95,
        metadata={
            "url": "http://example.com/api",
            "host": "http://example.com",
            "parameter": "token",
            "format": "python_pickle",
            "template_id": "deserialization_pickle_base64",
        },
    )
    store.add(ev)

    graph = KnowledgeGraph()
    builder.build_from_evidence(evidence=store, target="http://example.com", graph=graph)
    node_count_1 = len(graph.nodes)
    edge_count_1 = len(graph.edges)

    # Re-run build on same graph
    builder.build_from_evidence(evidence=store, target="http://example.com", graph=graph)
    assert len(graph.nodes) == node_count_1
    assert len(graph.edges) == edge_count_1


def test_adversarial_custom_http_client_exceptions():
    """Verify collector handles exceptions thrown by the HTTP client without crashing."""
    mock_client = AdversarialMockHttpClient(behavior_mode="raise_exception")
    collector = DeserializationCollector(http_client=mock_client)
    mission = Mission(
        target="http://example.com",
        endpoints=[
            {"url": "http://example.com/get", "method": "GET"},
            {"url": "http://example.com/post", "method": "POST", "body": "test"},
        ],
    )
    evs = collector.collect(mission)
    assert evs == []


def test_adversarial_malformed_url_handling():
    """Verify collector handles strange and malformed URL formats safely."""
    collector = DeserializationCollector(http_client=AdversarialMockHttpClient())
    mission = Mission(
        target="http://example.com",
        endpoints=[
            {"url": "not_a_valid_url"},
            {"url": "ftp://unsupported.proto"},
            {"url": ""},
        ],
    )
    evs = collector.collect(mission)
    assert evs == []


def test_adversarial_binary_formatter_vs_viewstate_differentiation():
    """Verify analyzer correctly tags .NET binary formatter vs ViewState error signatures."""
    analyzer = DeserializationAnalyzer()

    resp_bf = HttpResponse(
        success=False,
        status_code=500,
        body="System.Runtime.Serialization.SerializationException: The input stream is not a valid binary format. The starting contents (in bytes) are: 7B-22...",
        url="http://example.com/remoting",
    )
    res_bf = analyzer.analyze_response(resp_bf, {"payload": "AAEAAAD...", "format": "dotnet_binary_formatter"})
    assert res_bf is not None
    assert res_bf.format == "dotnet_binary_formatter"

    resp_vs = HttpResponse(
        success=False,
        status_code=500,
        body="System.Web.UI.ViewStateException: Invalid viewstate",
        url="http://example.com/default.aspx",
    )
    res_vs = analyzer.analyze_response(resp_vs, {"payload": "/wEPDw...", "format": "dotnet_viewstate"})
    assert res_vs is not None
    assert res_vs.format == "dotnet_viewstate"


def test_adversarial_reflection_with_unrelated_500_error():
    """Verify that a 500 error containing payload echo + generic error is suppressed if it lacks deserialization stack trace."""
    analyzer = DeserializationAnalyzer()
    payload = "rO0ABXNyABpvcmcuYXJndXMuc2VjdXJpdHkuUHJvYmVPYmplY3QAAAAAAAAAAQIAAHhw"
    resp = HttpResponse(
        success=False,
        status_code=500,
        body=f"500 Internal Server Error: Failed executing query with param={payload}. Out of memory.",
        url="http://example.com/query",
    )
    res = analyzer.analyze_response(resp, {"payload": payload, "format": "java"})
    assert res is None


def test_adversarial_cvss_vector_roundtrip():
    """Verify CVSS calculator handles deserialization scoring, vectors, and metrics consistently."""
    calc = CVSSCalculator()
    data = calc.derive_cvss_for_vulnerability(category="deserialization", severity="critical")
    assert data.score == 9.8
    assert data.severity_rating == "Critical"
    assert data.metrics.get("AV") == "N"
    assert data.metrics.get("AC") == "L"
    assert data.metrics.get("PR") == "N"
    assert data.metrics.get("C") == "H"
    assert data.metrics.get("I") == "H"
    assert data.metrics.get("A") == "H"


def test_adversarial_plugin_executor_error_handling():
    """Verify PluginExecutorAdapter raises ValueError on unknown plugins and succeeds on deserialization."""
    adapter = PluginExecutorAdapter()
    specialist = adapter._instantiate_specialist_fallback("deserialization_validation_collector")
    assert specialist is not None
    assert isinstance(specialist, DeserializationCollector)

    with pytest.raises(ValueError):
        adapter.execute_plugin("completely_non_existent_plugin_xyz", Mission(target="http://example.com"))


def test_adversarial_task_generator_empty_assets():
    """Verify TaskGenerator handles gaps with empty vs populated related assets."""
    mission = Mission(target="http://example.com", endpoints=["http://example.com/api/test"])
    gen = TaskGenerator(mission)

    # Gap without related assets
    gap_no_assets = CoverageGap(category=TaskCategory.EVIDENCE_CORRELATION, area="deserialization", description="Check deser")
    tasks_1 = gen.from_gaps([gap_no_assets])
    assert len(tasks_1) == 1
    assert tasks_1[0].required_inputs == ["http://example.com/api/test"]

    # Gap with explicit related assets
    gap_with_assets = CoverageGap(
        category=TaskCategory.EVIDENCE_CORRELATION,
        area="deserialization",
        description="Check deser with explicit target",
        related_assets=["http://example.com/explicit/endpoint"],
    )
    tasks_2 = gen.from_gaps([gap_with_assets])
    assert len(tasks_2) == 1
    assert tasks_2[0].required_inputs == ["http://example.com/explicit/endpoint"]


def test_adversarial_evidence_metadata_validation():
    """Verify full schema validation of emitted Evidence and ProvenanceData."""
    mock_client = AdversarialMockHttpClient()
    mock_client.set_route = lambda *args: None
    collector = DeserializationCollector(http_client=mock_client)
    res = DeserializationResult(
        format="java",
        technique="object_input_stream",
        mutation_strategy="gzip_base64",
        severity="critical",
        confidence=0.95,
        payload="H4sIC...",
        matched_signature="java_class_not_found",
        evidence_snippet="ClassNotFoundException: test",
    )
    mission = Mission(id="test_mission_001", target="http://example.com")
    ev = collector._create_evidence_and_update_state(
        mission=mission,
        target_url="http://example.com/api/data",
        base_url="http://example.com",
        param="blob",
        param_type="post_body",
        payload="H4sIC...",
        status_code=500,
        result=res,
    )
    assert ev.mission_id == "test_mission_001"
    assert ev.category == "deserialization"
    assert ev.severity == "critical"
    assert ev.confidence == 0.95
    assert ev.provenance is not None
    assert ev.provenance.step_id == "deserialization_validation_collector"
    assert ev.metadata["cwe_id"] == "CWE-502"
    assert ev.metadata["cvss_score"] == 9.8
    assert ev.metadata["mutation_strategy"] == "gzip_base64"
