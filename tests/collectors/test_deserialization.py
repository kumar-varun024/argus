"""
Comprehensive Unit and Integration Tests for DeserializationCollector, DeserializationPayloadGenerator,
DeserializationAnalyzer, AttackSurfaceGraph integration, TaskGenerator DAG wiring, and ToolRegistry.
"""
from typing import Any, Dict, List, Optional, Tuple
import pytest
import urllib.parse

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


class MockDeserializationHttpClient:
    """Mock HTTP client for Deserialization tests supporting customizable routes and response payloads."""

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

        headers = kwargs.get("headers") or {}
        cookies = kwargs.get("cookies") or {}
        params = kwargs.get("params") or {}

        # 1. Match custom headers
        for hk, hv in headers.items():
            for rk, (sc, b, el) in self.routes.items():
                if rk.startswith("header:") and rk.split(":", 2)[1].lower() == hk.lower() and rk.split(":", 2)[2] in str(hv):
                    return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        # 2. Match cookies
        for ck, cv in cookies.items():
            for rk, (sc, b, el) in self.routes.items():
                if rk.startswith("cookie:") and rk.split(":", 2)[1].lower() == ck.lower() and rk.split(":", 2)[2] in str(cv):
                    return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        # 3. Match params
        for pk, pv in params.items():
            for rk, (sc, b, el) in self.routes.items():
                if rk in str(pv) or rk in str(pk):
                    return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        # 4. Check exact & substring url matches
        unquoted = urllib.parse.unquote_plus(target_url)
        for rk, (sc, b, el) in self.routes.items():
            if rk in target_url or rk in unquoted:
                return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        return HttpResponse(success=True, status_code=200, raw_body="OK Clean Response", body="OK Clean Response", url=target_url, elapsed=0.05)

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        data = kwargs.get("data")
        json_data = kwargs.get("json")
        headers = kwargs.get("headers") or {}
        cookies = kwargs.get("cookies") or {}
        self.requested_posts.append({"url": target_url, "data": data, "json": json_data, "headers": headers, "cookies": cookies})

        payload_str = ""
        if isinstance(data, (bytes, bytearray)):
            payload_str = data.decode("latin1", errors="ignore")
        elif isinstance(data, str):
            payload_str = data
        elif isinstance(json_data, dict):
            payload_str = json.dumps(json_data)

        # Match routes in payload
        for rk, (sc, b, el) in self.routes.items():
            if rk in payload_str:
                return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        # Header / Cookie matching in POST
        for hk, hv in headers.items():
            for rk, (sc, b, el) in self.routes.items():
                if rk.startswith("header:") and rk.split(":", 2)[1].lower() == hk.lower() and rk.split(":", 2)[2] in str(hv):
                    return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        for ck, cv in cookies.items():
            for rk, (sc, b, el) in self.routes.items():
                if rk.startswith("cookie:") and rk.split(":", 2)[1].lower() == ck.lower() and rk.split(":", 2)[2] in str(cv):
                    return HttpResponse(success=(200 <= sc < 300), status_code=sc, raw_body=b, body=b, url=target_url, elapsed=el)

        return HttpResponse(success=True, status_code=200, raw_body="OK Clean POST Response", body="OK Clean POST Response", url=target_url, elapsed=0.05)


# -----------------------------------------------------------------------------
# 1. Enums and Data Models Tests
# -----------------------------------------------------------------------------

def test_deserialization_enums_and_data_models():
    """Verify all enums and data model defaults."""
    assert DeserializationFormat.JAVA == "java"
    assert DeserializationFormat.PYTHON_PICKLE == "python_pickle"
    assert DeserializationFormat.PHP_SERIALIZE == "php_serialize"
    assert DeserializationFormat.RUBY_MARSHAL == "ruby_marshal"
    assert DeserializationFormat.DOTNET_VIEWSTATE == "dotnet_viewstate"
    assert DeserializationFormat.DOTNET_BINARY_FORMATTER == "dotnet_binary_formatter"

    assert DeserializationTechnique.OBJECT_INPUT_STREAM == "object_input_stream"
    assert DeserializationTechnique.PICKLE_LOADS == "pickle_loads"
    assert DeserializationTechnique.PHP_UNSERIALIZE == "php_unserialize"
    assert DeserializationTechnique.RUBY_MARSHAL_LOAD == "ruby_marshal_load"

    assert DeserializationMutationStrategy.BASE64 == "base64"
    assert DeserializationMutationStrategy.DOUBLE_BASE64 == "double_base64"
    assert DeserializationMutationStrategy.GZIP_BASE64 == "gzip_base64"
    assert DeserializationMutationStrategy.HEX == "hex"
    assert DeserializationMutationStrategy.URL_ENCODE == "url_encode"
    assert DeserializationMutationStrategy.CONTENT_TYPE_MANIPULATION == "content_type_manipulation"

    res = DeserializationResult(
        format="java",
        technique="object_input_stream",
        mutation_strategy="base64",
        severity="critical",
        confidence=0.95,
        payload="rO0AB...",
        matched_signature="java_class_not_found",
        evidence_snippet="ClassNotFoundException: org.example.Vuln",
    )
    assert res.is_valid_finding is True
    assert res.severity == "critical"


# -----------------------------------------------------------------------------
# 2. Signature Catalog Verification
# -----------------------------------------------------------------------------

def test_java_deserialization_error_signatures():
    """Verify Java deserialization error signatures match expected stack traces."""
    patterns = JAVA_DESERIALIZATION_SIGNATURES
    assert patterns["class_not_found"].search("java.lang.ClassNotFoundException: org.apache.commons.collections.Transformer")
    assert patterns["invalid_class"].search("java.io.InvalidClassException: filter status: REJECTED")
    assert patterns["stream_corrupted"].search("java.io.StreamCorruptedException: invalid stream header: 7372001A")
    assert patterns["optional_data"].search("java.io.OptionalDataException: EOF reached")
    assert patterns["object_stream"].search("java.io.ObjectStreamException: deserialization failure")
    assert patterns["object_input_stream_trace"].search("at java.io.ObjectInputStream.readObject(ObjectInputStream.java:372)")
    assert patterns["serializable_resolution"].search("cannot deserialize instance of java.util.HashMap")


def test_python_pickle_error_signatures():
    """Verify Python pickle error signatures match expected exceptions."""
    patterns = PYTHON_PICKLE_SIGNATURES
    assert patterns["unpickling_error"].search("_pickle.UnpicklingError: pickle data was truncated")
    assert patterns["invalid_load_key"].search("UnpicklingError: invalid load key, 'X'")
    assert patterns["pickle_data_truncated"].search("pickle data was truncated")
    assert patterns["pickle_type_error"].search("TypeError: a bytes-like object is required, not 'str'")
    assert patterns["pickle_loads_trace"].search("in _pickle.loads(payload)")
    assert patterns["stack_global_error"].search("STACK_GLOBAL requires str")


def test_php_unserialize_error_signatures():
    """Verify PHP unserialize error signatures match expected warnings and errors."""
    patterns = PHP_UNSERIALIZE_SIGNATURES
    assert patterns["unserialize_offset_error"].search("unserialize(): Error at offset 42 of 120 bytes")
    assert patterns["unserialize_node_error"].search("unserialize(): Node no longer exists")
    assert patterns["php_notice_unserialize"].search("PHP Notice: unserialize(): Error at offset 0")
    assert patterns["php_warning_unserialize"].search("PHP Warning: unserialize(): End of data reached")
    assert patterns["php_error_unserialize"].search("PHP Fatal error: unserialize(): Class 'Unknown' not found")
    assert patterns["unserialize_end_data"].search("unserialize(): Unexpected end of serialized data")


def test_ruby_marshal_error_signatures():
    """Verify Ruby Marshal error signatures match expected exceptions."""
    patterns = RUBY_MARSHAL_SIGNATURES
    assert patterns["incompatible_marshal_format"].search("TypeError: incompatible marshal file format (can't be read)\n\tformat version 4.8 required; 7.4 given")
    assert patterns["marshal_data_too_short"].search("ArgumentError: marshal data too short")
    assert patterns["dump_format_error"].search("TypeError: dump format error (0x2e)")
    assert patterns["undefined_class_module"].search("ArgumentError: undefined class/module NonExistentClass")
    assert patterns["marshal_load_trace"].search("in `load': dump format error (Marshal.load)")


def test_dotnet_deserialization_error_signatures():
    """Verify .NET ViewState and BinaryFormatter signatures match expected exceptions."""
    patterns = DOTNET_DESERIALIZATION_SIGNATURES
    assert patterns["serialization_exception"].search("System.Runtime.Serialization.SerializationException: End of Stream encountered")
    assert patterns["binary_format_error"].search("The input stream is not a valid binary format. The starting contents (in bytes) are: 7B-22-64-61...")
    assert patterns["viewstate_exception"].search("System.Web.UI.ViewStateException: Invalid viewstate")
    assert patterns["invalid_viewstate"].search("The client resolved a viewstate that is invalid")
    assert patterns["json_typename_exception"].search("Newtonsoft.Json.JsonSerializationException: Type specified in $type 'System.Diagnostics.Process' was not resolved")
    assert patterns["binary_formatter_trace"].search("at System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize(Stream serializationStream)")


# -----------------------------------------------------------------------------
# 3. Marker Detection Tests
# -----------------------------------------------------------------------------

def test_detect_serialized_markers_all_formats():
    """Verify detect_serialized_markers detects signatures for all 5 formats."""
    analyzer = DeserializationAnalyzer()

    # Java
    java_markers = analyzer.detect_serialized_markers("rO0ABXNyABpvcmcu")
    assert any(m[0] == DeserializationFormat.JAVA.value for m in java_markers)
    java_hex_markers = analyzer.detect_serialized_markers("aced00057372001a")
    assert any(m[0] == DeserializationFormat.JAVA.value for m in java_hex_markers)

    # Python Pickle
    pickle_markers = analyzer.detect_serialized_markers("gASVHgAAAAAAAACM")
    assert any(m[0] == DeserializationFormat.PYTHON_PICKLE.value for m in pickle_markers)

    # PHP
    php_markers = analyzer.detect_serialized_markers('O:4:"User":1:{s:4:"name";s:5:"admin";}')
    assert any(m[0] == DeserializationFormat.PHP_SERIALIZE.value for m in php_markers)

    # Ruby Marshal
    ruby_markers = analyzer.detect_serialized_markers("BAhvOh9Bcmd1cz")
    assert any(m[0] == DeserializationFormat.RUBY_MARSHAL.value for m in ruby_markers)

    # .NET ViewState / BinaryFormatter
    dotnet_markers = analyzer.detect_serialized_markers("/wEPDwULLTEyMz")
    assert any(m[0] == DeserializationFormat.DOTNET_VIEWSTATE.value for m in dotnet_markers)
    bf_markers = analyzer.detect_serialized_markers("AAEAAAD/////AQAAAAAAAAAM")
    assert any(m[0] == DeserializationFormat.DOTNET_VIEWSTATE.value for m in bf_markers)


# -----------------------------------------------------------------------------
# 4. Mutation Strategy Tests
# -----------------------------------------------------------------------------

def test_mutation_strategy_base64_and_double_base64():
    """Verify Base64 and Double Base64 mutation generation."""
    gen = DeserializationPayloadGenerator()
    b64_s, b64_d = gen.mutate_base64(b"test_payload_stream")
    assert b64_s == "dGVzdF9wYXlsb2FkX3N0cmVhbQ=="
    assert b64_d != b64_s


def test_mutation_strategy_gzip_compression():
    """Verify Gzip compression + Base64 wrapper mutation generation."""
    gen = DeserializationPayloadGenerator()
    gzip_b64 = gen.mutate_gzip(b"test_payload_stream")
    assert isinstance(gzip_b64, str)
    # Validate gzip magic header in decoded bytes
    import base64
    gz_bytes = base64.b64decode(gzip_b64)
    assert gz_bytes[:2] == b"\x1f\x8b"


def test_mutation_strategy_hex_encoding():
    """Verify raw and escaped hex mutation generation."""
    gen = DeserializationPayloadGenerator()
    hex_raw, hex_esc = gen.mutate_hex(b"\xac\xed\x00\x05")
    assert hex_raw == "aced0005"
    assert hex_esc == "\\xac\\xed\\x00\\x05"


def test_mutation_strategy_url_and_double_url_encoding():
    """Verify URL and Double URL encoding mutations."""
    gen = DeserializationPayloadGenerator()
    url_s, url_d = gen.mutate_url_encoding("rO0AB+==")
    assert "%2B" in url_s or "+" in url_s or "%3D" in url_s
    assert "%25" in url_d


def test_mutation_strategy_content_type_manipulation():
    """Verify Content-Type header manipulation mutations."""
    gen = DeserializationPayloadGenerator()
    payloads = gen.generate_mutated_payloads(strategy=DeserializationMutationStrategy.CONTENT_TYPE_MANIPULATION)
    content_types = {p.get("content_type") for p in payloads if "content_type" in p}
    assert "application/x-java-serialized-object" in content_types
    assert "application/x-python-pickle" in content_types
    assert "application/x-php-serialized" in content_types
    assert "application/x-ruby-marshal" in content_types
    assert "application/octet-stream" in content_types


def test_generate_mutated_payloads_deduplicated():
    """Verify generator yields >= 5 distinct mutation strategies across formats."""
    gen = DeserializationPayloadGenerator()
    payloads = gen.generate_mutated_payloads()
    assert len(payloads) >= 15
    strategies = {p["mutation_strategy"] for p in payloads}
    assert len(strategies) >= 5
    formats = {p["format"] for p in payloads}
    assert len(formats) >= 5


# -----------------------------------------------------------------------------
# 5. Collector Detection Tests across Channels & Formats
# -----------------------------------------------------------------------------

def test_collector_java_deserialization_post_body():
    """Verify detection of Java deserialization via POST body."""
    mock_client = MockDeserializationHttpClient()
    mock_client.set_route(
        "rO0AB",
        500,
        "java.lang.ClassNotFoundException: org.apache.commons.collections.functors.InvokerTransformer\n\tat java.io.ObjectInputStream.readClassDesc(ObjectInputStream.java:1820)",
        0.05,
    )
    collector = DeserializationCollector(http_client=mock_client)
    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/api/import", "method": "POST", "body": "test"}],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "deserialization"
    assert ev.severity == "critical"
    assert ev.status == "CONFIRMED"
    assert ev.confidence >= 0.90
    assert ev.metadata["format"] == "java"
    assert "ClassNotFoundException" in ev.metadata["evidence_snippet"]
    assert ev.metadata["cwe_id"] == "CWE-502"
    assert ev.metadata["cvss_score"] == 9.8


def test_collector_python_pickle_post_json():
    """Verify detection of Python pickle deserialization via POST JSON."""
    mock_client = MockDeserializationHttpClient()
    mock_client.set_route(
        "gASV",
        500,
        "Traceback (most recent call last):\n  File \"app.py\", line 45, in load_data\n    data = _pickle.loads(payload)\n_pickle.UnpicklingError: invalid load key, 'X'",
        0.05,
    )
    collector = DeserializationCollector(http_client=mock_client)
    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/api/v1/session", "method": "POST", "body": {"token": "sample"}}],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "deserialization"
    assert ev.severity == "critical"
    assert ev.metadata["format"] == "python_pickle"
    assert "UnpicklingError" in ev.metadata["evidence_snippet"]


def test_collector_php_unserialize_get_query():
    """Verify detection of PHP unserialize via GET query parameters."""
    mock_client = MockDeserializationHttpClient()
    mock_client.set_route(
        "Argus_Probe_NonExistent",
        200,
        "PHP Notice: unserialize(): Error at offset 42 of 64 bytes in /var/www/html/auth.php on line 12",
        0.05,
    )
    collector = DeserializationCollector(http_client=mock_client)
    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/profile?data=test", "method": "GET", "params": {"data": "test"}}],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "deserialization"
    assert ev.metadata["format"] == "php_serialize"
    assert "unserialize(): Error at offset" in ev.metadata["evidence_snippet"]


def test_collector_ruby_marshal_cookie():
    """Verify detection of Ruby Marshal via Cookie."""
    mock_client = MockDeserializationHttpClient()
    mock_client.set_route(
        "cookie:session:BAhv",
        500,
        "TypeError: incompatible marshal file format (can't be read)\n\tformat version 4.8 required; 7.4 given\n\tfrom /usr/lib/ruby/2.7.0/marshal.rb:34:in `load'",
        0.05,
    )
    collector = DeserializationCollector(http_client=mock_client)
    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/dashboard", "method": "GET", "cookies": {"session": "test_cookie"}}],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "deserialization"
    assert ev.metadata["format"] == "ruby_marshal"
    assert "incompatible marshal file format" in ev.metadata["evidence_snippet"]


def test_collector_dotnet_viewstate_header():
    """Verify detection of .NET ViewState / BinaryFormatter via Custom Header."""
    mock_client = MockDeserializationHttpClient()
    mock_client.set_route(
        "header:X-ViewState:/wEPDw",
        500,
        "System.Web.UI.ViewStateException: Invalid viewstate.\n   at System.Web.UI.Page.DecryptString(String s)",
        0.05,
    )
    collector = DeserializationCollector(http_client=mock_client)
    mission = Mission(
        target="http://example.com",
        endpoints=[{"url": "http://example.com/app/default.aspx", "method": "POST", "body": ""}],
    )

    evidence_list = collector.collect(mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "deserialization"
    assert ev.metadata["format"] == "dotnet_viewstate"
    assert "ViewStateException" in ev.metadata["evidence_snippet"]


# -----------------------------------------------------------------------------
# 6. False Positive Suppression & Baseline Subtraction Tests
# -----------------------------------------------------------------------------

def test_fp_suppression_verbatim_search_reflection():
    """Verify that echoing the payload verbatim on a search page does NOT produce findings."""
    analyzer = DeserializationAnalyzer()
    payload = "rO0ABXNyABpvcmcuYXJndXMuc2VjdXJpdHkuUHJvYmVPYmplY3QAAAAAAAAAAQIAAHhw"
    # Search page returns the query string verbatim in HTML
    resp = HttpResponse(
        success=True,
        status_code=200,
        body=f"<html><body><h2>Search Results for: {payload}</h2><p>No results found.</p></body></html>",
        url="http://example.com/search",
    )
    res = analyzer.analyze_response(resp, {"payload": payload, "format": "java"})
    assert res is None


def test_fp_suppression_normal_base64_data():
    """Verify that responses with normal Base64 data (images/tokens) without deserialization traces return None."""
    analyzer = DeserializationAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=200,
        body='{"image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="}',
        url="http://example.com/api/avatar",
    )
    res = analyzer.analyze_response(resp, {"payload": "rO0AB", "format": "java"})
    assert res is None


def test_fp_suppression_benign_404_500_errors():
    """Verify generic 404/500 errors without deserialization signatures return None."""
    analyzer = DeserializationAnalyzer()
    resp = HttpResponse(
        success=False,
        status_code=500,
        body="<html><body><h1>500 Internal Server Error</h1><p>Database connection timed out.</p></body></html>",
        url="http://example.com/api/data",
    )
    res = analyzer.analyze_response(resp, {"payload": "rO0AB", "format": "java"})
    assert res is None


def test_analyzer_baseline_subtraction():
    """Verify that if an error signature is already present in baseline, finding is suppressed."""
    analyzer = DeserializationAnalyzer()
    baseline_resp = HttpResponse(
        success=False,
        status_code=500,
        body="java.lang.ClassNotFoundException: com.legacy.OldService (System Startup Failure)",
        url="http://example.com/api/test",
    )
    injected_resp = HttpResponse(
        success=False,
        status_code=500,
        body="java.lang.ClassNotFoundException: com.legacy.OldService (System Startup Failure)",
        url="http://example.com/api/test",
    )
    res = analyzer.analyze_response(injected_resp, {"payload": "rO0AB", "format": "java"}, baseline_response=baseline_resp)
    assert res is None


# -----------------------------------------------------------------------------
# 7. Mission, ControlledMission & Aliases Tests
# -----------------------------------------------------------------------------

def test_collector_empty_mission_graceful_handling():
    """Verify collector gracefully handles empty missions."""
    collector = DeserializationCollector(http_client=MockDeserializationHttpClient())
    mission = Mission(target="", endpoints=[], live_hosts=[])
    res = collector.collect(mission)
    assert res == []


def test_collector_controlled_mission_compatibility():
    """Verify collector publishes findings when invoked through ControlledMission wrapper."""
    mock_client = MockDeserializationHttpClient()
    mock_client.set_route("rO0AB", 500, "java.lang.ClassNotFoundException: org.argus.Test", 0.05)
    collector = DeserializationCollector(http_client=mock_client)

    raw_mission = Mission(target="http://example.com", endpoints=[{"url": "http://example.com/rpc", "method": "POST", "body": "test"}])
    controlled = ControlledMission(raw_mission)

    res = collector.collect(controlled)
    assert len(res) >= 1
    assert len(raw_mission.evidence) >= 1
    assert len(raw_mission.vulnerabilities) >= 1


def test_collector_aliases():
    """Verify backwards-compatibility aliases instantiate correctly."""
    assert issubclass(InsecureDeserializationCollector, DeserializationCollector)
    assert issubclass(DeserializationValidationCollector, DeserializationCollector)
    c1 = InsecureDeserializationCollector()
    c2 = DeserializationValidationCollector()
    assert hasattr(c1, "collect")
    assert hasattr(c2, "collect")


# -----------------------------------------------------------------------------
# 8. Registry, DAG, Graph and CVSS Integration Tests
# -----------------------------------------------------------------------------

def test_tool_registry_registration_and_aliases():
    """Verify ToolRegistry has deserialization tool registered with all required aliases."""
    tool = registry.get("deserialization")
    assert tool is not None
    assert tool.id == "deserialization"
    assert tool.capability == "deserialization_detector"
    assert "Insecure Deserialization Detection" in tool.supported_tasks
    assert "endpoints" in tool.required_inputs

    # Check aliases
    assert registry.get("insecure_deserialization") is not None
    assert registry.get("pickle") is not None
    assert registry.get("unserialize") is not None
    assert registry.get("java_deserialization") is not None
    assert registry.get("viewstate") is not None


def test_plugin_executor_adapter_instantiation():
    """Verify PluginExecutorAdapter dynamically instantiates fallback deserialization collector."""
    adapter = PluginExecutorAdapter()
    specialist = adapter._instantiate_specialist_fallback("deserialization")
    assert specialist is not None
    assert isinstance(specialist, DeserializationCollector)
    assert hasattr(specialist, "collect")
    assert hasattr(specialist, "execute")


def test_task_generator_dag_wiring():
    """Verify TaskGenerator recon template for deserialization is configured in DAG."""
    assert "deserialization" in _RECON_TEMPLATES
    tmpl = _RECON_TEMPLATES["deserialization"]
    assert tmpl["title"] == "Validate Insecure Deserialization"
    assert tmpl["category"] == TaskCategory.EVIDENCE_CORRELATION
    assert tmpl["dependencies"] == ["Discover API Endpoints"]
    assert tmpl["required_inputs"] == ["endpoints"]
    assert tmpl["metadata"]["tool_id"] == "deserialization"


def test_task_generator_gap_resolution():
    """Verify TaskGenerator maps deserialization coverage gaps to the deserialization template."""
    mission = Mission(target="http://example.com", endpoints=["http://example.com/api/v1"])
    generator = TaskGenerator(mission)

    gaps = [
        CoverageGap(category=TaskCategory.EVIDENCE_CORRELATION, area="insecure deserialization", description="Unsafe deserialization risk"),
        CoverageGap(category=TaskCategory.EVIDENCE_CORRELATION, area="python pickle", description="Pickle loads check"),
        CoverageGap(category=TaskCategory.EVIDENCE_CORRELATION, area="php unserialize", description="PHP unserialize fuzzing"),
        CoverageGap(category=TaskCategory.EVIDENCE_CORRELATION, area="viewstate", description="ASP.NET ViewState inspection"),
    ]
    tasks = generator.from_gaps(gaps)
    assert len(tasks) >= 1
    assert any(t.metadata.get("tool_id") == "deserialization" for t in tasks)


def test_attack_surface_graph_builder_deserialization():
    """Verify AttackSurfaceGraphBuilder Section 17 constructs nodes and HAS_VULNERABILITY edges."""
    builder = AttackSurfaceGraphBuilder()
    store = EvidenceStore()
    ev = Evidence(
        title="Insecure Deserialization (Java ObjectInputStream): body on http://example.com/api/import",
        category="deserialization",
        severity="critical",
        confidence=0.95,
        metadata={
            "url": "http://example.com/api/import",
            "host": "http://example.com",
            "parameter": "body",
            "format": "java",
            "technique": "object_input_stream",
            "template_id": "deserialization_java_base64",
            "status_code": 500,
        },
    )
    store.add(ev)

    graph = builder.build_from_evidence(evidence=store, target="http://example.com", graph=KnowledgeGraph())
    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) >= 1
    assert "Insecure Deserialization" in vuln_nodes[0].value

    has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(has_vuln_edges) >= 2  # live_host -> vuln, endpoint -> vuln


def test_cvss_cwe_metadata_mapping():
    """Verify CWE-502 and CVSS 9.8 calculation for deserialization vulnerabilities."""
    calc = CVSSCalculator()
    cwe = calc.get_cwe_info("deserialization")
    assert cwe.id == "CWE-502"
    assert "Deserialization of Untrusted Data" in cwe.name

    cwe_java = calc.get_cwe_info("java_deserialization")
    assert cwe_java.id == "CWE-502"

    cwe_pickle = calc.get_cwe_info("python_pickle")
    assert cwe_pickle.id == "CWE-502"

    cvss_data = calc.derive_cvss_for_vulnerability(category="deserialization", severity="critical")
    assert cvss_data.score == 9.8
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in cvss_data.vector
