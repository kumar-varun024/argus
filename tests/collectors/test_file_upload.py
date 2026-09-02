"""
Unit and Integration Test Suite for File Upload Vulnerability Detection Module.

Covers:
- Models, Enums, Aliases, and Result structures
- FileUploadPayloadGenerator (unrestricted, MIME bypass, double ext, polyglots, path traversal, evasion mutations, benign baselines, apply_mutation)
- FileUploadProber (multipart dispatch, storage extraction, web shell verification)
- FileUploadAnalyzer (path disclosure, error disclosure, false positive rejection, severity/CWE/CVSS calibration)
- FileUploadCollector lifecycle and Quadruple State Publishing
- ToolRegistry and alias resolution
- PluginExecutorAdapter fallback instantiation
- TaskGenerator DAG task generation and gap resolution
- AttackSurfaceGraphBuilder Section 26 graph expansion
- CVSS and CWE database mappings
- ControlledMission wrapper compatibility
"""
import copy
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import pytest

from argus.collectors.file_upload import (
    FileUploadCollector,
    UploadVulnerabilityCollector,
    FileUploadSecurityCollector,
    UnrestrictedFileUploadCollector,
    ArbitraryFileUploadCollector,
    FileUploadPayloadGenerator,
    FileUploadProber,
    FileUploadAnalyzer,
    FileUploadProbe,
    FileUploadResponse,
    FileUploadResult,
    FileUploadSeverity,
    FileUploadTechnique,
    FileUploadMutationStrategy,
    TargetRuntime,
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


class MockFileUploadHttpClient:
    """Mock HTTP client simulating upload responses and web shell execution."""

    def __init__(
        self,
        post_response_fn=None,
        get_response_fn=None,
    ):
        self.post_response_fn = post_response_fn
        self.get_response_fn = get_response_fn
        self.requests_log: List[Dict[str, Any]] = []

    def post(self, url: str, **kwargs) -> HttpResponse:
        self.requests_log.append({"method": "POST", "url": url, "kwargs": kwargs})
        if self.post_response_fn:
            return self.post_response_fn(url, **kwargs)
        return HttpResponse(
            success=True,
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"status": "success", "url": "/uploads/shell.php"}',
            raw_body='{"status": "success", "url": "/uploads/shell.php"}',
            url=url,
        )

    def get(self, url: str, **kwargs) -> HttpResponse:
        self.requests_log.append({"method": "GET", "url": url, "kwargs": kwargs})
        if self.get_response_fn:
            return self.get_response_fn(url, **kwargs)
        return HttpResponse(
            success=True,
            status_code=200,
            headers={"content-type": "text/html"},
            body="ARGUS_CANARY_TEST_TOKEN",
            raw_body="ARGUS_CANARY_TEST_TOKEN",
            url=url,
        )


# =============================================================================
# 1. Models & Enums Tests
# =============================================================================

def test_file_upload_severity_enums_and_aliases():
    assert FileUploadSeverity.CRITICAL.value == "critical"
    assert FileUploadSeverity.HIGH.value == "high"
    assert FileUploadSeverity.MEDIUM.value == "medium"
    assert FileUploadSeverity.LOW.value == "low"
    assert FileUploadSeverity.INFO.value == "info"
    assert FileUploadSeverity.CRIT == FileUploadSeverity.CRITICAL


def test_file_upload_technique_enums_and_aliases():
    assert FileUploadTechnique.UNRESTRICTED_UPLOAD.value == "unrestricted_upload"
    assert FileUploadTechnique.MIME_TYPE_BYPASS.value == "mime_type_bypass"
    assert FileUploadTechnique.DOUBLE_EXTENSION_BYPASS.value == "double_extension_bypass"
    assert FileUploadTechnique.POLYGLOT_MAGIC_BYTES.value == "polyglot_magic_bytes"
    assert FileUploadTechnique.PATH_TRAVERSAL_FILENAME.value == "path_traversal_filename"
    assert FileUploadTechnique.NULL_BYTE_INJECTION.value == "null_byte_injection"
    assert FileUploadTechnique.WEB_SHELL_EXECUTION.value == "web_shell_execution"
    assert FileUploadTechnique.STORAGE_PATH_DISCLOSURE.value == "storage_path_disclosure"

    # Aliases
    assert FileUploadTechnique.UNRESTRICTED_FILE_UPLOAD == FileUploadTechnique.UNRESTRICTED_UPLOAD
    assert FileUploadTechnique.MIME_BYPASS == FileUploadTechnique.MIME_TYPE_BYPASS
    assert FileUploadTechnique.DOUBLE_EXTENSION == FileUploadTechnique.DOUBLE_EXTENSION_BYPASS
    assert FileUploadTechnique.POLYGLOT == FileUploadTechnique.POLYGLOT_MAGIC_BYTES
    assert FileUploadTechnique.PATH_TRAVERSAL == FileUploadTechnique.PATH_TRAVERSAL_FILENAME
    assert FileUploadTechnique.NULL_BYTE == FileUploadTechnique.NULL_BYTE_INJECTION
    assert FileUploadTechnique.WEB_SHELL == FileUploadTechnique.WEB_SHELL_EXECUTION
    assert FileUploadTechnique.STORAGE_DISCLOSURE == FileUploadTechnique.STORAGE_PATH_DISCLOSURE


def test_file_upload_mutation_strategy_enums():
    assert FileUploadMutationStrategy.EXTENSION_CASING.value == "extension_casing"
    assert FileUploadMutationStrategy.NULL_BYTE.value == "null_byte"
    assert FileUploadMutationStrategy.CONTENT_TYPE_MISMATCH.value == "content_type_mismatch"
    assert FileUploadMutationStrategy.MAGIC_BYTES_PREPENDING.value == "magic_bytes_prepending"
    assert FileUploadMutationStrategy.FILENAME_ENCODING.value == "filename_encoding"
    assert FileUploadMutationStrategy.TRAILING_DOTS_SPACES.value == "trailing_dots_spaces"
    assert FileUploadMutationStrategy.NTFS_STREAM.value == "ntfs_stream"
    assert FileUploadMutationStrategy.STANDARD.value == "standard"


def test_file_upload_result_properties():
    result = FileUploadResult(
        template_id="unrestricted-upload-php",
        technique="unrestricted_upload",
        vulnerability_type=FileUploadTechnique.UNRESTRICTED_UPLOAD,
        mutation_strategy="standard",
        filename="shell.php",
        content_type="application/x-php",
        severity="critical",
        cwe_id="CWE-434",
        cvss_score=9.8,
        description="Unrestricted executable file upload accepted",
        evidence_snippet="HTTP 200 OK",
        target_url="https://api.example.com/upload",
        uploaded_file_url="https://api.example.com/uploads/shell.php",
        canary_token="ARGUS_CANARY_123",
    )
    assert result.severity == "critical"
    assert result.cwe_id == "CWE-434"
    assert result.cvss_score == 9.8
    assert result.is_valid_finding is True


# =============================================================================
# 2. Payload Generator Tests
# =============================================================================

def test_payload_generator_unrestricted_probes():
    gen = FileUploadPayloadGenerator()
    probes = gen.generate_unrestricted_probes()
    assert len(probes) >= 10

    filenames = [p.filename for p in probes]
    assert "shell.php" in filenames
    assert "exploit.jsp" in filenames
    assert "payload.aspx" in filenames
    assert "script.py" in filenames
    assert "script.rb" in filenames
    assert "cmd.sh" in filenames
    assert "binary.exe" in filenames

    for p in probes:
        assert p.canary_token != ""
        assert p.technique == FileUploadTechnique.UNRESTRICTED_UPLOAD


def test_payload_generator_mime_bypass_probes():
    gen = FileUploadPayloadGenerator()
    probes = gen.generate_mime_bypass_probes()
    assert len(probes) >= 8

    for p in probes:
        assert p.technique == FileUploadTechnique.MIME_TYPE_BYPASS
        assert p.strategy == FileUploadMutationStrategy.CONTENT_TYPE_MISMATCH
        assert p.content_type in ("image/jpeg", "image/png", "image/gif", "application/pdf")
        assert any(p.filename.endswith(ext) for ext in (".php", ".phtml", ".jsp", ".asp", ".aspx", ".py", ".rb", ".sh"))


def test_payload_generator_double_extension_probes():
    gen = FileUploadPayloadGenerator()
    probes = gen.generate_double_extension_probes()
    assert len(probes) >= 10

    filenames = [p.filename for p in probes]
    assert "shell.php.jpg" in filenames
    assert "exploit.jsp.png" in filenames
    assert "payload.aspx.gif" in filenames
    assert "shell.php.png" in filenames

    for p in probes:
        assert p.technique == FileUploadTechnique.DOUBLE_EXTENSION_BYPASS


def test_payload_generator_polyglot_probes():
    gen = FileUploadPayloadGenerator()
    probes = gen.generate_polyglot_probes()
    assert len(probes) >= 8

    for p in probes:
        assert p.technique == FileUploadTechnique.POLYGLOT_MAGIC_BYTES
        assert isinstance(p.content, bytes)
        # Check that magic bytes are present
        assert (
            p.content.startswith(gen.GIF89A_HEADER)
            or p.content.startswith(gen.PNG_HEADER)
            or p.content.startswith(b"\xff\xd8\xff")
            or p.content.startswith(b"%PDF")
        )


def test_payload_generator_path_traversal_probes():
    gen = FileUploadPayloadGenerator()
    probes = gen.generate_path_traversal_probes()
    assert len(probes) >= 8

    filenames = [p.filename for p in probes]
    assert any("../" in f or "..\\" in f or "%2e%2e" in f for f in filenames)
    for p in probes:
        assert p.technique == FileUploadTechnique.PATH_TRAVERSAL_FILENAME


def test_payload_generator_evasion_mutations():
    gen = FileUploadPayloadGenerator()
    probes = gen.generate_evasion_mutations()
    assert len(probes) >= 15

    strategies = {p.strategy for p in probes}
    assert FileUploadMutationStrategy.EXTENSION_CASING in strategies
    assert FileUploadMutationStrategy.NULL_BYTE in strategies
    assert FileUploadMutationStrategy.FILENAME_ENCODING in strategies
    assert FileUploadMutationStrategy.TRAILING_DOTS_SPACES in strategies
    assert FileUploadMutationStrategy.NTFS_STREAM in strategies


def test_payload_generator_benign_probes():
    gen = FileUploadPayloadGenerator()
    probes = gen.generate_benign_probes()
    assert len(probes) == 3
    for p in probes:
        assert p.is_benign is True
        assert p.filename in ("legitimate_image.jpg", "legitimate_photo.png", "document.pdf")


def test_payload_generator_apply_mutation():
    gen = FileUploadPayloadGenerator()
    base_probe = FileUploadProbe(
        filename="shell.php",
        content="<?php echo 'TEST'; ?>",
        content_type="application/x-php",
        technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
        target_runtime=TargetRuntime.PHP,
        canary_token="ARGUS_CANARY_123",
    )

    # 1. Casing
    cased = gen.apply_mutation(base_probe, FileUploadMutationStrategy.EXTENSION_CASING)
    assert cased.filename != "shell.php"
    assert cased.filename.lower() == "shell.php"
    assert cased.strategy == FileUploadMutationStrategy.EXTENSION_CASING

    # 2. Null byte
    nb = gen.apply_mutation(base_probe, FileUploadMutationStrategy.NULL_BYTE)
    assert "%00.jpg" in nb.filename
    assert nb.content_type == "image/jpeg"

    # 3. Content-Type Mismatch
    ctm = gen.apply_mutation(base_probe, FileUploadMutationStrategy.CONTENT_TYPE_MISMATCH)
    assert ctm.content_type == "image/jpeg"
    assert ctm.filename == "shell.php"

    # 4. Magic Bytes Prepending
    mb = gen.apply_mutation(base_probe, FileUploadMutationStrategy.MAGIC_BYTES_PREPENDING)
    assert isinstance(mb.content, bytes)
    assert mb.content.startswith(gen.GIF89A_HEADER)
    assert mb.content_type == "image/gif"

    # 5. Filename Encoding
    fe = gen.apply_mutation(base_probe, FileUploadMutationStrategy.FILENAME_ENCODING)
    assert "%2e" in fe.filename

    # 6. Trailing Dots/Spaces
    td = gen.apply_mutation(base_probe, FileUploadMutationStrategy.TRAILING_DOTS_SPACES)
    assert td.filename.endswith(".")

    # 7. NTFS Stream
    ntfs = gen.apply_mutation(base_probe, FileUploadMutationStrategy.NTFS_STREAM)
    assert "::$DATA" in ntfs.filename


def test_payload_generator_generate_all_probes():
    gen = FileUploadPayloadGenerator()
    all_probes = gen.generate_all_probes()
    assert len(all_probes) >= 50
    assert any(p.technique == FileUploadTechnique.UNRESTRICTED_UPLOAD for p in all_probes)
    assert any(p.technique == FileUploadTechnique.MIME_TYPE_BYPASS for p in all_probes)
    assert any(p.technique == FileUploadTechnique.DOUBLE_EXTENSION_BYPASS for p in all_probes)
    assert any(p.technique == FileUploadTechnique.POLYGLOT_MAGIC_BYTES for p in all_probes)
    assert any(p.technique == FileUploadTechnique.PATH_TRAVERSAL_FILENAME for p in all_probes)


# =============================================================================
# 3. Prober Tests
# =============================================================================

def test_prober_extract_storage_information_location_header():
    client = MockFileUploadHttpClient()
    prober = FileUploadProber(client=client)

    response = FileUploadResponse(
        status_code=201,
        headers={"location": "/static/uploads/2026/shell.php"},
        body="",
    )
    prober._extract_storage_information(response, "https://api.example.com/api/v1/upload", "shell.php")
    assert response.storage_url == "https://api.example.com/static/uploads/2026/shell.php"


def test_prober_extract_storage_information_json_body():
    client = MockFileUploadHttpClient()
    prober = FileUploadProber(client=client)

    response = FileUploadResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body='{"success": true, "file_url": "https://cdn.example.com/files/exploit.jsp", "path": "/var/www/html/uploads/exploit.jsp"}',
    )
    prober._extract_storage_information(response, "https://api.example.com/upload", "exploit.jsp")
    assert response.storage_url == "https://cdn.example.com/files/exploit.jsp"
    assert response.storage_path_disclosed == "/var/www/html/uploads/exploit.jsp"


def test_prober_extract_storage_information_html_regex():
    client = MockFileUploadHttpClient()
    prober = FileUploadProber(client=client)

    response = FileUploadResponse(
        status_code=200,
        headers={"content-type": "text/html"},
        body='<div>File uploaded successfully! Download at <a href="/media/uploads/script.py">link</a></div>',
    )
    prober._extract_storage_information(response, "https://api.example.com/upload", "script.py")
    assert response.storage_url == "https://api.example.com/media/uploads/script.py"


def test_prober_web_shell_reachability_and_execution_verification():
    canary = "ARGUS_CANARY_EXEC_TEST_123"

    def mock_post(url, **kwargs):
        return HttpResponse(
            success=True,
            status_code=201,
            headers={"location": "/uploads/shell.php"},
            body='{"url": "/uploads/shell.php"}',
            url=url,
        )

    def mock_get(url, **kwargs):
        return HttpResponse(
            success=True,
            status_code=200,
            headers={"content-type": "text/html"},
            body=f"<html><body>Output: {canary}</body></html>",
            url=url,
        )

    client = MockFileUploadHttpClient(post_response_fn=mock_post, get_response_fn=mock_get)
    prober = FileUploadProber(client=client)

    probe = FileUploadProbe(
        filename="shell.php",
        content="<?php echo 'ARGUS_CANARY_EXEC_TEST_123'; ?>",
        content_type="application/x-php",
        technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
        canary_token=canary,
    )

    mission = Mission(target="https://api.example.com")
    resp = prober.execute_upload(mission, "https://api.example.com/upload", probe)

    assert resp.status_code == 201
    assert resp.storage_url == "https://api.example.com/uploads/shell.php"
    assert resp.web_shell_executed is True
    assert resp.web_shell_status_code == 200


# =============================================================================
# 4. Analyzer Tests
# =============================================================================

def test_analyzer_detect_storage_path_disclosure():
    analyzer = FileUploadAnalyzer()
    probe = FileUploadProbe(
        filename="test.txt",
        content="hello",
        content_type="text/plain",
        technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
    )
    resp = FileUploadResponse(
        status_code=200,
        body="File saved to internal path: /var/www/vhosts/example.com/public_html/uploads/test.txt",
    )
    result = analyzer.evaluate_probe(probe, resp, "https://example.com/upload")
    assert result is not None
    assert result.is_valid_finding is True
    assert result.storage_path is not None
    assert "/var/www/vhosts" in result.storage_path


def test_analyzer_detect_error_disclosure():
    analyzer = FileUploadAnalyzer()
    probe = FileUploadProbe(
        filename="test.php",
        content="<?php ?>",
        content_type="application/x-php",
        technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
    )
    resp = FileUploadResponse(
        status_code=500,
        body="Fatal error: Uncaught Exception in /var/www/app/UploadHandler.php on line 42\nStack trace: ...",
    )
    result = analyzer.evaluate_probe(probe, resp, "https://example.com/upload")
    assert result is not None
    assert result.is_valid_finding is True
    assert result.cwe_id == "CWE-200"
    assert result.severity == FileUploadSeverity.MEDIUM.value


def test_analyzer_false_positive_rejection_benign_probe():
    analyzer = FileUploadAnalyzer()
    probe = FileUploadProbe(
        filename="legitimate.jpg",
        content=b"\xff\xd8\xff",
        content_type="image/jpeg",
        technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
        is_benign=True,
    )
    resp = FileUploadResponse(
        status_code=200,
        body='{"status": "uploaded", "url": "/uploads/legitimate.jpg"}',
    )
    result = analyzer.evaluate_probe(probe, resp, "https://example.com/upload")
    assert result is None


def test_analyzer_false_positive_rejection_status_403_and_rejection_keywords():
    analyzer = FileUploadAnalyzer()
    probe = FileUploadProbe(
        filename="shell.php",
        content="<?php ?>",
        content_type="application/x-php",
        technique=FileUploadTechnique.UNRESTRICTED_UPLOAD,
    )
    resp = FileUploadResponse(
        status_code=403,
        body="Upload failed: File extension .php is forbidden by server policy.",
    )
    result = analyzer.evaluate_probe(probe, resp, "https://example.com/upload")
    assert result is None


def test_analyzer_false_positive_rejection_uuid_renaming_safe_ext():
    analyzer = FileUploadAnalyzer()
    probe = FileUploadProbe(
        filename="shell.php.jpg",
        content="malicious",
        content_type="image/jpeg",
        technique=FileUploadTechnique.DOUBLE_EXTENSION_BYPASS,
    )
    resp = FileUploadResponse(
        status_code=200,
        body='{"status": "ok", "url": "https://cdn.example.com/assets/f47ac10b-58cc-4372-a567-0e02b2c3d479.jpg"}',
    )
    result = analyzer.evaluate_probe(probe, resp, "https://example.com/upload")
    assert result is None


def test_analyzer_severity_and_cwe_calibration():
    analyzer = FileUploadAnalyzer()

    # 1. Web shell execution -> Critical, CWE-434, CVSS 9.8
    p1 = FileUploadProbe("shell.php", "<?php ?>", "application/x-php", FileUploadTechnique.UNRESTRICTED_UPLOAD)
    r1 = FileUploadResponse(status_code=200, web_shell_executed=True, storage_url="/uploads/shell.php")
    res1 = analyzer.evaluate_probe(p1, r1, "https://example.com/upload")
    assert res1.severity == FileUploadSeverity.CRITICAL.value
    assert res1.cwe_id == "CWE-434"
    assert res1.cvss_score == 9.8

    # 2. MIME bypass -> High, CWE-436, CVSS 8.1
    p2 = FileUploadProbe("shell.php", "<?php ?>", "image/jpeg", FileUploadTechnique.MIME_TYPE_BYPASS)
    r2 = FileUploadResponse(status_code=200, storage_url="/uploads/shell.php")
    res2 = analyzer.evaluate_probe(p2, r2, "https://example.com/upload")
    assert res2.severity == FileUploadSeverity.HIGH.value
    assert res2.cwe_id == "CWE-436"
    assert res2.cvss_score == 8.1

    # 3. Path traversal -> High, CWE-22, CVSS 8.1
    p3 = FileUploadProbe("../../shell.php", "<?php ?>", "application/x-php", FileUploadTechnique.PATH_TRAVERSAL_FILENAME)
    r3 = FileUploadResponse(status_code=200, storage_path_disclosed="/var/www/shell.php")
    res3 = analyzer.evaluate_probe(p3, r3, "https://example.com/upload")
    assert res3.severity == FileUploadSeverity.HIGH.value
    assert res3.cwe_id == "CWE-22"
    assert res3.cvss_score == 8.1


# =============================================================================
# 5. Collector Lifecycle & Quadruple State Publishing
# =============================================================================

def test_collector_full_lifecycle_and_quadruple_state_publishing():
    mission = Mission(
        target="https://target.local",
        endpoints=[{"url": "https://target.local/api/upload"}],
    )
    controlled_mission = ControlledMission(mission)

    def mock_post(url, **kwargs):
        return HttpResponse(
            success=True,
            status_code=201,
            headers={"location": "/uploads/shell.php"},
            body='{"status": "uploaded", "url": "/uploads/shell.php"}',
            url=url,
        )

    def mock_get(url, **kwargs):
        return HttpResponse(
            success=True,
            status_code=200,
            headers={"content-type": "text/html"},
            body="ARGUS_CANARY_",
            url=url,
        )

    mock_client = MockFileUploadHttpClient(post_response_fn=mock_post, get_response_fn=mock_get)
    collector = FileUploadCollector(http_client=mock_client, max_probes_per_endpoint=5)

    evidence_list = collector.collect(controlled_mission)
    assert len(evidence_list) > 0

    # 1. raw_mission.evidence
    ev_items = mission.evidence.all() if hasattr(mission.evidence, "all") else list(mission.evidence)
    assert len(ev_items) > 0
    assert any(ev.category == "file_upload" for ev in ev_items)

    # 2. raw_mission.vulnerabilities
    assert len(mission.vulnerabilities) > 0
    assert any("File Upload" in v.get("name", "") for v in mission.vulnerabilities)

    # 3. attack_surface_graph
    graph = mission.attack_surface_graph
    assert len(graph.nodes) >= 3
    assert any(n.type == "vulnerability" for n in graph.nodes.values())
    assert any(n.type == "endpoint" for n in graph.nodes.values())
    assert any(n.type == "live_host" for n in graph.nodes.values())

    vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    ep_edges = [e for e in graph.edges if e.type == "HAS_ENDPOINT"]
    assert len(vuln_edges) > 0
    assert len(ep_edges) > 0


def test_collector_discover_candidate_endpoints_deduplication():
    mission = Mission(
        target="https://example.com",
        endpoints=[
            {"url": "https://example.com/upload"},
            {"path": "https://example.com/upload"},
            "https://example.com/v2/upload",
        ],
        live_hosts=["https://example.com"],
    )
    mission.inputs = {"endpoints": ["https://example.com/upload", "https://example.com/files"]}

    collector = FileUploadCollector()
    endpoints = collector._discover_candidate_endpoints(mission)

    assert "https://example.com/upload" in endpoints
    assert "https://example.com/v2/upload" in endpoints
    assert "https://example.com/files" in endpoints
    # Check deduplication
    assert endpoints.count("https://example.com/upload") == 1


def test_collector_compatibility_aliases():
    assert UploadVulnerabilityCollector is FileUploadCollector
    assert FileUploadSecurityCollector is FileUploadCollector
    assert UnrestrictedFileUploadCollector is FileUploadCollector
    assert ArbitraryFileUploadCollector is FileUploadCollector


# =============================================================================
# 6. Tool Registry & Plugin Adapter Tests
# =============================================================================

def test_tool_registry_file_upload_registration_and_aliases():
    tool = registry.get("file_upload")
    assert tool is not None
    assert tool.id == "file_upload"
    assert tool.capability == "file_upload_detector"
    assert tool.priority == 95

    # Check aliases
    assert registry.get("file-upload").id == "file_upload"
    assert registry.get("file_upload_specialist").id == "file_upload"
    assert registry.get("file_upload_collector").id == "file_upload"
    assert registry.get("file_upload_detector").id == "file_upload"
    assert registry.get("unrestricted_file_upload").id == "file_upload"
    assert registry.get("arbitrary_file_upload").id == "file_upload"
    assert registry.get("upload_security").id == "file_upload"


def test_plugin_executor_adapter_file_upload_fallback():
    adapter = PluginExecutorAdapter()
    instance = adapter._instantiate_specialist_fallback("file_upload")
    assert isinstance(instance, FileUploadCollector)

    instance2 = adapter._instantiate_specialist_fallback("file_upload_collector")
    assert isinstance(instance2, FileUploadCollector)

    instance3 = adapter._instantiate_specialist_fallback("unrestricted_upload")
    assert isinstance(instance3, FileUploadCollector)


# =============================================================================
# 7. Task Generator DAG & Gap Resolution Tests
# =============================================================================

def test_task_generator_dag_file_upload_template():
    mission = Mission(target="https://target.local", endpoints=["https://target.local/upload"])
    generator = TaskGenerator(mission)
    tasks = generator.generate_recon_tasks()
    assert isinstance(tasks, list)
    gap = CoverageGap(area="file_upload", description="Check file upload security", category=TaskCategory.EVIDENCE_CORRELATION)
    gap_tasks = generator.from_gaps([gap])
    assert len(gap_tasks) == 1
    assert gap_tasks[0].metadata.get("tool_id") == "file_upload"


def test_task_generator_resolve_gap_file_upload():
    mission = Mission(target="https://target.local", endpoints=["https://target.local/upload"])
    generator = TaskGenerator(mission)

    # 1. Area matching
    gap1 = CoverageGap(area="file upload", description="Check file upload security", category=TaskCategory.EVIDENCE_CORRELATION)
    template1 = generator._resolve_template_for_gap(gap1)
    assert template1["metadata"]["tool_id"] == "file_upload"
    assert "Discover API Endpoints" in template1["dependencies"]

    # 2. Area matching unrestricted upload
    gap2 = CoverageGap(area="unrestricted file upload", description="Upload web shells", category=TaskCategory.EVIDENCE_CORRELATION)
    template2 = generator._resolve_template_for_gap(gap2)
    assert template2["metadata"]["tool_id"] == "file_upload"

    # 3. Category fallback keyword matching
    gap3 = CoverageGap(area="unknown", description="Probe for MIME type bypass and polyglot web shell", category=TaskCategory.EVIDENCE_CORRELATION)
    template3 = generator._resolve_template_for_gap(gap3)
    assert template3["metadata"]["tool_id"] == "file_upload"

    # 4. Generate ResearchTasks
    tasks = generator.from_gaps([gap1])
    assert len(tasks) == 1
    assert tasks[0].metadata.get("tool_id") == "file_upload"
    assert "https://target.local/upload" in tasks[0].required_inputs


# =============================================================================
# 8. Attack Surface Graph Expansion Tests
# =============================================================================

def test_attack_surface_graph_file_upload_evidence_edges():
    builder = AttackSurfaceGraphBuilder()

    ev = Evidence(
        category="file_upload",
        value="file_upload:unrestricted-upload:https://example.com/api/upload:shell.php",
        source="file_upload",
        status="CONFIRMED",
        confidence=0.95,
        severity="critical",
        title="File Upload Vulnerability: unrestricted_upload on https://example.com/api/upload",
        metadata={
            "url": "https://example.com/api/upload",
            "host": "https://example.com",
            "template_id": "unrestricted-upload-php",
            "technique": "unrestricted_upload",
            "filename": "shell.php",
            "status_code": 201,
            "cwe_id": "CWE-434",
            "cvss_score": 9.8,
        },
    )

    graph = builder.build_from_evidence([ev])

    assert "endpoint:https://example.com/api/upload" in graph.nodes
    assert "vulnerability:unrestricted-upload-php:https://example.com/api/upload:shell.php" in graph.nodes
    assert "live_host:https://example.com" in graph.nodes

    # Check edges
    lh_to_ep = [e for e in graph.edges if e.source == "live_host:https://example.com" and e.target == "endpoint:https://example.com/api/upload" and e.type == "HAS_ENDPOINT"]
    lh_to_vuln = [e for e in graph.edges if e.source == "live_host:https://example.com" and "vulnerability:" in e.target and e.type == "HAS_VULNERABILITY"]
    ep_to_vuln = [e for e in graph.edges if e.source == "endpoint:https://example.com/api/upload" and "vulnerability:" in e.target and e.type == "HAS_VULNERABILITY"]

    assert len(lh_to_ep) == 1
    assert len(lh_to_vuln) == 1
    assert len(ep_to_vuln) == 1


# =============================================================================
# 9. CVSS & CWE Mapping Tests
# =============================================================================

def test_cvss_calculator_cwe_434_and_436_mappings():
    calc = CVSSCalculator()

    cwe434 = calc.get_cwe_info("file_upload")
    assert cwe434.id == "CWE-434"
    assert "Unrestricted Upload" in cwe434.name

    cwe436 = calc.get_cwe_info("mime_type_bypass")
    assert cwe436.id == "CWE-436"
    assert "Interpretation Conflict" in cwe436.name

    polyglot_cwe = calc.get_cwe_info("polyglot_magic_bytes")
    assert polyglot_cwe.id == "CWE-436"
