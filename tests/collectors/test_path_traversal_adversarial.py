"""
Adversarial Stress Test Suite for Path Traversal Engine & Attack Surface Graph Integration.

Challenger 2 Empirical Verification:
- Boundary Linux/Unix & Windows signatures (passwd, shadow, environ, hosts, win.ini, boot.ini)
- False positive rejection under reflection, soft-404, JSON errors, HTTP status code boundaries
- Attack surface graph edge and node integrity (HAS_ENDPOINT, HAS_VULNERABILITY, no orphan nodes)
- Documentation and characterization of signature edge cases and findings.
"""
from typing import Any, Dict, List, Optional
import pytest
import urllib.parse

from argus.collectors.path_traversal import (
    PathTraversalCollector,
    PathTraversalPayloadGenerator,
    PathTraversalAnalyzer,
    DEFAULT_TRAVERSAL_PAYLOADS,
)
from argus.evidence.model import Evidence, ProvenanceData
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission


class MockAdversarialHttpClient:
    """Configurable Mock HTTP Client for Adversarial Path Traversal Scenarios."""

    def __init__(self, default_response: Optional[tuple] = None):
        self.routes: Dict[str, tuple] = {}
        self.default_response = default_response or (404, "Not Found")
        self.history: List[str] = []

    def set_route(self, url: str, status_code: int, body: str):
        self.routes[url] = (status_code, body)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        self.history.append(target_url)

        if target_url in self.routes:
            status_code, body = self.routes[target_url]
            return HttpResponse(
                success=(200 <= status_code < 300),
                status_code=status_code,
                raw_body=body,
                body=body,
                url=target_url,
            )

        status_code, body = self.default_response
        return HttpResponse(
            success=(200 <= status_code < 300),
            status_code=status_code,
            raw_body=body,
            body=body,
            url=target_url,
        )


# ============================================================================
# 1. SIGNATURE MATCHING & BOUNDARY CONDITIONS (Linux & Windows)
# ============================================================================

@pytest.mark.parametrize(
    "passwd_line,expected_match",
    [
        # Standard root with bash/sh/zsh/dash/nologin
        ("root:x:0:0:root:/root:/bin/bash", True),
        ("root:x:0:0:root:/root:/bin/sh", True),
        ("root:x:0:0:root:/root:/bin/zsh", True),
        ("root:x:0:0:root:/root:/bin/dash", True),
        ("root:x:0:0:root:/root:/usr/bin/nologin", True),
        ("root:x:0:0:root:/root:/bin/nologin", True),
        # BSD / macOS root format with asterisks or empty password
        ("root:*:0:0:System Administrator:/var/root:/bin/sh", True),
        ("root::0:0:SuperUser:/root:/bin/bash", True),
        # Non-standard shells / fallbacks
        ("root:x:0:0:root:/root:/usr/bin/fish", True),
        ("root:x:0:0:root:/root:/sbin/nologin", True),
        ("root:x:0:0::/root:/bin/sh", True),
        # Daemon / bin / nobody secondary lines
        ("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/bin/sh", True),
        ("nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nroot:x:0:0:root:/root:/bin/sh", True),
        # Malformed / truncated lines (should NOT match)
        ("root:x:0", False),
        ("root:x:0:0", False),
        ("root:x:0:0:", False),
        ("user:x:1000:1000:User:/home/user:/bin/bash", False),
        ("daemon:x:abc:1:daemon:/bin:/bin/sh", False),
        ("daemon:x:1:daemon:/bin:/bin/sh", False),
    ],
)
def test_adversarial_linux_passwd_signature_boundaries(passwd_line: str, expected_match: bool):
    analyzer = PathTraversalAnalyzer()
    res = analyzer.analyze(200, passwd_line + "\n", "/etc/passwd")
    if expected_match:
        assert res is not None, f"Failed to match valid passwd signature: {passwd_line}"
        assert res["target_file"] == "/etc/passwd"
        assert res["os"] == "linux"
    else:
        assert res is None, f"Incorrectly matched invalid passwd line: {passwd_line}"


@pytest.mark.parametrize(
    "shadow_line,expected_match",
    [
        ("root:$6$rounds=656000$salt$hash:19000:0:99999:7:::", True),
        ("root:$1$salt$hash:18000:0:99999:7:::", True),
        ("root:$5$salt$hash:18000:0:99999:7:::", True),
        ("root:$y$j9T$salt$hash:19500:0:99999:7:::", True),
        ("root:!:18000:0:99999:7:::", True),
        ("root:*:18000:0:99999:7:::", True),
        # Invalid / truncated shadow
        ("root:$6$incomplete", False),
        ("daemon:$6$rounds=656000$salt$hash:19000:0:99999:7:::", False),
    ],
)
def test_adversarial_linux_shadow_signature_boundaries(shadow_line: str, expected_match: bool):
    analyzer = PathTraversalAnalyzer()
    res = analyzer.analyze(200, shadow_line + "\n", "/etc/shadow")
    if expected_match:
        assert res is not None, f"Failed to match valid shadow signature: {shadow_line}"
        assert res["target_file"] == "/etc/shadow"
    else:
        assert res is None, f"Incorrectly matched invalid shadow line: {shadow_line}"


@pytest.mark.parametrize(
    "environ_content,expected_match",
    [
        ("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\x00USER=root\x00PWD=/var/www\x00", True),
        ("HOSTNAME=web-prod-01\x00HOME=/root\x00SHELL=/bin/bash\x00", True),
        ("LANG=en_US.UTF-8\x00PATH=/bin:/usr/bin\x00", True),
        # Short / invalid
        ("P=", False),
        ("PATH=", False),
        ("FOOBAR=123", False),
    ],
)
def test_adversarial_linux_environ_signature_boundaries(environ_content: str, expected_match: bool):
    analyzer = PathTraversalAnalyzer()
    res = analyzer.analyze(200, environ_content, "/proc/self/environ")
    if expected_match:
        assert res is not None
        assert res["target_file"] == "/proc/self/environ"
    else:
        assert res is None


@pytest.mark.parametrize(
    "hosts_content,expected_match",
    [
        ("127.0.0.1 localhost\n::1 localhost ip6-localhost", True),
        ("127.0.0.1\tlocalhost\n127.0.1.1\thostname", True),
        ("127.0.0.1   localhost", True),
        # Invalid hosts
        ("127.0.0.1 mycustomhost", False),
        ("localhost 127.0.0.1", False),
    ],
)
def test_adversarial_linux_hosts_signature_boundaries(hosts_content: str, expected_match: bool):
    analyzer = PathTraversalAnalyzer()
    res = analyzer.analyze(200, hosts_content, "/etc/hosts")
    if expected_match:
        assert res is not None
        assert res["target_file"] == "/etc/hosts"
    else:
        assert res is None


@pytest.mark.parametrize(
    "win_content,expected_match,expected_file",
    [
        ("[fonts]\r\nArial=arial.ttf\r\n[extensions]\r\n", True, "c:\\windows\\win.ini"),
        ("[FONTS]\r\nArial=arial.ttf\r\n[EXTENSIONS]\r\n", True, "c:\\windows\\win.ini"),
        ("; for 16-bit app support\r\n[386Enh]\r\nwoafont=dosapp.fon\r\n", True, "c:\\windows\\win.ini"),
        ("[boot loader]\r\ntimeout=30\r\n[operating systems]\r\n", True, "c:\\boot.ini"),
        ("[BOOT LOADER]\r\ntimeout=30\r\n[OPERATING SYSTEMS]\r\n", True, "c:\\boot.ini"),
        # Invalid Windows
        ("[font]", False, None),
        ("[extension]", False, None),
        ("boot loader without brackets", False, None),
        ("random content in file", False, None),
    ],
)
def test_adversarial_windows_signatures_boundaries(win_content: str, expected_match: bool, expected_file: Optional[str]):
    analyzer = PathTraversalAnalyzer()
    res = analyzer.analyze(200, win_content, "c:\\windows\\win.ini")
    if expected_match:
        assert res is not None, f"Failed to match valid windows signature: {win_content}"
        assert res["os"] == "windows"
        if expected_file:
            assert res["target_file"] == expected_file
    else:
        assert res is None, f"Incorrectly matched invalid windows content: {win_content}"


# ============================================================================
# 2. FALSE POSITIVE REJECTION UNDER ADVERSARIAL STRESS
# ============================================================================

@pytest.mark.parametrize(
    "error_body,payload",
    [
        # HTML error reflections
        ("<html><body><h1>404 Not Found</h1><p>File ../../../../etc/passwd not found.</p></body></html>", "../../../../etc/passwd"),
        ("<div class='error'>Error opening file: ../../../../windows/win.ini - No such file</div>", "../../../../windows/win.ini"),
        ("<p>Requested template: c:\\boot.ini was not found on server.</p>", "c:\\boot.ini"),
        ("<h3>Cannot read /etc/shadow: Permission denied</h3>", "/etc/shadow"),
        # Soft-404 JSON error reflections
        ('{"status": "error", "message": "Failed to load ../../../../etc/passwd: File does not exist"}', "../../../../etc/passwd"),
        ('{"code": 404, "error": "Path traversal detected: c:/windows/win.ini"}', "c:/windows/win.ini"),
        ('{"error": "Invalid document: ../../../../boot.ini"}', "../../../../boot.ini"),
        # Form echoes
        ('<form><input type="hidden" name="file" value="../../../../etc/passwd" /></form>', "../../../../etc/passwd"),
        ('<div>Search results for query: <b>../../../../windows/win.ini</b> (0 results)</div>', "../../../../windows/win.ini"),
    ],
)
def test_adversarial_reflection_false_positive_rejection(error_body: str, payload: str):
    analyzer = PathTraversalAnalyzer()
    res = analyzer.analyze(200, error_body, payload)
    assert res is None, f"False positive detected on reflected error body: {error_body}"


@pytest.mark.parametrize(
    "status_code",
    [
        100, 101, 103,
        300, 301, 302, 303, 304, 307, 308,
        400, 401, 402, 403, 404, 405, 422, 429,
        500, 501, 502, 503, 504,
        None,
    ],
)
def test_adversarial_http_status_code_filtering(status_code: Optional[int]):
    """Non-2xx status codes must NEVER produce confirmed evidence."""
    analyzer = PathTraversalAnalyzer()
    valid_body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    res = analyzer.analyze(status_code, valid_body, "../../../../etc/passwd")
    assert res is None, f"Status code {status_code} was incorrectly accepted!"


@pytest.mark.parametrize("status_code", [200, 201, 202, 203, 206])
def test_valid_http_2xx_status_codes_accepted(status_code: int):
    """2xx status codes with valid payload disclosure must produce confirmed evidence."""
    analyzer = PathTraversalAnalyzer()
    valid_body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    res = analyzer.analyze(status_code, valid_body, "../../../../etc/passwd")
    assert res is not None
    assert res["target_file"] == "/etc/passwd"


def test_adversarial_baseline_differential_suppression():
    """
    If the baseline response already contains OS signatures (e.g. documentation, static code sample),
    fuzzing that endpoint must NOT trigger a false positive.
    """
    analyzer = PathTraversalAnalyzer()
    static_doc = """
    <html>
    <head><title>Linux Documentation</title></head>
    <body>
    <h1>Understanding /etc/passwd</h1>
    <pre>
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/bin/sh
    </pre>
    </body>
    </html>
    """

    res = analyzer.analyze(
        status_code=200,
        body=static_doc,
        payload="../../../../etc/passwd",
        baseline_body=static_doc,
    )
    assert res is None, "Baseline differential failed to suppress static documentation reflection"


def test_adversarial_empty_and_short_bodies():
    analyzer = PathTraversalAnalyzer()
    assert analyzer.analyze(200, "", "/etc/passwd") is None
    assert analyzer.analyze(200, "   ", "/etc/passwd") is None
    assert analyzer.analyze(200, "root:x", "/etc/passwd") is None
    assert analyzer.analyze(200, None, "/etc/passwd") is None


# ============================================================================
# 3. ATTACK SURFACE GRAPH INTEGRATION & INTEGRITY
# ============================================================================

def test_adversarial_graph_node_and_edge_integrity():
    """
    Verify that live_host, endpoint, and vulnerability nodes and
    HAS_ENDPOINT and HAS_VULNERABILITY edges are constructed without orphan nodes.
    """
    mission = Mission(target="secops.corp.local")
    mission.live_hosts = ["https://secops.corp.local"]
    mission.endpoints = [{"url": "https://secops.corp.local/api/v2/view?file=report.pdf"}]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    mock_client = MockAdversarialHttpClient()
    vuln_url = "https://secops.corp.local/api/v2/view?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    mock_client.set_route(
        vuln_url,
        200,
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    )

    collector = PathTraversalCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) == 1
    ev = evidence_list[0]

    # Inspect the KnowledgeGraph
    lh_id = "live_host:https://secops.corp.local"
    ep_id = f"endpoint:{vuln_url}"
    vuln_id = f"vulnerability:{ev.metadata['template_id']}:{vuln_url}"

    assert lh_id in graph.nodes
    assert ep_id in graph.nodes
    assert vuln_id in graph.nodes

    # Check edges
    has_endpoint_edges = [
        e for e in graph.edges if e.type == "HAS_ENDPOINT" and e.source == lh_id and e.target == ep_id
    ]
    assert len(has_endpoint_edges) == 1, "Missing HAS_ENDPOINT edge from live_host to endpoint"

    has_vuln_lh_edges = [
        e for e in graph.edges if e.type == "HAS_VULNERABILITY" and e.source == lh_id and e.target == vuln_id
    ]
    assert len(has_vuln_lh_edges) == 1, "Missing HAS_VULNERABILITY edge from live_host to vulnerability"

    has_vuln_ep_edges = [
        e for e in graph.edges if e.type == "HAS_VULNERABILITY" and e.source == ep_id and e.target == vuln_id
    ]
    assert len(has_vuln_ep_edges) == 1, "Missing HAS_VULNERABILITY edge from endpoint to vulnerability"

    # Verify no orphan nodes: every node must have at least one connected edge
    connected_node_ids = set()
    for e in graph.edges:
        connected_node_ids.add(e.source)
        connected_node_ids.add(e.target)

    for node_id in graph.nodes:
        assert node_id in connected_node_ids, f"Found orphan node in graph: {node_id}"


def test_adversarial_attack_surface_graph_builder_reconstruction_consistency():
    """
    Verify that AttackSurfaceGraphBuilder offline reconstruction from Evidence items
    produces identical topology and attributes as runtime collection.
    """
    ev1 = Evidence(
        mission_id="m1",
        title="Path Traversal: file on https://app.corp/read?file=../../../../etc/passwd",
        category="path_traversal",
        severity="critical",
        status="CONFIRMED",
        confidence=0.95,
        value="https://app.corp/read?file=../../../../etc/passwd",
        source="https://app.corp/read?file=../../../../etc/passwd",
        metadata={
            "url": "https://app.corp/read?file=../../../../etc/passwd",
            "host": "https://app.corp",
            "path": "/read",
            "parameter": "file",
            "template_id": "path-traversal-etc-passwd",
            "target_file": "/etc/passwd",
            "os": "linux",
            "status_code": 200,
        },
    )

    ev2 = Evidence(
        mission_id="m1",
        title="Path Traversal: path on https://app.corp/download/c:/windows/win.ini",
        category="path_traversal",
        severity="critical",
        status="CONFIRMED",
        confidence=0.95,
        value="https://app.corp/download/c:/windows/win.ini",
        source="https://app.corp/download/c:/windows/win.ini",
        metadata={
            "url": "https://app.corp/download/c:/windows/win.ini",
            "host": "https://app.corp",
            "path": "/download",
            "parameter": "path",
            "template_id": "path-traversal-c--windows-win-ini",
            "target_file": "c:\\windows\\win.ini",
            "os": "windows",
            "status_code": 200,
        },
    )

    builder = AttackSurfaceGraphBuilder()
    graph = builder.build_from_evidence([ev1, ev2], target="app.corp")

    # Assert nodes
    assert "target:app.corp" in graph.nodes
    assert "live_host:https://app.corp" in graph.nodes
    assert "endpoint:https://app.corp/read?file=../../../../etc/passwd" in graph.nodes
    assert "endpoint:https://app.corp/download/c:/windows/win.ini" in graph.nodes
    assert "vulnerability:path-traversal-etc-passwd:https://app.corp/read?file=../../../../etc/passwd" in graph.nodes
    assert "vulnerability:path-traversal-c--windows-win-ini:https://app.corp/download/c:/windows/win.ini" in graph.nodes

    # Assert edges
    edges = [(e.source, e.type, e.target) for e in graph.edges]
    assert ("live_host:https://app.corp", "HAS_ENDPOINT", "endpoint:https://app.corp/read?file=../../../../etc/passwd") in edges
    assert ("live_host:https://app.corp", "HAS_ENDPOINT", "endpoint:https://app.corp/download/c:/windows/win.ini") in edges
    assert ("live_host:https://app.corp", "HAS_VULNERABILITY", "vulnerability:path-traversal-etc-passwd:https://app.corp/read?file=../../../../etc/passwd") in edges
    assert ("endpoint:https://app.corp/read?file=../../../../etc/passwd", "HAS_VULNERABILITY", "vulnerability:path-traversal-etc-passwd:https://app.corp/read?file=../../../../etc/passwd") in edges
    assert ("live_host:https://app.corp", "HAS_VULNERABILITY", "vulnerability:path-traversal-c--windows-win-ini:https://app.corp/download/c:/windows/win.ini") in edges
    assert ("endpoint:https://app.corp/download/c:/windows/win.ini", "HAS_VULNERABILITY", "vulnerability:path-traversal-c--windows-win-ini:https://app.corp/download/c:/windows/win.ini") in edges


def test_adversarial_mission_builder_dual_mode_graph_integrity():
    """
    Verify AttackSurfaceGraphBuilder.build(mission) correctly attaches to
    both mission.attack_surface_graph and mission.graph.
    """
    mission = Mission(target="dual.example.com")
    mission.live_hosts = ["https://dual.example.com"]
    mission.vulnerabilities = [
        {
            "name": "Path Traversal (/etc/passwd)",
            "template_id": "path-traversal-etc-passwd",
            "severity": "critical",
            "host": "https://dual.example.com",
            "url": "https://dual.example.com/view?file=../../../../etc/passwd",
        }
    ]

    builder = AttackSurfaceGraphBuilder()
    graph = builder.build(mission)

    assert graph is not None
    assert mission.attack_surface_graph is graph
    assert mission.graph is graph

    # Verify nodes
    vuln_node = graph.get("vulnerability:path-traversal-etc-passwd:https://dual.example.com/view?file=../../../../etc/passwd")
    assert vuln_node is not None
    assert vuln_node.metadata["severity"] == "critical"


# ============================================================================
# 4. EMPIRICAL CHALLENGER FINDINGS CHARACTERIZATION
# ============================================================================

def test_characterize_finding_unanchored_passwd_regex():
    """
    Empirical Observation: UNIX_PASSWD_REGEX in path_traversal.py lacks line-start / word boundary anchor.
    This test verifies how it matches prefix usernames vs standard root entries.
    """
    analyzer = PathTraversalAnalyzer()
    # Standard matches
    res_std = analyzer.analyze(200, "root:x:0:0:root:/root:/bin/bash\n", "/etc/passwd")
    assert res_std is not None
    assert res_std["matched_signature"] == "linux_passwd_root"

    # Prefix username matching due to missing anchor
    res_prefix = analyzer.analyze(200, "not_root:x:0:0:root:/root:/bin/bash\n", "/etc/passwd")
    # Documents that current regex matches substring 'root:x:0:0:root:/root'
    assert res_prefix is not None


def test_characterize_finding_windows_hosts_signature_ordering():
    """
    Empirical Observation: Windows hosts file containing '127.0.0.1 localhost' matches linux_hosts first
    due to signature evaluation order in PathTraversalAnalyzer.SIGNATURES.
    """
    analyzer = PathTraversalAnalyzer()
    win_hosts_doc = "# Copyright (c) 1993-2009 Microsoft Corp.\r\n127.0.0.1       localhost\r\n::1             localhost\r\n"
    res = analyzer.analyze(200, win_hosts_doc, "c:\\windows\\system32\\drivers\\etc\\hosts")
    assert res is not None
    # Documents signature precedence behavior
    assert res["matched_signature"] in ("linux_hosts", "windows_hosts")
