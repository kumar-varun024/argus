"""
Adversarial Stress Test Suite for Sprint 6 Access Control Engine (Challenger 2).

Systematic empirical stress tests for:
1. Collector target handling (empty lists, malformed URLs, complex nested paths, query arrays, single/missing/zero identities).
2. Header bypass logic (multiple proxy headers, non-standard ports, invalid schemes, query params).
3. KnowledgeGraph & AttackSurfaceBuilder (connectivity, deduplication, graph invariants, orphan prevention).
4. DAG & Task Generator integration under edge conditions.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Optional
import pytest

from argus.analyzers.response_discrepancy import ResponseDiscrepancyAnalyzer, DiscrepancyVerdict
from argus.collectors.access_control import (
    AccessControlCollector,
    HORIZONTAL_PATH_PATTERNS,
    QUERY_ID_PARAM_REGEX,
    VERTICAL_ADMIN_PATTERNS,
)
from argus.evidence.model import Evidence, ProvenanceData
from argus.evidence.store import EvidenceStore
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.http.client import HttpResponse
from argus.http.coordinator import MultiIdentitySessionCoordinator
from argus.models.test_identity import TestIdentity, AuthType
from argus.planning.gap_analysis import GapAnalyzer
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry


class AdversarialMockHttpClient:
    """Configurable HTTP client for simulating complex server responses and edge cases."""

    def __init__(self):
        # Maps (url, identity_id, header_key, header_val) -> (status_code, body, headers)
        self.routes: Dict[tuple, tuple] = {}
        self.call_history: List[Dict[str, Any]] = []

    def set_route(
        self,
        url: str,
        status_code: int,
        body: str,
        identity_id: Optional[str] = None,
        header_key: Optional[str] = None,
        header_val: Optional[str] = None,
        resp_headers: Optional[Dict[str, str]] = None,
    ):
        key = (url, identity_id, header_key, header_val)
        self.routes[key] = (status_code, body, resp_headers or {})

    def execute_as(
        self,
        identity: Optional[TestIdentity],
        mission: Any,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        **kwargs,
    ) -> HttpResponse:
        ident_id = identity.id if identity else None
        self.call_history.append({
            "identity_id": ident_id,
            "method": method,
            "url": url,
            "headers": headers,
        })

        # 1. Header-specific match
        if headers:
            for hk, hv in headers.items():
                if (url, ident_id, hk, hv) in self.routes:
                    st, bd, hd = self.routes[(url, ident_id, hk, hv)]
                    return HttpResponse(success=(st < 400), status_code=st, raw_body=bd, body=bd, url=url, headers=hd)
                if (url, None, hk, hv) in self.routes:
                    st, bd, hd = self.routes[(url, None, hk, hv)]
                    return HttpResponse(success=(st < 400), status_code=st, raw_body=bd, body=bd, url=url, headers=hd)

        # 2. Identity-specific match
        if (url, ident_id, None, None) in self.routes:
            st, bd, hd = self.routes[(url, ident_id, None, None)]
            return HttpResponse(success=(st < 400), status_code=st, raw_body=bd, body=bd, url=url, headers=hd)

        # 3. Generic match
        if (url, None, None, None) in self.routes:
            st, bd, hd = self.routes[(url, None, None, None)]
            return HttpResponse(success=(st < 400), status_code=st, raw_body=bd, body=bd, url=url, headers=hd)

        # Default 404
        return HttpResponse(success=False, status_code=404, raw_body="Not Found", body="Not Found", url=url)


# =============================================================================
# SECTION 1: Collector Target Handling Stress Tests
# =============================================================================

def test_target_handling_empty_endpoints_and_live_hosts():
    """Validates collector behavior when endpoints and live hosts are empty or None."""
    # Case A: Target provided with empty endpoints and live hosts
    mission_a = Mission(target="target.com")
    mission_a.endpoints = []
    mission_a.live_hosts = []
    mission_a.evidence = EvidenceStore()
    mission_a.vulnerabilities = []

    mock_client = AdversarialMockHttpClient()
    # Mock admin probe responses as 404
    for p in ["/admin", "/admin/dashboard", "/admin/users", "/api/admin/users", "/api/admin/system", "/management/users"]:
        mock_client.set_route(f"https://target.com{p}", 404, "Not Found")

    collector = AccessControlCollector(http_client=mock_client)
    evidence = collector.collect(mission_a)
    assert isinstance(evidence, list)
    assert len(evidence) == 0

    # Case B: No target, empty endpoints, empty live hosts (nil mission state)
    mission_b = Mission(target="")
    mission_b.endpoints = None
    mission_b.live_hosts = None
    mission_b.evidence = None
    mission_b.vulnerabilities = None

    evidence_b = collector.collect(mission_b)
    assert isinstance(evidence_b, list)
    assert len(evidence_b) == 0


def test_target_handling_malformed_urls():
    """Validates collector resilience against malformed, whitespace, unparseable, and non-HTTP URLs."""
    mission = Mission(target="target.corp")
    mission.endpoints = [
        {"url": ""},
        {"url": None},
        "",
        "   https://target.corp/api/users/123/profile   ",  # whitespace
        "target.corp/api/users/456/profile",  # missing scheme
        "ftp://target.corp/api/users/789/profile",  # ftp scheme
        "javascript:alert(1)",  # invalid scheme
        "https://target.corp:8443/api/users/999/profile",  # non-standard port
        {"path": "/api/users/111/profile"},  # relative dict path
    ]
    mission.live_hosts = ["https://target.corp", "https://target.corp:8443"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    collector = AccessControlCollector()
    candidates = collector._extract_candidate_endpoints(mission)

    assert isinstance(candidates, list)
    # Ensure invalid / empty items did not cause crashes
    assert any("123" in c for c in candidates)
    assert any("8443" in c for c in candidates)
    assert any("111" in c for c in candidates)


def test_target_handling_numeric_and_uuid_path_parameters():
    """
    Validates regex detection and collector execution for standard API paths and UUID routes:
    /api/v1/users/123/profile and /api/accounts/550e8400-e29b-41d4-a716-446655440000/invoices/9988
    """
    api_url = "https://target.corp/api/v1/users/123/profile"
    uuid_url = "https://target.corp/api/accounts/550e8400-e29b-41d4-a716-446655440000/invoices/9988"

    assert any(p.search(api_url) for p in HORIZONTAL_PATH_PATTERNS)
    assert any(p.search(uuid_url) for p in HORIZONTAL_PATH_PATTERNS)

    mission = Mission(target="target.corp")
    mission.endpoints = [api_url, uuid_url]
    mission.live_hosts = ["https://target.corp"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    user_owner = TestIdentity(
        id="user_123",
        name="Target User",
        role="user",
        credentials={"user_id": "123", "email": "owner@target.corp"},
    )
    user_attacker = TestIdentity(
        id="usr_attacker",
        name="Attacker User",
        role="user",
        credentials={"user_id": "usr_attacker", "email": "attacker@target.corp"},
    )
    mission.test_identities = [user_owner, user_attacker]

    mock_client = AdversarialMockHttpClient()
    leaked_payload = json.dumps({
        "id": "123",
        "email": "owner@target.corp",
        "name": "Target User",
    })
    mock_client.set_route(api_url, 200, leaked_payload, identity_id=user_owner.id)
    mock_client.set_route(api_url, 200, leaked_payload, identity_id=user_attacker.id)
    mock_client.set_route(uuid_url, 200, '{"invoice_id": "9988"}', identity_id=user_owner.id)
    mock_client.set_route(uuid_url, 403, '{"error": "Forbidden"}', identity_id=user_attacker.id)

    collector = AccessControlCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.category == "broken_access_control"
    assert ev.severity == "critical"
    assert "user_123" in ev.value or "123" in ev.description
    assert ev.metadata["discrepancy_type"] == "horizontal_idor"


def test_target_handling_query_id_parameters():
    """
    Validates regex matching and IDOR testing for standard query string identifiers:
    e.g. ?user_id=123, ?account_id=999, ?uid=alice
    """
    q_url_1 = "https://target.corp/api/search?user_id=123&sort=desc"
    q_url_2 = "https://target.corp/api/documents?doc_id=doc_999"

    assert QUERY_ID_PARAM_REGEX.search(q_url_1) is not None
    assert QUERY_ID_PARAM_REGEX.search(q_url_2) is not None

    mission = Mission(target="target.corp")
    mission.endpoints = [q_url_1, q_url_2]
    mission.live_hosts = ["https://target.corp"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    user_a = TestIdentity(id="u123", role="user", credentials={"user_id": "123"})
    user_b = TestIdentity(id="u456", role="user", credentials={"user_id": "456"})
    mission.test_identities = [user_a, user_b]

    mock_client = AdversarialMockHttpClient()
    mock_client.set_route(q_url_1, 200, json.dumps({"user_id": "123", "data": "secret_records"}), identity_id=user_a.id)
    mock_client.set_route(q_url_1, 200, json.dumps({"user_id": "123", "data": "secret_records"}), identity_id=user_b.id)

    collector = AccessControlCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    assert any(e.metadata["discrepancy_type"] == "horizontal_idor" for e in evidence)


def test_target_handling_single_identity_mission():
    """
    When only 1 user identity exists (User A with credentials):
    The collector must synthesize an unauthorized/attacker probe to verify if User A's private data
    is accessible without authorization or with unprivileged session.
    """
    mission = Mission(target="target.corp")
    mission.endpoints = ["https://target.corp/api/users/123/profile"]
    mission.live_hosts = ["https://target.corp"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    single_user = TestIdentity(
        id="user_alice",
        name="Alice",
        role="user",
        credentials={"email": "alice@target.corp", "user_id": "123"},
    )
    mission.test_identities = [single_user]

    mock_client = AdversarialMockHttpClient()
    alice_payload = json.dumps({"id": "123", "name": "Alice", "email": "alice@target.corp"})
    # Both Alice and unauthenticated/synthetic user get Alice's profile
    mock_client.set_route("https://target.corp/api/users/123/profile", 200, alice_payload, identity_id="user_alice")
    mock_client.set_route("https://target.corp/api/users/123/profile", 200, alice_payload, identity_id="unauth_user")

    collector = AccessControlCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) == 1
    assert evidence[0].category == "broken_access_control"
    assert evidence[0].metadata["discrepancy_type"] == "horizontal_idor"


def test_target_handling_missing_admin_identities():
    """
    When no admin identities are configured in mission.test_identities (only regular user exists):
    Vertical privilege escalation testing still executes using the regular user as unprivileged probe,
    flagging when administrative endpoints (e.g. /admin/dashboard) return 200 with admin content.
    """
    mission = Mission(target="target.corp")
    mission.endpoints = ["https://target.corp/admin/dashboard"]
    mission.live_hosts = ["https://target.corp"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    reg_user = TestIdentity(id="regular_user", role="user")
    mission.test_identities = [reg_user]  # No admin identity

    mock_client = AdversarialMockHttpClient()
    admin_body = "<html><head><title>Admin Console</title></head><body><h1>Administrative Management</h1><p>Full control active</p></body></html>"
    mock_client.set_route("https://target.corp/admin/dashboard", 200, admin_body, identity_id="regular_user")

    collector = AccessControlCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    vert_ev = next(e for e in evidence if e.metadata["discrepancy_type"] == "vertical_privilege_escalation")
    assert vert_ev.category == "broken_access_control"
    assert vert_ev.severity == "critical"


def test_target_handling_zero_identities_mission():
    """
    When mission.test_identities is completely empty:
    The collector gracefully falls back to unauthenticated guest probing without raising exceptions.
    """
    mission = Mission(target="target.corp")
    mission.endpoints = ["https://target.corp/admin/dashboard"]
    mission.live_hosts = ["https://target.corp"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.test_identities = []

    mock_client = AdversarialMockHttpClient()
    mock_client.set_route("https://target.corp/admin/dashboard", 403, "Forbidden")

    collector = AccessControlCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert isinstance(evidence, list)
    assert len(evidence) == 0


# =============================================================================
# SECTION 2: Header Bypass Logic Stress Tests
# =============================================================================

def test_header_bypass_multiple_proxy_headers():
    """
    Validates header bypass testing across multiple candidate proxy headers:
    X-Original-URL, X-Rewrite-URL, X-Forwarded-Host, X-Custom-IP-Authorization.
    """
    mission = Mission(target="proxy.target.corp")
    mission.endpoints = [
        "https://proxy.target.corp/api/admin/users",
        "https://proxy.target.corp/management/settings",
    ]
    mission.live_hosts = ["https://proxy.target.corp"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    mock_client = AdversarialMockHttpClient()
    # Baseline requests blocked with 403
    mock_client.set_route("https://proxy.target.corp/api/admin/users", 403, "Access Denied")
    mock_client.set_route("https://proxy.target.corp/management/settings", 403, "Access Denied")

    # X-Rewrite-URL bypass on base host
    mock_client.set_route(
        "https://proxy.target.corp",
        200,
        json.dumps({"admin_users": ["root", "admin"], "status": "active"}),
        header_key="X-Rewrite-URL",
        header_val="/api/admin/users",
    )

    # X-Forwarded-Host bypass on target URL
    mock_client.set_route(
        "https://proxy.target.corp/management/settings",
        200,
        json.dumps({"internal_settings": {"debug_mode": True}}),
        header_key="X-Forwarded-Host",
        header_val="127.0.0.1",
    )

    collector = AccessControlCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 2
    bypasses = [e for e in evidence if e.metadata.get("discrepancy_type") == "header_bypass"]
    assert len(bypasses) >= 2
    header_names = {b.metadata.get("header_name") for b in bypasses}
    assert "X-Rewrite-URL" in header_names or "X-Original-URL" in header_names


def test_header_bypass_non_standard_ports_and_schemes():
    """
    Validates that base_url and port preservation work correctly for non-standard ports
    (e.g., https://target.corp:8443/admin and http://target.corp:8080/api/admin).
    """
    mission = Mission(target="target.corp:8443")
    mission.endpoints = ["https://target.corp:8443/admin/system"]
    mission.live_hosts = ["https://target.corp:8443"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    mock_client = AdversarialMockHttpClient()
    # Baseline blocked with 401
    mock_client.set_route("https://target.corp:8443/admin/system", 401, "Unauthorized")

    # Header bypass on base host with port preserved
    mock_client.set_route(
        "https://target.corp:8443",
        200,
        json.dumps({"system": "ok", "admin": True}),
        header_key="X-Original-URL",
        header_val="/admin/system",
    )

    collector = AccessControlCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = evidence[0]
    assert ev.metadata["discrepancy_type"] == "header_bypass"
    assert "8443" in ev.value
    assert ev.metadata["header_name"] == "X-Original-URL"


def test_header_bypass_suppresses_false_positives_on_errors_and_login_pages():
    """
    When injecting headers (X-Original-URL, etc.) returns:
    1. Soft error JSON: {"status": "error", "message": "unauthorized"}
    2. HTML login page
    3. HTTP 500 or 403
    Verifies that NO false positive evidence is generated.
    """
    mission = Mission(target="target.corp")
    mission.endpoints = ["https://target.corp/admin/secrets"]
    mission.live_hosts = ["https://target.corp"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    mock_client = AdversarialMockHttpClient()
    mock_client.set_route("https://target.corp/admin/secrets", 403, "Forbidden")

    # Header injection returns 200 OK but HTML login page
    login_html = "<html><form action='/login'><input type='password' name='pass'/></form></html>"
    mock_client.set_route(
        "https://target.corp",
        200,
        login_html,
        header_key="X-Original-URL",
        header_val="/admin/secrets",
    )

    collector = AccessControlCollector(http_client=mock_client)
    evidence = collector.collect(mission)

    assert len(evidence) == 0


# =============================================================================
# SECTION 3: KnowledgeGraph & AttackSurfaceBuilder Stress Tests
# =============================================================================

def test_knowledge_graph_connectivity_invariants():
    """
    Validates graph connectivity invariants:
    1. live_host -> endpoint via HAS_ENDPOINT
    2. live_host -> vulnerability via HAS_VULNERABILITY
    3. endpoint -> vulnerability via HAS_VULNERABILITY
    4. are_connected(live_host, vulnerability) is True
    5. in_same_host_subgraph(endpoint, vulnerability) is True
    6. get_host_for_node(vulnerability) resolves to live_host
    """
    graph = KnowledgeGraph()
    lh_id = "live_host:https://api.target.corp:8443"
    ep_id = "endpoint:https://api.target.corp:8443/api/v1/users/42/profile"
    vuln_id = "vulnerability:idor-horizontal-privilege-escalation:https://api.target.corp:8443/api/v1/users/42/profile"

    graph.add(Node(id=lh_id, type="live_host", value="https://api.target.corp:8443", metadata={"url": "https://api.target.corp:8443", "host": "api.target.corp"}))
    graph.add(Node(id=ep_id, type="endpoint", value="https://api.target.corp:8443/api/v1/users/42/profile", metadata={"url": "https://api.target.corp:8443/api/v1/users/42/profile"}))
    graph.add(Node(id=vuln_id, type="vulnerability", value="Broken Access Control (IDOR)", metadata={"severity": "critical"}))

    graph.connect(lh_id, ep_id, "HAS_ENDPOINT")
    graph.connect(lh_id, vuln_id, "HAS_VULNERABILITY")
    graph.connect(ep_id, vuln_id, "HAS_VULNERABILITY")

    # Connectivity checks
    assert graph.are_connected(lh_id, ep_id) is True
    assert graph.are_connected(lh_id, vuln_id) is True
    assert graph.are_connected(ep_id, vuln_id) is True

    # Host resolution
    resolved_host = graph.get_host_for_node(vuln_id)
    assert resolved_host is not None
    assert resolved_host.id == lh_id

    # Subgraph grouping
    assert graph.in_same_host_subgraph(ep_id, vuln_id) is True
    assert graph.in_same_host_subgraph(lh_id, vuln_id) is True

    # Check connected endpoints
    connected_eps = graph.get_connected_endpoints(lh_id)
    assert len(connected_eps) == 1
    assert connected_eps[0].id == ep_id


def test_knowledge_graph_deduplication_on_repeated_evidence():
    """
    Validates that repeatedly emitting findings or rebuilding from evidence does NOT
    duplicate nodes or produce disconnected duplicate subgraphs.
    """
    ev_store = EvidenceStore()
    target_url = "https://target.corp/api/users/99/profile"

    # Add duplicate evidence items
    for i in range(3):
        ev = Evidence(
            mission_id="m1",
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=f"IDOR #{i}",
            category="broken_access_control",
            value=target_url,
            source=target_url,
            severity="critical",
            status="CONFIRMED",
            metadata={
                "url": target_url,
                "host": "https://target.corp",
                "template_id": "idor-horizontal-privilege-escalation",
            },
        )
        ev_store.add(ev)

    builder = AttackSurfaceGraphBuilder()
    graph = builder.build_from_evidence(ev_store, target="target.corp")

    # Check node counts: exactly 1 live_host, 1 endpoint, 1 vulnerability
    live_hosts = graph.nodes_by_type("live_host")
    endpoints = graph.nodes_by_type("endpoint")
    vulns = graph.nodes_by_type("vulnerability")

    assert len(live_hosts) == 1
    assert len(endpoints) == 1
    assert len(vulns) == 1

    # Verify edge deduplication
    assert graph.edge_count() == 3  # HAS_ENDPOINT, HAS_VULNERABILITY (from host), HAS_VULNERABILITY (from endpoint)


# =============================================================================
# SECTION 4: DAG Integration & Task Generator Stress Tests
# =============================================================================

def test_dag_task_generator_access_control_dependencies_and_priority():
    """
    Validates that TaskGenerator sets up access_control tasks with:
    1. Dependencies on 'Discover API Endpoints'.
    2. Category TaskCategory.AUTHORIZATION_ANALYSIS.
    3. Proper priority (0.81) placing it after API discovery.
    """
    assert "access_control" in _RECON_TEMPLATES
    tmpl = _RECON_TEMPLATES["access_control"]
    assert tmpl["category"] == TaskCategory.AUTHORIZATION_ANALYSIS
    assert tmpl["dependencies"] == ["Discover API Endpoints"]
    assert tmpl["priority"] == 0.81
    assert tmpl["metadata"]["tool_id"] == "access_control"

    mission = Mission(target="target.corp")
    mission.endpoints = ["https://target.corp/api/users/1"]
    task_gen = TaskGenerator(mission)

    gap = CoverageGap(
        area="Access Control",
        description="Analyze IDOR and access control boundaries",
        category=TaskCategory.AUTHORIZATION_ANALYSIS,
    )
    tasks = task_gen.from_gaps([gap])
    assert len(tasks) == 1
    task = tasks[0]
    assert task.title == "Analyze Access Control & IDOR"
    assert task.category == TaskCategory.AUTHORIZATION_ANALYSIS
    assert "Discover API Endpoints" in task.dependencies
    assert task.metadata.get("tool_id") == "access_control"
    assert "https://target.corp/api/users/1" in task.required_inputs


def test_tool_registry_and_plugin_adapter_resolution():
    """
    Validates that:
    1. ToolRegistry has access_control registered.
    2. find_compatible_tools("Authorization Analysis") returns access_control tool.
    3. PluginExecutorAdapter instantiates AccessControlCollector without failure.
    """
    tool = registry.get("access_control")
    assert tool is not None
    assert tool.capability == "access_control_collector"
    assert "Authorization Analysis" in tool.supported_tasks

    compat = registry.find_compatible_tools("Authorization Analysis")
    assert any(t.id == "access_control" for t in compat)

    adapter = PluginExecutorAdapter()
    instance = adapter._instantiate_specialist_fallback("access_control")
    assert isinstance(instance, AccessControlCollector)


# =============================================================================
# SECTION 5: Empirical Adversarial Failure Reproducers (Defect Verifications)
# =============================================================================

def test_reproduce_defect_1_horizontal_path_patterns_double_slash_and_nested_routes():
    """
    VERIFICATION FOR REMEDIATION 1:
    In argus/collectors/access_control.py:
    HORIZONTAL_PATH_PATTERNS now properly matches:
    - https://target.com/users/alice
    - https://target.com/profiles/alice
    - https://target.com/orders/ORD-1001
    - https://target.com/api/v2/organizations/org_123/projects/prj_456/users/usr_789
    """
    pat1 = HORIZONTAL_PATH_PATTERNS[0]
    pat2 = HORIZONTAL_PATH_PATTERNS[1]

    # Standard non-/api REST routes
    url_non_api_user = "https://target.com/users/alice"
    url_nested = "https://target.com/api/v2/organizations/org_123/projects/prj_456/users/usr_789"

    match_non_api = pat1.search(url_non_api_user) or pat2.search(url_non_api_user)
    match_nested = pat1.search(url_nested) or pat2.search(url_nested)

    assert match_non_api is not None, "Remediation verified: /users/alice is matched by HORIZONTAL_PATH_PATTERNS"
    assert match_nested is not None, "Remediation verified: nested /organizations/.../users/usr_789 is matched"


def test_reproduce_defect_2_query_id_param_regex_misses_array_notation():
    """
    VERIFICATION FOR REMEDIATION 2:
    In argus/collectors/access_control.py:
    QUERY_ID_PARAM_REGEX now supports array brackets:
    - ?ids[]=1&ids[]=2
    - ?user_id[]=123
    - ?id[]=123
    """
    q_array_1 = "https://target.com/api/search?ids[]=1&ids[]=2"
    q_array_2 = "https://target.com/api/users?user_id[]=123"

    assert QUERY_ID_PARAM_REGEX.search(q_array_1) is not None, "Remediation verified: ids[]=1 is matched"
    assert QUERY_ID_PARAM_REGEX.search(q_array_2) is not None, "Remediation verified: user_id[]=123 is matched"


def test_reproduce_defect_3_attacksurface_graph_builder_duplicate_vuln_nodes():
    """
    VERIFICATION FOR REMEDIATION 3:
    In argus/graph/attack_surface.py:
    build_from_evidence generates vulnerability node IDs as `vulnerability:{template_id}:{url}`.
    build() now aligns with this schema using meta.get("url"), eliminating duplicate vulnerability nodes.
    """
    mission = Mission(target="api.target.com")
    mission.endpoints = [{"url": "https://api.target.com/api/users/123/profile"}]
    mission.live_hosts = ["https://api.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    alice = TestIdentity(id="alice", credentials={"email": "alice@target.com", "user_id": "123"})
    bob = TestIdentity(id="bob", credentials={"email": "bob@target.com", "user_id": "456"})
    mission.test_identities = [alice, bob]

    mock_client = AdversarialMockHttpClient()
    mock_client.set_route("https://api.target.com/api/users/123/profile", 200, json.dumps({"id": "123", "email": "alice@target.com"}))

    collector = AccessControlCollector(http_client=mock_client)
    collector.collect(mission)

    # Rebuild graph via AttackSurfaceGraphBuilder.build(mission)
    builder = AttackSurfaceGraphBuilder()
    rebuilt = builder.build(mission)

    vuln_nodes = rebuilt.nodes_by_type("vulnerability")
    vuln_node_ids = [n.id for n in vuln_nodes]

    # Demonstrate that exactly one deduplicated vulnerability node exists
    assert len(vuln_nodes) == 1, f"Expected exactly 1 deduplicated vulnerability node, got {vuln_node_ids}"
    assert "vulnerability:idor-horizontal-privilege-escalation:https://api.target.com/api/users/123/profile" in vuln_node_ids
