"""
Tests for AccessControlCollector, ResponseDiscrepancyAnalyzer, and Attack Surface Graph integration.
Validates Horizontal IDOR detection, Vertical Privilege Escalation, Header Bypasses,
False Positive Suppression, KnowledgeGraph node and edge wiring, and AttackSurfaceGraphBuilder reconstruction.
"""
import json
from typing import Optional, Any, Dict, List, Set, Tuple
import pytest


from argus.analyzers.response_discrepancy import ResponseDiscrepancyAnalyzer, DiscrepancyVerdict
from argus.collectors.access_control import AccessControlCollector
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.models.test_identity import TestIdentity, AuthType
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission


class MockIDORHttpClient:
    """Configurable HTTP client for testing access control scenarios."""

    def __init__(self):
        self.routes = {}

    def set_route(self, url: str, status_code: int, body: str, identity_id: Optional[str] = None, header_key: Optional[str] = None, header_val: Optional[str] = None):
        key = (url, identity_id, header_key, header_val)
        self.routes[key] = (status_code, body)

    def execute_as(self, identity: Optional[TestIdentity], mission: Any, method: str, url: str, headers: Optional[dict] = None, **kwargs) -> HttpResponse:
        ident_id = identity.id if identity else None

        # Check for specific header match first
        if headers:
            for hk, hv in headers.items():
                if (url, ident_id, hk, hv) in self.routes:
                    status, body = self.routes[(url, ident_id, hk, hv)]
                    return HttpResponse(success=True, status_code=status, raw_body=body, body=body, url=url)
                if (url, None, hk, hv) in self.routes:
                    status, body = self.routes[(url, None, hk, hv)]
                    return HttpResponse(success=True, status_code=status, raw_body=body, body=body, url=url)

        # Check identity-specific route
        if (url, ident_id, None, None) in self.routes:
            status, body = self.routes[(url, ident_id, None, None)]
            return HttpResponse(success=True, status_code=status, raw_body=body, body=body, url=url)

        # Check generic route
        if (url, None, None, None) in self.routes:
            status, body = self.routes[(url, None, None, None)]
            return HttpResponse(success=True, status_code=status, raw_body=body, body=body, url=url)

        return HttpResponse(success=False, status_code=404, error="Not Found", url=url)


def test_horizontal_idor_true_positive_generates_critical_evidence():
    """
    User A (Alice) owns /api/users/123/profile.
    User B (Bob) replays the request and receives Alice's profile data.
    Verifies that AccessControlCollector emits critical Evidence and updates mission state.
    """
    mission = Mission(target="api.target.com")
    mission.endpoints = [{"url": "https://api.target.com/api/users/123/profile"}]
    mission.live_hosts = ["https://api.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    alice = TestIdentity(
        id="user_alice_123",
        name="Alice Smith",
        role="user",
        auth_type=AuthType.BEARER,
        token="tok_alice",
        credentials={"email": "alice@target.com", "user_id": "123"},
    )
    bob = TestIdentity(
        id="user_bob_456",
        name="Bob Jones",
        role="user",
        auth_type=AuthType.BEARER,
        token="tok_bob",
        credentials={"email": "bob@target.com", "user_id": "456"},
    )
    mission.test_identities = [alice, bob]

    mock_client = MockIDORHttpClient()
    alice_profile_json = json.dumps({
        "id": "123",
        "name": "Alice Smith",
        "email": "alice@target.com",
        "ssn": "000-12-3456",
        "credit_card": "4111-2222-3333-4444",
    })

    # Both Alice and Bob receive Alice's profile JSON when calling /api/users/123/profile (IDOR!)
    mock_client.set_route("https://api.target.com/api/users/123/profile", 200, alice_profile_json, identity_id=alice.id)
    mock_client.set_route("https://api.target.com/api/users/123/profile", 200, alice_profile_json, identity_id=bob.id)

    collector = AccessControlCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) == 1
    ev = evidence_list[0]
    assert ev.category == "broken_access_control"
    assert ev.severity == "critical"
    assert ev.status == "CONFIRMED"
    assert ev.confidence >= 0.90
    assert "user_bob_456" in ev.description or "123" in ev.description
    assert ev.metadata["discrepancy_type"] == "horizontal_idor"

    # Verify mission state
    assert len(mission.vulnerabilities) == 1
    assert "Broken Access Control" in mission.vulnerabilities[0]["name"]

    # Verify KnowledgeGraph wiring
    assert graph.get("endpoint:https://api.target.com/api/users/123/profile") is not None
    vuln_node = graph.get("vulnerability:idor-horizontal-privilege-escalation:https://api.target.com/api/users/123/profile")
    assert vuln_node is not None
    assert graph.are_connected("live_host:https://api.target.com", "endpoint:https://api.target.com/api/users/123/profile")
    assert graph.are_connected("endpoint:https://api.target.com/api/users/123/profile", vuln_node.id)


def test_horizontal_idor_false_positive_suppression_on_403():
    """
    User A accesses /api/users/123/profile successfully (200 OK).
    User B attempts access and is properly rejected with 403 Forbidden.
    Verifies that NO evidence or vulnerability is emitted.
    """
    mission = Mission(target="api.target.com")
    mission.endpoints = [{"url": "https://api.target.com/api/users/123/profile"}]
    mission.live_hosts = ["https://api.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    alice = TestIdentity(id="user_alice", name="Alice", role="user", credentials={"email": "alice@target.com"})
    bob = TestIdentity(id="user_bob", name="Bob", role="user", credentials={"email": "bob@target.com"})
    mission.test_identities = [alice, bob]

    mock_client = MockIDORHttpClient()
    mock_client.set_route("https://api.target.com/api/users/123/profile", 200, '{"id":"123","email":"alice@target.com"}', identity_id=alice.id)
    mock_client.set_route("https://api.target.com/api/users/123/profile", 403, '{"error":"Access Denied"}', identity_id=bob.id)

    collector = AccessControlCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) == 0
    assert len(mission.vulnerabilities) == 0


def test_vertical_privilege_escalation_true_positive():
    """
    Standard unprivileged user accesses administrative endpoint /admin/dashboard.
    Server returns 200 OK with sensitive admin panel content.
    Verifies that vertical privilege escalation is detected with critical severity.
    """
    mission = Mission(target="target.com")
    mission.endpoints = ["https://target.com/admin/dashboard"]
    mission.live_hosts = ["https://target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    admin = TestIdentity(id="admin_user", name="Admin", role="admin")
    standard_user = TestIdentity(id="standard_user", name="Regular User", role="user")
    mission.test_identities = [standard_user, admin]

    mock_client = MockIDORHttpClient()
    admin_panel_content = """
    <html>
        <head><title>Admin Control Center</title></head>
        <body>
            <h1>System Administration</h1>
            <div>Users Management, Role Configuration, API Keys</div>
        </body>
    </html>
    """
    mock_client.set_route("https://target.com/admin/dashboard", 200, admin_panel_content, identity_id=admin.id)
    mock_client.set_route("https://target.com/admin/dashboard", 200, admin_panel_content, identity_id=standard_user.id)

    collector = AccessControlCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) >= 1
    vert_ev = next(e for e in evidence_list if e.metadata["discrepancy_type"] == "vertical_privilege_escalation")
    assert vert_ev.category == "broken_access_control"
    assert vert_ev.severity == "critical"
    assert "https://target.com/admin/dashboard" in vert_ev.value

    assert len(mission.vulnerabilities) >= 1
    assert graph.get("endpoint:https://target.com/admin/dashboard") is not None


def test_vertical_privilege_escalation_suppression_on_403_or_login():
    """
    Standard unprivileged user receives 401 Unauthorized or login page on /admin/dashboard.
    Verifies NO false positive evidence is emitted.
    """
    mission = Mission(target="target.com")
    mission.endpoints = ["https://target.com/admin/dashboard"]
    mission.live_hosts = ["https://target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    user = TestIdentity(id="user1", role="user")
    mission.test_identities = [user]

    mock_client = MockIDORHttpClient()
    mock_client.set_route("https://target.com/admin/dashboard", 403, "<html><body>Forbidden</body></html>")

    collector = AccessControlCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) == 0


def test_reverse_proxy_header_bypass_true_positive():
    """
    Endpoint /admin/users returns 403 Forbidden by default.
    Injecting header X-Original-URL: /admin/users to base URL returns 200 OK with users list.
    Verifies that header bypass is flagged.
    """
    mission = Mission(target="target.com")
    mission.endpoints = ["https://target.com/admin/users"]
    mission.live_hosts = ["https://target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    mock_client = MockIDORHttpClient()
    # Baseline returns 403
    mock_client.set_route("https://target.com/admin/users", 403, "Access Forbidden")
    # Base URL with X-Original-URL header returns 200 with admin user list
    mock_client.set_route(
        "https://target.com",
        200,
        json.dumps({"users": ["admin@target.com", "root@target.com"], "count": 2}),
        header_key="X-Original-URL",
        header_val="/admin/users",
    )

    collector = AccessControlCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) >= 1
    bypass_ev = next(e for e in evidence_list if e.metadata["discrepancy_type"] == "header_bypass")
    assert bypass_ev.category == "broken_access_control"
    assert bypass_ev.severity == "high"
    assert bypass_ev.metadata["header_name"] == "X-Original-URL"


def test_response_discrepancy_analyzer_filters_soft_errors_and_login_pages():
    """Validates that ResponseDiscrepancyAnalyzer accurately detects soft-errors and login forms."""
    analyzer = ResponseDiscrepancyAnalyzer()

    # 1. Soft-403 with 200 OK status in JSON
    soft_err_resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body='{"status": "error", "message": "You do not have permission to view this resource"}',
        body='{"status": "error", "message": "You do not have permission to view this resource"}',
    )
    assert analyzer.is_error_or_login_response(soft_err_resp) is True

    # 2. HTML Login page with 200 OK status
    login_resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body='<html><body><form action="/login" method="post"><input type="password" name="p"/></form></body></html>',
        body='<html><body><form action="/login" method="post"><input type="password" name="p"/></form></body></html>',
    )
    assert analyzer.is_error_or_login_response(login_resp) is True

    # 3. Empty body
    empty_resp = HttpResponse(success=True, status_code=200, raw_body="", body="")
    assert analyzer.is_error_or_login_response(empty_resp) is True

    # 4. Valid business payload
    valid_resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body='{"id": "123", "username": "alice", "account_balance": 50000.00}',
        body='{"id": "123", "username": "alice", "account_balance": 50000.00}',
    )
    assert analyzer.is_error_or_login_response(valid_resp) is False


def test_attack_surface_graph_builder_reconstructs_broken_access_control():
    """Validates that AttackSurfaceGraphBuilder correctly ingests broken_access_control Evidence into the graph."""
    ev_store = EvidenceStore()
    ev = Evidence(
        mission_id="m123",
        source_type="LOG",
        created_by="SYSTEM_GENERATED",
        title="Broken Access Control (IDOR): https://target.corp/api/orders/999",
        description="IDOR detected on order endpoint",
        category="broken_access_control",
        value="https://target.corp/api/orders/999",
        source="https://target.corp/api/orders/999",
        severity="critical",
        status="CONFIRMED",
        metadata={
            "url": "https://target.corp/api/orders/999",
            "host": "https://target.corp",
            "template_id": "idor-order-leak",
            "category": "broken_access_control",
            "severity": "critical",
        },
    )
    ev_store.add(ev)

    builder = AttackSurfaceGraphBuilder()
    graph = builder.build_from_evidence(ev_store, target="target.corp")

    assert graph.get("live_host:https://target.corp") is not None
    assert graph.get("endpoint:https://target.corp/api/orders/999") is not None
    assert graph.get("vulnerability:idor-order-leak:https://target.corp/api/orders/999") is not None

    assert graph.are_connected(
        "live_host:https://target.corp",
        "endpoint:https://target.corp/api/orders/999",
    )
    assert graph.are_connected(
        "endpoint:https://target.corp/api/orders/999",
        "vulnerability:idor-order-leak:https://target.corp/api/orders/999",
    )
    assert graph.are_connected(
        "live_host:https://target.corp",
        "vulnerability:idor-order-leak:https://target.corp/api/orders/999",
    )


def test_controlled_mission_unpacking_in_collector():
    """Verifies that ControlledMission wrapping does not impede AccessControlCollector."""
    raw_mission = Mission(target="api.test.com")
    raw_mission.endpoints = ["https://api.test.com/api/users/99/profile"]
    raw_mission.live_hosts = ["https://api.test.com"]
    raw_mission.evidence = EvidenceStore()
    raw_mission.vulnerabilities = []
    raw_mission.attack_surface_graph = KnowledgeGraph()

    user_a = TestIdentity(id="uA", credentials={"email": "a@test.com"})
    user_b = TestIdentity(id="uB", credentials={"email": "b@test.com"})
    raw_mission.test_identities = [user_a, user_b]

    mock_client = MockIDORHttpClient()
    mock_client.set_route(
        "https://api.test.com/api/users/99/profile",
        200,
        '{"id": "99", "email": "a@test.com", "secret": "leaked"}',
    )

    collector = AccessControlCollector(http_client=mock_client)
    controlled_mission = ControlledMission(raw_mission)

    # Execute via execute() with controlled mission
    evidence_list = collector.execute(controlled_mission)
    assert len(evidence_list) == 1
    assert evidence_list[0].category == "broken_access_control"
    assert len(raw_mission.vulnerabilities) == 1


def test_remediation_horizontal_path_patterns_non_api_and_nested():
    """Validates that non-/api routes and deeply nested routes are identified and tested."""
    mission = Mission(target="target.com")
    mission.endpoints = [
        "https://target.com/users/alice",
        "https://target.com/profiles/bob",
        "https://target.com/orders/ORD-1001",
        "https://target.com/api/v2/organizations/org_123/projects/prj_456/users/usr_789",
    ]
    mission.live_hosts = ["https://target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    alice = TestIdentity(id="usr_789", name="Alice", credentials={"email": "alice@target.com", "user_id": "usr_789"})
    attacker = TestIdentity(id="usr_attacker", name="Attacker", role="user")
    mission.test_identities = [alice, attacker]

    mock_client = MockIDORHttpClient()
    nested_url = "https://target.com/api/v2/organizations/org_123/projects/prj_456/users/usr_789"
    mock_client.set_route(nested_url, 200, json.dumps({"user_id": "usr_789", "email": "alice@target.com"}))

    collector = AccessControlCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert any(e.value == nested_url for e in evidence_list)


def test_remediation_query_id_array_brackets():
    """Validates that query parameters with array brackets (?ids[]=1) are identified and tested."""
    mission = Mission(target="target.com")
    array_url = "https://target.com/api/items?ids[]=1001"
    mission.endpoints = [array_url]
    mission.live_hosts = ["https://target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    owner = TestIdentity(id="u1001", credentials={"email": "owner@target.com", "item_id": "1001"})
    attacker = TestIdentity(id="u2002", role="user")
    mission.test_identities = [owner, attacker]

    mock_client = MockIDORHttpClient()
    mock_client.set_route(array_url, 200, json.dumps({"item_id": "1001", "owner": "owner@target.com"}))

    collector = AccessControlCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) == 1
    assert evidence_list[0].value == array_url


def test_remediation_unicode_json_escaped_leakage():
    """Validates that Unicode-escaped JSON responses are correctly identified as IDOR leaks."""
    mission = Mission(target="target.com")
    url = "https://target.com/api/users/u_international/profile"
    mission.endpoints = [url]
    mission.live_hosts = ["https://target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    victim = TestIdentity(id="u_international", name="René Müller", credentials={"email": "rene.müller@corp.de"})
    attacker = TestIdentity(id="u_attacker", role="user")
    mission.test_identities = [victim, attacker]

    # JSON with \u00e9 and \u00fc escape sequences
    escaped_body = json.dumps({"name": "René Müller", "email": "rene.müller@corp.de"}, ensure_ascii=True)

    mock_client = MockIDORHttpClient()
    mock_client.set_route(url, 200, escaped_body)

    collector = AccessControlCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) == 1
    assert evidence_list[0].value == url
    assert "rene.müller@corp.de" in str(evidence_list[0].metadata.get("leaked_data", {}))

