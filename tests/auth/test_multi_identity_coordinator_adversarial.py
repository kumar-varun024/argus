"""
Adversarial and Stress Tests for MultiIdentitySessionCoordinator.
Validates session isolation under high concurrency, rapid cookie mutation,
header bleed prevention across 5+ identities, and lifecycle resilience.
"""
import concurrent.futures
import json
import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import pytest

from argus.http.coordinator import MultiIdentitySessionCoordinator, MultiIdentityComparison
from argus.http.client import AuthenticatedHttpClient, HttpResponse
from argus.models.test_identity import TestIdentity, AuthType
from argus.runtime.mission import Mission
from argus.runtime.manager import mission_manager


def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ConcurrencyBleedAuditHandler(BaseHTTPRequestHandler):
    """Adversarial HTTP handler that checks for cookie/header bleed on every incoming request."""

    def log_message(self, format, *args):
        pass  # Suppress standard logging to keep test output clean

    def do_GET(self):
        auth_hdr = self.headers.get("Authorization", "")
        cookie_hdr = self.headers.get("Cookie", "")
        custom_hdr = self.headers.get("X-Identity-Scope", "")

        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        step = qs.get("step", ["0"])[0]

        # Determine expected identity from query parameter or authorization header
        if "ident" in qs:
            expected_ident = qs["ident"][0]
        elif auth_hdr and "Bearer token_" in auth_hdr:
            expected_ident = auth_hdr.split("Bearer token_")[-1].strip()
        else:
            expected_ident = "unauth"

        # Parse cookies received in request
        cookies = {}
        if cookie_hdr:
            for item in cookie_hdr.split(";"):
                if "=" in item:
                    k, v = item.strip().split("=", 1)
                    cookies[k] = v

        # Store bleed errors if detected
        bleed_errors = []

        # 1. Cookie Bleed Check: No cookie belonging to another identity should ever be present
        for k, v in cookies.items():
            if k.startswith("sess_") and k != f"sess_{expected_ident}":
                bleed_errors.append(f"COOKIE_BLEED: {expected_ident} received foreign cookie {k}={v}")

        # 2. Header Bleed Check: Token must match expected identity exactly
        if expected_ident != "unauth":
            expected_token = f"token_{expected_ident}"
            if expected_token not in auth_hdr and auth_hdr != "":
                bleed_errors.append(f"HEADER_BLEED: {expected_ident} received unexpected auth header '{auth_hdr}'")
            if custom_hdr and custom_hdr != f"scope_{expected_ident}":
                bleed_errors.append(f"CUSTOM_HEADER_BLEED: {expected_ident} received foreign header '{custom_hdr}'")
        else:
            if auth_hdr:
                bleed_errors.append(f"UNAUTH_HEADER_BLEED: unauthenticated client received auth header '{auth_hdr}'")
            if cookie_hdr:
                for k, v in cookies.items():
                    if k.startswith("sess_"):
                        bleed_errors.append(f"UNAUTH_COOKIE_BLEED: unauthenticated client received cookie {k}={v}")

        # Send response and mutate cookie on every request
        status_code = 200 if not bleed_errors else 500
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")

        if expected_ident != "unauth":
            mutated_cookie_val = f"mutated_{expected_ident}_{step}_{time.time_ns()}"
            self.send_header("Set-Cookie", f"sess_{expected_ident}={mutated_cookie_val}; Path=/")

        self.end_headers()
        resp_data = {
            "status": "ok" if not bleed_errors else "bleed_detected",
            "ident": expected_ident,
            "step": step,
            "bleed_errors": bleed_errors,
        }
        self.wfile.write(json.dumps(resp_data).encode("utf-8"))


@pytest.fixture(scope="module")
def stress_http_server():
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), ConcurrencyBleedAuditHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def stress_mission():
    mission = Mission(name="Adversarial Stress Mission", target="127.0.0.1")
    mission.scope = ["127.0.0.1"]
    mission_manager._active_missions[mission.id] = mission
    return mission


def test_concurrent_session_isolation_across_multiple_identities(stress_http_server, stress_mission):
    """
    Adversarial Challenge 1:
    Spawn 5 distinct authenticated identities + unauthenticated identity.
    Execute 180 rapid concurrent requests in parallel across a thread pool with mutating cookies.
    Verify 0 cookie or header bleed incidents across all threads.
    """
    identities = [
        TestIdentity(id="alice", name="Alice", role="user", auth_type=AuthType.BEARER, token="token_alice", headers={"X-Identity-Scope": "scope_alice"}),
        TestIdentity(id="bob", name="Bob", role="user", auth_type=AuthType.BEARER, token="token_bob", headers={"X-Identity-Scope": "scope_bob"}),
        TestIdentity(id="charlie", name="Charlie", role="user", auth_type=AuthType.BEARER, token="token_charlie", headers={"X-Identity-Scope": "scope_charlie"}),
        TestIdentity(id="dave", name="Dave", role="user", auth_type=AuthType.BEARER, token="token_dave", headers={"X-Identity-Scope": "scope_dave"}),
        TestIdentity(id="eve_admin", name="Eve Admin", role="admin", auth_type=AuthType.BEARER, token="token_eve_admin", headers={"X-Identity-Scope": "scope_eve_admin"}),
    ]

    coord = MultiIdentitySessionCoordinator()
    bleed_reports = []

    def make_request(ident, step_num):
        ident_name = ident.id if ident else "unauth"
        url = f"{stress_http_server}/api/resource?ident={ident_name}&step={step_num}"
        resp = coord.execute_as(ident, stress_mission, "GET", url)
        if resp.status_code != 200:
            bleed_reports.append(f"HTTP {resp.status_code}: {resp.raw_body}")
        else:
            try:
                data = json.loads(resp.raw_body)
                if data.get("bleed_errors"):
                    bleed_reports.extend(data["bleed_errors"])
            except Exception as e:
                bleed_reports.append(f"JSON error: {e}")

    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        for step in range(30):
            for ident in identities:
                futures.append(executor.submit(make_request, ident, step))
            # Also execute unauthenticated in parallel
            futures.append(executor.submit(make_request, None, step))

    for f in concurrent.futures.as_completed(futures):
        f.result()

    coord.close_all()

    assert len(futures) == 180
    assert len(bleed_reports) == 0, f"Detected bleed violations: {bleed_reports}"


def test_coordinator_lifecycle_and_unauthenticated_client_isolation(stress_http_server, stress_mission):
    """
    Adversarial Challenge 2:
    Verify unauthenticated client behavior when reused or recreated across multiple cycles.
    Ensure that unauthenticated requests never store or forward cookies.
    """
    with MultiIdentitySessionCoordinator() as coord:
        ident_a = TestIdentity(id="user_a", auth_type=AuthType.BEARER, token="token_user_a")
        
        # User A sets a cookie
        resp_a = coord.execute_as(ident_a, stress_mission, "GET", f"{stress_http_server}/api/resource?ident=user_a&step=1")
        assert resp_a.status_code == 200

        # Unauthenticated request immediately following User A
        resp_unauth = coord.execute_as(None, stress_mission, "GET", f"{stress_http_server}/api/resource?ident=unauth&step=1")
        assert resp_unauth.status_code == 200
        unauth_data = json.loads(resp_unauth.raw_body)
        assert unauth_data["bleed_errors"] == []

        # Get explicit unauth client and make request
        unauth_client = coord.get_unauthenticated_client()
        resp_direct = unauth_client.get(stress_mission, f"{stress_http_server}/api/resource?ident=unauth&step=2")
        assert resp_direct.status_code == 200
        direct_data = json.loads(resp_direct.raw_body)
        assert direct_data["bleed_errors"] == []


def test_execute_across_identities_concurrency(stress_http_server, stress_mission):
    """
    Adversarial Challenge 3:
    Verify execute_across_identities returns distinct responses for all 5 identities without crosstalk.
    """
    identities = [
        TestIdentity(id=f"user_{i}", auth_type=AuthType.BEARER, token=f"token_user_{i}")
        for i in range(5)
    ]
    stress_mission.test_identities = identities

    with MultiIdentitySessionCoordinator() as coord:
        results = coord.execute_across_identities(
            stress_mission,
            "GET",
            f"{stress_http_server}/api/resource",
        )
        assert len(results) == 5
        for ident in identities:
            assert ident.id in results
            resp = results[ident.id]
            assert resp.status_code == 200
            data = json.loads(resp.raw_body)
            assert data["ident"] == ident.id
            assert data["bleed_errors"] == []
