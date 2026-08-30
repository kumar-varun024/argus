"""
Unit tests for MultiIdentitySessionCoordinator and MultiIdentityComparison.
Validates session and cookie isolation, auth header injection, differential request replay,
response comparison, automated authentication, and lifecycle resource cleanup.
"""
import json
import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import pytest

from argus.http.coordinator import MultiIdentitySessionCoordinator, MultiIdentityComparison
from argus.http.client import AuthenticatedHttpClient
from argus.models.test_identity import TestIdentity, AuthType
from argus.runtime.mission import Mission
from argus.runtime.manager import mission_manager


def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class MultiIdentityMockHttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth_hdr = self.headers.get("Authorization", "")
        cookie_hdr = self.headers.get("Cookie", "")
        api_key_hdr = self.headers.get("X-API-Key", "")

        if self.path.startswith("/set-cookie"):
            # Set a cookie specific to who called it or path query
            cookie_val = "cookie_default"
            if "val=" in self.path:
                cookie_val = self.path.split("val=")[-1]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", f"session_id={cookie_val}; Path=/")
            self.end_headers()
            resp = {"status": "ok", "cookie_set": cookie_val}
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/echo":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "auth_header": auth_hdr,
                "cookie_header": cookie_hdr,
                "api_key_header": api_key_hdr,
                "path": self.path,
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        if self.path == "/api/user/profile":
            if "Bearer token_alice" in auth_hdr or "alice_session" in cookie_hdr:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                resp = {"user_id": "alice_123", "username": "alice", "email": "alice@example.com", "role": "user"}
                self.wfile.write(json.dumps(resp).encode("utf-8"))
                return
            elif "Bearer token_bob" in auth_hdr or "bob_session" in cookie_hdr:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                resp = {"user_id": "bob_456", "username": "bob", "email": "bob@example.com", "role": "user"}
                self.wfile.write(json.dumps(resp).encode("utf-8"))
                return
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Unauthorized")
                return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {"message": "root OK"}
        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        if self.path == "/auth/login":
            data = json.loads(body) if body else {}
            username = data.get("username")
            if username == "alice":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "session=alice_logged_in_cookie; Path=/")
                self.end_headers()
                resp = {"token": "alice_jwt_token", "user": "alice"}
                self.wfile.write(json.dumps(resp).encode("utf-8"))
                return
            elif username == "bob":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "session=bob_logged_in_cookie; Path=/")
                self.end_headers()
                resp = {"token": "bob_jwt_token", "user": "bob"}
                self.wfile.write(json.dumps(resp).encode("utf-8"))
                return
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Invalid credentials")
                return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"POST ok")


@pytest.fixture(scope="module")
def multi_id_server():
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), MultiIdentityMockHttpHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.fixture
def multi_id_mission():
    mission = Mission(name="Multi-ID Mission", target="127.0.0.1")
    mission.scope = ["127.0.0.1"]
    mission_manager._active_missions[mission.id] = mission
    return mission


def test_coordinator_initialization_and_lazy_client_creation(multi_id_server, multi_id_mission):
    coord = MultiIdentitySessionCoordinator()
    alice = TestIdentity(name="Alice", role="user", auth_type=AuthType.BEARER, token="token_alice")
    bob = TestIdentity(name="Bob", role="user", auth_type=AuthType.BEARER, token="token_bob")

    client_alice = coord.get_client_for_identity(alice)
    assert isinstance(client_alice, AuthenticatedHttpClient)
    assert client_alice.identity == alice

    client_bob = coord.get_client_for_identity(bob)
    assert isinstance(client_bob, AuthenticatedHttpClient)
    assert client_bob.identity == bob
    assert client_alice is not client_bob

    # Cached
    assert coord.get_client_for_identity(alice) is client_alice
    coord.close_all()


def test_coordinator_cookie_jar_isolation_between_identities(multi_id_server, multi_id_mission):
    """Verifies that cookie state is strictly isolated: cookies set on Identity A never bleed into Identity B."""
    alice = TestIdentity(name="Alice", role="user")
    bob = TestIdentity(name="Bob", role="user")

    with MultiIdentitySessionCoordinator() as coord:
        # Alice requests set-cookie with val=alice_cookie_123
        resp_alice1 = coord.execute_as(alice, multi_id_mission, "GET", f"{multi_id_server}/set-cookie?val=alice_cookie_123")
        assert resp_alice1.success is True
        assert alice.cookies.get("session_id") == "alice_cookie_123"

        # Bob requests set-cookie with val=bob_cookie_456
        resp_bob1 = coord.execute_as(bob, multi_id_mission, "GET", f"{multi_id_server}/set-cookie?val=bob_cookie_456")
        assert resp_bob1.success is True
        assert bob.cookies.get("session_id") == "bob_cookie_456"

        # Alice verifies only her cookie is sent
        resp_alice_echo = coord.execute_as(alice, multi_id_mission, "GET", f"{multi_id_server}/echo")
        assert "session_id=alice_cookie_123" in resp_alice_echo.body
        assert "bob_cookie_456" not in resp_alice_echo.body

        # Bob verifies only his cookie is sent
        resp_bob_echo = coord.execute_as(bob, multi_id_mission, "GET", f"{multi_id_server}/echo")
        assert "session_id=bob_cookie_456" in resp_bob_echo.body
        assert "alice_cookie_123" not in resp_bob_echo.body

        # Unauthenticated client has NO cookies
        resp_unauth = coord.execute_as(None, multi_id_mission, "GET", f"{multi_id_server}/echo")
        data = json.loads(resp_unauth.body)
        assert not data["cookie_header"]


def test_coordinator_distinct_auth_headers_injection(multi_id_server, multi_id_mission):
    alice = TestIdentity(name="Alice", role="user", auth_type=AuthType.BEARER, token="token_alice")
    bob = TestIdentity(name="Bob", role="user", auth_type=AuthType.BEARER, token="token_bob")
    admin = TestIdentity(name="Admin", role="admin", auth_type=AuthType.API_KEY, credentials={"api_key": "admin_key_999"})

    with MultiIdentitySessionCoordinator() as coord:
        r_alice = coord.execute_as(alice, multi_id_mission, "GET", f"{multi_id_server}/echo")
        data_a = json.loads(r_alice.body)
        assert data_a["auth_header"] == "Bearer token_alice"

        r_bob = coord.execute_as(bob, multi_id_mission, "GET", f"{multi_id_server}/echo")
        data_b = json.loads(r_bob.body)
        assert data_b["auth_header"] == "Bearer token_bob"

        r_admin = coord.execute_as(admin, multi_id_mission, "GET", f"{multi_id_server}/echo")
        data_adm = json.loads(r_admin.raw_body or r_admin.body)
        assert data_adm["api_key_header"] == "admin_key_999"



def test_coordinator_execute_across_identities(multi_id_server, multi_id_mission):
    alice = TestIdentity(name="Alice", role="user", auth_type=AuthType.BEARER, token="token_alice")
    bob = TestIdentity(name="Bob", role="user", auth_type=AuthType.BEARER, token="token_bob")
    multi_id_mission.test_identities = [alice, bob]

    with MultiIdentitySessionCoordinator() as coord:
        results = coord.execute_across_identities(multi_id_mission, "GET", f"{multi_id_server}/api/user/profile")
        assert len(results) == 2
        assert alice.id in results
        assert bob.id in results

        resp_a = results[alice.id]
        resp_b = results[bob.id]
        assert resp_a.status_code == 200
        assert resp_b.status_code == 200

        data_a = json.loads(resp_a.body)
        data_b = json.loads(resp_b.body)
        assert data_a["username"] == "alice"
        assert data_b["username"] == "bob"


def test_coordinator_execute_comparison_structured_metrics(multi_id_server, multi_id_mission):
    alice = TestIdentity(name="Alice", role="user", auth_type=AuthType.BEARER, token="token_alice")
    bob = TestIdentity(name="Bob", role="user", auth_type=AuthType.BEARER, token="token_bob")

    with MultiIdentitySessionCoordinator() as coord:
        # Same endpoint returning different identity profile
        comparison = coord.execute_comparison(
            multi_id_mission,
            "GET",
            f"{multi_id_server}/api/user/profile",
            primary_identity=alice,
            secondary_identity=bob,
        )

        assert isinstance(comparison, MultiIdentityComparison)
        assert comparison.primary_identity_id == alice.id
        assert comparison.secondary_identity_id == bob.id
        assert comparison.status_match is True
        assert comparison.primary_response.status_code == 200
        assert comparison.secondary_response.status_code == 200
        assert comparison.body_match is False
        assert 0.0 < comparison.body_similarity < 1.0


def test_coordinator_authenticate_all(multi_id_server, multi_id_mission):
    alice = TestIdentity(
        name="Alice",
        role="user",
        login_url=f"{multi_id_server}/auth/login",
        login_payload={"username": "alice", "password": "password"},
        login_type="json",
    )
    bob = TestIdentity(
        name="Bob",
        role="user",
        login_url=f"{multi_id_server}/auth/login",
        login_payload={"username": "bob", "password": "password"},
        login_type="json",
    )
    multi_id_mission.test_identities = [alice, bob]

    with MultiIdentitySessionCoordinator() as coord:
        login_results = coord.authenticate_all(multi_id_mission)
        assert len(login_results) == 2
        assert login_results[alice.id].status_code == 200
        assert login_results[bob.id].status_code == 200

        assert alice.token == "alice_jwt_token"
        assert alice.cookies.get("session") == "alice_logged_in_cookie"

        assert bob.token == "bob_jwt_token"
        assert bob.cookies.get("session") == "bob_logged_in_cookie"


def test_coordinator_fallback_when_empty_identities(multi_id_server, multi_id_mission):
    multi_id_mission.test_identities = []
    with MultiIdentitySessionCoordinator() as coord:
        results = coord.execute_across_identities(multi_id_mission, "GET", f"{multi_id_server}/")
        assert "unauthenticated" in results
        assert results["unauthenticated"].status_code == 200
