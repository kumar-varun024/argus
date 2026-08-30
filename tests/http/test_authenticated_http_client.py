import pytest
import threading
import json
import time
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch, MagicMock

from argus.runtime.mission import Mission
from argus.runtime.manager import mission_manager
from argus.authorization.scope import ScopeState
from argus.models.test_identity import TestIdentity, AuthType
from argus.http.client import AuthenticatedHttpClient, HttpResponse


def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class MockAuthHttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/timeout":
            time.sleep(0.5)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"timeout done")
            return

        if self.path == "/protected":
            auth_hdr = self.headers.get("Authorization", "")
            cookie_hdr = self.headers.get("Cookie", "")
            api_key_hdr = self.headers.get("X-API-Key", "")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "auth_header": auth_hdr,
                "cookie_header": cookie_hdr,
                "api_key_header": api_key_hdr,
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "session_token=valid_cookie_12345; Path=/")
        self.end_headers()
        resp = {
            "message": "GET ok",
            "headers": {k: v for k, v in self.headers.items()},
        }
        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        if self.path == "/login/json":
            data = json.loads(body) if body else {}
            if data.get("username") == "admin" and data.get("password") == "pass":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "jwt_session=cookie_token_999; Path=/")
                self.end_headers()
                resp = {"token": "jwt_access_token_xyz", "user": "admin"}
                self.wfile.write(json.dumps(resp).encode("utf-8"))
                return
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Unauthorized")
                return

        if self.path == "/login/form":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "form_session=form_cookie_777; Path=/")
            self.end_headers()
            resp = {"token": "form_token_123", "body": body}
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {"message": "POST ok", "body": body}
        self.wfile.write(json.dumps(resp).encode("utf-8"))


@pytest.fixture(scope="module")
def mock_auth_server():
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), MockAuthHttpHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.fixture
def auth_mission():
    mission = Mission(name="Auth Test Mission", target="127.0.0.1")
    mission.scope = ["127.0.0.1"]
    mission_manager._active_missions[mission.id] = mission
    return mission


def test_authenticated_client_in_scope_success(mock_auth_server, auth_mission):
    with AuthenticatedHttpClient() as client:
        resp = client.get(auth_mission, f"{mock_auth_server}/")
        assert resp.success is True
        assert resp.status_code == 200
        assert resp.scope_decision.decision == ScopeState.IN_SCOPE


def test_authenticated_client_out_of_scope_blocks_credential_transmission(mock_auth_server, auth_mission):
    auth_mission.scope = ["company.com"]  # 127.0.0.1 is now out of scope
    ident = TestIdentity(
        name="Secret Admin",
        auth_type=AuthType.BEARER,
        token="very_secret_token_123",
    )
    with AuthenticatedHttpClient(identity=ident) as client:
        resp = client.get(auth_mission, f"{mock_auth_server}/protected")
        assert resp.success is False
        assert "Blocked by scope" in resp.error
        assert resp.scope_decision.decision == ScopeState.OUT_OF_SCOPE


def test_authenticated_client_bearer_token_injection(mock_auth_server, auth_mission):
    ident = TestIdentity(
        name="Bearer User",
        auth_type=AuthType.BEARER,
        token="token_abc_123",
    )
    with AuthenticatedHttpClient(identity=ident) as client:
        resp = client.get(auth_mission, f"{mock_auth_server}/protected")
        assert resp.success is True
        data = json.loads(resp.body)
        assert data["auth_header"] == "Bearer token_abc_123"


def test_authenticated_client_basic_auth_injection(mock_auth_server, auth_mission):
    ident = TestIdentity(
        name="Basic User",
        auth_type=AuthType.BASIC,
        credentials={"username": "root", "password": "toorpassword"},
    )
    with AuthenticatedHttpClient(identity=ident) as client:
        resp = client.get(auth_mission, f"{mock_auth_server}/protected")
        assert resp.success is True
        data = json.loads(resp.body)
        assert data["auth_header"].startswith("Basic ")


def test_authenticated_client_api_key_injection(mock_auth_server, auth_mission):
    ident = TestIdentity(
        name="API User",
        auth_type=AuthType.API_KEY,
        credentials={"api_key": "custom_api_key_val", "key_header": "X-API-Key"},
    )
    with AuthenticatedHttpClient(identity=ident) as client:
        resp = client.get(auth_mission, f"{mock_auth_server}/protected")
        assert resp.success is True
        data = json.loads(resp.raw_body or resp.body)
        assert data["api_key_header"] == "custom_api_key_val"


def test_authenticated_client_cookie_injection_and_persistence(mock_auth_server, auth_mission):
    ident = TestIdentity(
        name="Cookie User",
        auth_type=AuthType.COOKIE,
        cookies={"user_session": "sess_9988"},
    )
    with AuthenticatedHttpClient(identity=ident) as client:
        # First request sends user_session and receives session_token Set-Cookie
        resp1 = client.get(auth_mission, f"{mock_auth_server}/")
        assert resp1.success is True
        assert ident.cookies.get("session_token") == "valid_cookie_12345"

        # Next request persists session_token cookie automatically
        resp2 = client.get(auth_mission, f"{mock_auth_server}/protected")
        assert resp2.success is True
        data = json.loads(resp2.body)
        assert "valid_cookie_12345" in data["cookie_header"]


def test_authenticated_client_automated_json_login_flow(mock_auth_server, auth_mission):
    ident = TestIdentity(
        name="Login User",
        auth_type=AuthType.BEARER,
        login_url=f"{mock_auth_server}/login/json",
        login_payload={"username": "admin", "password": "pass"},
        login_type="json",
    )
    with AuthenticatedHttpClient() as client:
        resp = client.login(auth_mission, identity=ident)
        assert resp.success is True
        assert resp.status_code == 200
        assert ident.token == "jwt_access_token_xyz"
        assert ident.cookies.get("jwt_session") == "cookie_token_999"


def test_authenticated_client_automated_form_login_flow(mock_auth_server, auth_mission):
    ident = TestIdentity(
        name="Form User",
        auth_type=AuthType.BEARER,
        login_url=f"{mock_auth_server}/login/form",
        login_payload={"username": "admin", "password": "pass"},
        login_type="form",
    )
    with AuthenticatedHttpClient() as client:
        resp = client.login(auth_mission, identity=ident)
        assert resp.success is True
        assert resp.status_code == 200
        assert ident.token == "form_token_123"
        assert ident.cookies.get("form_session") == "form_cookie_777"


def test_authenticated_client_proxy_configuration():
    client = AuthenticatedHttpClient(proxy="http://127.0.0.1:8080")
    assert client.proxy == "http://127.0.0.1:8080"
    client.close()


def test_authenticated_client_retry_logic_on_connection_error(auth_mission):
    with AuthenticatedHttpClient(max_retries=2, backoff_factor=0.01) as client:
        resp = client.get(auth_mission, "http://127.0.0.1:65530/")
        assert resp.success is False
        assert "Connection error" in resp.error


def test_authenticated_client_retry_logic_on_timeout(mock_auth_server, auth_mission):
    with AuthenticatedHttpClient(max_retries=1, backoff_factor=0.01) as client:
        resp = client.get(auth_mission, f"{mock_auth_server}/timeout", timeout=0.1)
        assert resp.success is False
        assert "Timeout" in resp.error
