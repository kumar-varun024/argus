import pytest
import threading
import json
import time
import socket
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import httpx

from argus.runtime.mission import Mission
from argus.runtime.manager import mission_manager
from argus.authorization.scope import ScopeState, ScopeResolver
from argus.authorization.gate import AuthDecision, authorization_gate
from argus.models.test_identity import TestIdentity, AuthType
from argus.http.client import (
    AuthorizedHttpClient,
    AuthenticatedHttpClient,
    HttpResponse,
    sanitize_url,
    sanitize_headers,
)


def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class EmpiricalStressHttpHandler(BaseHTTPRequestHandler):
    """Multi-endpoint test server for empirical challenge of HTTP and Auth workflows."""

    def log_message(self, format, *args):
        pass  # Suppress default server logging to keep test output clean

    def do_GET(self):
        # 1. Sequence / Cookie Jar tracking endpoint
        if self.path.startswith("/cookies/step"):
            step = self.path.split("/")[-1]
            cookie_hdr = self.headers.get("Cookie", "")
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if step == "step1":
                self.send_header("Set-Cookie", "c1=val1; Path=/; HttpOnly")
                self.send_header("Set-Cookie", "c2=initial2; Path=/")
            elif step == "step2":
                self.send_header("Set-Cookie", "c2=updated2; Path=/")
                self.send_header("Set-Cookie", "c3=val3; Path=/")
            elif step == "step3":
                self.send_header("Set-Cookie", "c4=val4; Path=/")
            self.end_headers()
            
            resp = {
                "step": step,
                "received_cookie_header": cookie_hdr,
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        # 2. Echo headers endpoint
        if self.path == "/echo_headers":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "headers": {k: v for k, v in self.headers.items()},
                "auth": self.headers.get("Authorization"),
                "cookie": self.headers.get("Cookie"),
                "x_api_key": self.headers.get("X-API-Key"),
                "x_custom_token": self.headers.get("X-Custom-Token"),
                "x_custom_auth": self.headers.get("X-Custom-Auth"),
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        # 3. Long sleep timeout endpoint
        if self.path == "/timeout_stress":
            time.sleep(0.4)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"timeout done")
            return

        # 4. Generic 200
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"path": self.path, "status": "ok"}).encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        # Login variations
        if self.path == "/login/nested_token":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "session_id=nested_session_abc; Path=/")
            self.end_headers()
            self.wfile.write(json.dumps({"data": {"token": "jwt_nested_12345"}}).encode("utf-8"))
            return

        if self.path == "/login/access_token":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "access_cookie=ac_999; Path=/")
            self.end_headers()
            self.wfile.write(json.dumps({"accessToken": "jwt_access_token_98765"}).encode("utf-8"))
            return

        if self.path == "/login/form_auth":
            parsed_form = parse_qs(body)
            user = parsed_form.get("username", [""])[0]
            pwd = parsed_form.get("password", [""])[0]
            if user == "secuser" and pwd == "secpass":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "form_auth_cookie=fac_777; Path=/")
                self.end_headers()
                self.wfile.write(json.dumps({"token": "form_jwt_token_4321"}).encode("utf-8"))
            else:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Unauthorized")
            return

        if self.path == "/login/fail_401":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_credentials", "token": "fake_token_should_not_capture"}).encode("utf-8"))
            return

        if self.path == "/login/redirect":
            self.send_response(302)
            self.send_header("Location", "/login/redirect_target")
            self.send_header("Set-Cookie", "redirect_cookie=rc_111; Path=/")
            self.end_headers()
            return

        if self.path == "/echo_post":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"body": body, "headers": {k: v for k, v in self.headers.items()}}).encode("utf-8"))
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "post_ok", "body": body}).encode("utf-8"))


@pytest.fixture(scope="module")
def stress_server():
    port = find_free_port()
    server = HTTPServer(("127.0.0.1", port), EmpiricalStressHttpHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.fixture
def base_mission():
    m = Mission(name="Empirical Mission", target="127.0.0.1")
    m.scope = ["127.0.0.1"]
    mission_manager._active_missions[m.id] = m
    return m


# =========================================================================
# 1. Session Cookie Jar Across Sequential Requests & State Synchronization
# =========================================================================

def test_cookie_jar_transmission_and_identity_sync(stress_server, base_mission):
    """
    Stress-test cookie jar lifecycle across 3 sequential requests:
    1. Step 1 sets c1=val1, c2=initial2
    2. Step 2 receives c1, c2, updates c2=updated2, adds c3=val3
    3. Step 3 receives c1, c2 (updated), c3, adds c4=val4
    4. Step 4 verifies all 4 cookies are transmitted in the Cookie header.
    """
    ident = TestIdentity(name="JarIdentity", auth_type=AuthType.COOKIE)
    with AuthenticatedHttpClient(identity=ident) as client:
        # Request 1
        r1 = client.get(base_mission, f"{stress_server}/cookies/step1")
        assert r1.success is True
        assert ident.cookies.get("c1") == "val1"
        assert ident.cookies.get("c2") == "initial2"

        # Request 2
        r2 = client.get(base_mission, f"{stress_server}/cookies/step2")
        assert r2.success is True
        d2 = json.loads(r2.body)
        assert "c1=val1" in d2["received_cookie_header"]
        assert "c2=initial2" in d2["received_cookie_header"]
        # Updated cookies in identity
        assert ident.cookies.get("c2") == "updated2"
        assert ident.cookies.get("c3") == "val3"

        # Request 3
        r3 = client.get(base_mission, f"{stress_server}/cookies/step3")
        assert r3.success is True
        d3 = json.loads(r3.body)
        assert "c1=val1" in d3["received_cookie_header"]
        assert "c3=val3" in d3["received_cookie_header"]
        assert ident.cookies.get("c4") == "val4"

        # Request 4 (echo_headers)
        r4 = client.get(base_mission, f"{stress_server}/echo_headers")
        assert r4.success is True
        d4 = json.loads(r4.body)
        cookie_header = d4["cookie"]
        assert "c1=val1" in cookie_header
        assert "c3=val3" in cookie_header
        assert "c4=val4" in cookie_header


def test_cookie_jar_manual_override_and_merging(stress_server, base_mission):
    """
    Test that per-request cookies merge with client cookies without losing session state.
    """
    with AuthenticatedHttpClient() as client:
        # First request sets c1 and c2
        client.get(base_mission, f"{stress_server}/cookies/step1")

        # Second request provides ad-hoc one-off cookie
        r = client.get(base_mission, f"{stress_server}/echo_headers", cookies={"adhoc_cookie": "adhoc_value"})
        assert r.success is True
        d = json.loads(r.body)
        assert "c1=val1" in d["cookie"]
        assert "adhoc_cookie=adhoc_value" in d["cookie"]


def test_cookie_jar_multi_step_accumulation_and_update(stress_server, base_mission):
    """
    Verify client.cookies does not suffer CookieConflict when accessing cookies
    across multi-step requests.
    """
    ident = TestIdentity(name="JarIdentity", auth_type=AuthType.COOKIE)
    with AuthenticatedHttpClient(identity=ident) as client:
        client.get(base_mission, f"{stress_server}/cookies/step1")
        assert client.cookies.get("c1") == "val1"
        assert client.cookies.get("c2") == "initial2"

        client.get(base_mission, f"{stress_server}/cookies/step2")
        assert client.cookies.get("c2") == "updated2"
        assert client.cookies.get("c3") == "val3"

        client.get(base_mission, f"{stress_server}/cookies/step3")
        assert client.cookies.get("c4") == "val4"


# =========================================================================
# 2. Scope Gating Preventing Leaks to Subdomains / External Domains
# =========================================================================

def test_scope_gating_subdomain_leak_prevention(stress_server, base_mission):
    """
    Ensure that when scope is restricted to 'api.target.com', requests to
    'admin.target.com', 'internal.target.com', or 'evil.com' are strictly blocked
    BEFORE sending credentials.
    """
    base_mission.scope = ["api.target.com"]
    ident = TestIdentity(
        name="Sensitive Admin",
        auth_type=AuthType.BEARER,
        token="TOP_SECRET_JWT_9999",
    )

    with AuthenticatedHttpClient(identity=ident) as client:
        # Out-of-scope sibling subdomain
        resp_sub = client.get(base_mission, "http://admin.target.com/api/v1")
        assert resp_sub.success is False
        assert "Blocked by scope" in resp_sub.error
        assert resp_sub.scope_decision.decision == ScopeState.OUT_OF_SCOPE

        # Out-of-scope external domain
        resp_ext = client.get(base_mission, "http://attacker.com/steal")
        assert resp_ext.success is False
        assert "Blocked by scope" in resp_ext.error
        assert resp_ext.scope_decision.decision == ScopeState.OUT_OF_SCOPE

        # Out-of-scope prefix attack (e.g. api.target.com.attacker.com)
        resp_prefix = client.get(base_mission, "http://api.target.com.attacker.com/evil")
        assert resp_prefix.success is False
        assert "Blocked by scope" in resp_prefix.error


def test_scope_gating_wildcard_domains(base_mission):
    """
    Test wildcard domain matching in scope (*.target.com).
    """
    base_mission.scope = ["*.target.com"]
    resolver = ScopeResolver()

    # Exact apex domain
    d_apex = resolver.check_scope("http://target.com/page", base_mission.id)
    assert d_apex.decision == ScopeState.IN_SCOPE

    # Subdomain
    d_sub = resolver.check_scope("http://sub.target.com/page", base_mission.id)
    assert d_sub.decision == ScopeState.IN_SCOPE

    # Deep subdomain
    d_deep = resolver.check_scope("http://a.b.target.com/page", base_mission.id)
    assert d_deep.decision == ScopeState.IN_SCOPE

    # Lookalike / out-of-scope
    d_lookalike = resolver.check_scope("http://target.com.evil.com/page", base_mission.id)
    assert d_lookalike.decision == ScopeState.OUT_OF_SCOPE


def test_scope_gating_ip_cidr_ranges(base_mission):
    """
    Test CIDR IP range scope enforcement.
    """
    base_mission.scope = ["10.0.0.0/24"]
    resolver = ScopeResolver()

    assert resolver.check_scope("http://10.0.0.1/api", base_mission.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("http://10.0.0.254/api", base_mission.id).decision == ScopeState.IN_SCOPE
    assert resolver.check_scope("http://10.0.1.1/api", base_mission.id).decision == ScopeState.OUT_OF_SCOPE
    assert resolver.check_scope("http://192.168.1.1/api", base_mission.id).decision == ScopeState.OUT_OF_SCOPE


# =========================================================================
# 3. Identity Injection (All Auth Types, Special Characters, Dynamic Resolution)
# =========================================================================

def test_identity_bearer_injection(stress_server, base_mission):
    ident = TestIdentity(name="BearerTest", auth_type=AuthType.BEARER, token="bearer_jwt_token_value")
    with AuthenticatedHttpClient(identity=ident) as client:
        r = client.get(base_mission, f"{stress_server}/echo_headers")
        assert r.success is True
        d = json.loads(r.raw_body or r.body)
        assert d["auth"] == "Bearer bearer_jwt_token_value"


def test_identity_basic_auth_with_special_characters(stress_server, base_mission):
    """
    Test Basic auth credentials with symbols, colons, spaces, and UTF-8.
    """
    username = "user:with:colons"
    password = "P@ssw0rd !#%&*()_+~"
    ident = TestIdentity(
        name="BasicSpecial",
        auth_type=AuthType.BASIC,
        credentials={"username": username, "password": password}
    )
    with AuthenticatedHttpClient(identity=ident) as client:
        r = client.get(base_mission, f"{stress_server}/echo_headers")
        assert r.success is True
        d = json.loads(r.raw_body or r.body)
        expected_raw = f"{username}:{password}"
        expected_b64 = base64.b64encode(expected_raw.encode("utf-8")).decode("ascii")
        assert d["auth"] == f"Basic {expected_b64}"


def test_identity_custom_api_key_injection(stress_server, base_mission):
    ident = TestIdentity(
        name="ApiKeyTest",
        auth_type=AuthType.API_KEY,
        credentials={"key_header": "X-Custom-Token", "api_key": "custom_api_secret_key_888"}
    )
    with AuthenticatedHttpClient(identity=ident) as client:
        r = client.get(base_mission, f"{stress_server}/echo_headers")
        assert r.success is True
        d = json.loads(r.raw_body or r.body)
        assert d["x_custom_token"] == "custom_api_secret_key_888"


def test_identity_oauth2_injection(stress_server, base_mission):
    ident = TestIdentity(
        name="OAuth2Test",
        auth_type=AuthType.OAUTH2,
        credentials={"access_token": "oauth2_access_tok_555"}
    )
    with AuthenticatedHttpClient(identity=ident) as client:
        r = client.get(base_mission, f"{stress_server}/echo_headers")
        assert r.success is True
        d = json.loads(r.raw_body or r.body)
        assert d["auth"] == "Bearer oauth2_access_tok_555"


def test_identity_custom_headers_injection(stress_server, base_mission):
    ident = TestIdentity(
        name="CustomTest",
        auth_type=AuthType.CUSTOM,
        headers={"X-Custom-Auth": "CustomVal123", "Authorization": "CustomToken XYZ"}
    )
    with AuthenticatedHttpClient(identity=ident) as client:
        r = client.get(base_mission, f"{stress_server}/echo_headers")
        assert r.success is True
        d = json.loads(r.raw_body or r.body)
        assert d["auth"] == "CustomToken XYZ"
        custom_auth = d.get("x_custom_auth") or d.get("headers", {}).get("x-custom-auth") or d.get("headers", {}).get("X-Custom-Auth")
        assert custom_auth == "CustomVal123"


def test_identity_mission_active_identity_resolution(stress_server, base_mission):
    """
    When AuthenticatedHttpClient has no identity passed, it automatically falls back
    to mission.get_active_identity().
    """
    ident_admin = TestIdentity(id="admin_id", name="Admin", auth_type=AuthType.BEARER, token="admin_token_001")
    ident_user = TestIdentity(id="user_id", name="User", auth_type=AuthType.BEARER, token="user_token_002")
    
    base_mission.add_test_identity(ident_admin)
    base_mission.add_test_identity(ident_user)
    base_mission.set_active_identity("admin_id")

    with AuthenticatedHttpClient() as client:
        # Request uses admin identity from mission
        r1 = client.get(base_mission, f"{stress_server}/echo_headers")
        assert r1.success is True
        assert json.loads(r1.raw_body or r1.body)["auth"] == "Bearer admin_token_001"

        # Switch mission active identity to user
        base_mission.set_active_identity("user_id")
        r2 = client.get(base_mission, f"{stress_server}/echo_headers")
        assert r2.success is True
        assert json.loads(r2.raw_body or r2.body)["auth"] == "Bearer user_token_002"


def test_identity_per_request_override_precedence(stress_server, base_mission):
    """
    Verify precedence: request(..., identity=override_ident) overrides client default identity.
    """
    client_ident = TestIdentity(name="DefaultClient", auth_type=AuthType.BEARER, token="client_default_token")
    override_ident = TestIdentity(name="PerRequest", auth_type=AuthType.BEARER, token="override_request_token")

    with AuthenticatedHttpClient(identity=client_ident) as client:
        # 1. Without override
        r1 = client.get(base_mission, f"{stress_server}/echo_headers")
        assert json.loads(r1.raw_body or r1.body)["auth"] == "Bearer client_default_token"

        # 2. With override
        r2 = client.get(base_mission, f"{stress_server}/echo_headers", identity=override_ident)
        assert json.loads(r2.raw_body or r2.body)["auth"] == "Bearer override_request_token"

        # 3. Next call returns back to client default
        r3 = client.get(base_mission, f"{stress_server}/echo_headers")
        assert json.loads(r3.raw_body or r3.body)["auth"] == "Bearer client_default_token"


# =========================================================================
# 4. Automated login() Workflows (Nested JSON, Form, Cookies, Failures)
# =========================================================================

def test_login_nested_json_token_capture(stress_server, base_mission):
    ident = TestIdentity(
        name="NestedLogin",
        auth_type=AuthType.BEARER,
        login_url=f"{stress_server}/login/nested_token",
        login_payload={"username": "user", "password": "pwd"},
        login_type="json"
    )
    with AuthenticatedHttpClient() as client:
        resp = client.login(base_mission, identity=ident)
        assert resp.success is True
        assert resp.status_code == 200
        assert ident.token == "jwt_nested_12345"
        assert ident.cookies.get("session_id") == "nested_session_abc"

        # Subsequent request uses the captured token and cookies
        r_after = client.get(base_mission, f"{stress_server}/echo_headers", identity=ident)
        assert r_after.success is True
        d = json.loads(r_after.raw_body or r_after.body)
        assert d["auth"] == "Bearer jwt_nested_12345"
        assert "session_id=nested_session_abc" in d["cookie"]


def test_login_access_token_capture(stress_server, base_mission):
    ident = TestIdentity(
        name="AccessTokenLogin",
        auth_type=AuthType.BEARER,
        login_url=f"{stress_server}/login/access_token",
        login_payload={},
        login_type="json"
    )
    with AuthenticatedHttpClient() as client:
        resp = client.login(base_mission, identity=ident)
        assert resp.success is True
        assert ident.token == "jwt_access_token_98765"
        assert ident.cookies.get("access_cookie") == "ac_999"


def test_login_form_encoded_workflow(stress_server, base_mission):
    ident = TestIdentity(
        name="FormLogin",
        auth_type=AuthType.BEARER,
        login_url=f"{stress_server}/login/form_auth",
        login_payload={"username": "secuser", "password": "secpass"},
        login_type="form"
    )
    with AuthenticatedHttpClient() as client:
        resp = client.login(base_mission, identity=ident)
        assert resp.success is True
        assert resp.status_code == 200
        assert ident.token == "form_jwt_token_4321"
        assert ident.cookies.get("form_auth_cookie") == "fac_777"


def test_login_failed_credentials_does_not_capture_invalid_token(stress_server, base_mission):
    ident = TestIdentity(
        name="FailLogin",
        auth_type=AuthType.BEARER,
        login_url=f"{stress_server}/login/fail_401",
        login_payload={"username": "bad", "password": "bad"},
        login_type="json"
    )
    with AuthenticatedHttpClient() as client:
        resp = client.login(base_mission, identity=ident)
        assert resp.success is True  # HTTP 401 response received
        assert resp.status_code == 401
        # Token must NOT be updated from 401 response
        assert ident.token is None


def test_login_out_of_scope_blocks_cleanly(stress_server, base_mission):
    base_mission.scope = ["different-host.com"]
    ident = TestIdentity(
        name="OutOfScopeLogin",
        auth_type=AuthType.BEARER,
        login_url=f"{stress_server}/login/nested_token",
        login_payload={"username": "admin", "password": "password"},
    )
    with AuthenticatedHttpClient() as client:
        resp = client.login(base_mission, identity=ident)
        assert resp.success is False
        assert "Blocked by scope" in resp.error
        assert ident.token is None


# =========================================================================
# 5. Proxy Parameter & Config Handling
# =========================================================================

def test_proxy_initialization():
    proxy_url = "http://127.0.0.1:9090"
    client = AuthenticatedHttpClient(proxy=proxy_url)
    assert client.proxy == proxy_url
    assert client._client is not None
    client.close()
    assert client._client.is_closed


# =========================================================================
# 6. Retries with Exponential Backoff
# =========================================================================

def test_retries_on_connection_error(base_mission):
    """
    Test retry logic with dead port. Verify retries count and backoff execution.
    """
    start_time = time.time()
    with AuthenticatedHttpClient(max_retries=2, backoff_factor=0.05) as client:
        # Non-listening port
        resp = client.get(base_mission, "http://127.0.0.1:65532/")
        elapsed = time.time() - start_time
        assert resp.success is False
        assert "Connection error" in resp.error
        # 2 retries with backoff: attempt 0 (sleep 0.05), attempt 1 (sleep 0.10) => total sleep >= 0.15s
        assert elapsed >= 0.12


def test_retries_on_timeout(stress_server, base_mission):
    start_time = time.time()
    with AuthenticatedHttpClient(max_retries=2, backoff_factor=0.05) as client:
        resp = client.get(base_mission, f"{stress_server}/timeout_stress", timeout=0.1)
        elapsed = time.time() - start_time
        assert resp.success is False
        assert "Timeout" in resp.error
        # 3 attempts (1 initial + 2 retries) * 0.1s timeout + backoff sleep >= 0.3s
        assert elapsed >= 0.25


def test_per_request_retry_override_zero_retries(base_mission):
    """
    Override max_retries=0 on a client configured with default max_retries=3.
    """
    start_time = time.time()
    with AuthenticatedHttpClient(max_retries=3, backoff_factor=0.2) as client:
        resp = client.get(base_mission, "http://127.0.0.1:65532/", max_retries=0)
        elapsed = time.time() - start_time
        assert resp.success is False
        # With 0 retries, elapsed time is near instantaneous (< 0.15s)
        assert elapsed < 0.15


# =========================================================================
# 7. Backward Compatibility: AuthorizedHttpClient vs AuthenticatedHttpClient
# =========================================================================

def test_backward_compatibility_authorized_http_client_api(stress_server, base_mission):
    """
    Verify AuthorizedHttpClient functions identically without breaking existing callers.
    """
    client = AuthorizedHttpClient()
    assert issubclass(AuthenticatedHttpClient, AuthorizedHttpClient)

    # 1. GET
    resp_get = client.get(base_mission, f"{stress_server}/")
    assert resp_get.success is True
    assert resp_get.status_code == 200
    assert resp_get.scope_decision.decision == ScopeState.IN_SCOPE
    assert resp_get.authorization_decision.allowed is True

    # 2. POST
    resp_post = client.post(base_mission, f"{stress_server}/echo_post", json={"k": "v"})
    assert resp_post.success is True
    assert resp_post.status_code == 200

    # 3. Evidence creation
    assert len(base_mission.evidence) > 0
    ev = base_mission.evidence.all()[-1]
    assert ev.category == "HTTP Response"
    assert ev.mission_id == base_mission.id


def test_all_http_verbs_supported_on_authenticated_client(stress_server, base_mission):
    """
    Verify GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS are all available and functional.
    """
    with AuthenticatedHttpClient() as client:
        r_get = client.get(base_mission, f"{stress_server}/")
        assert r_get.success is True

        r_post = client.post(base_mission, f"{stress_server}/echo_post", json={"test": "post"})
        assert r_post.success is True

        r_put = client.put(base_mission, f"{stress_server}/echo_post", json={"test": "put"})
        assert r_put.success is True

        r_patch = client.patch(base_mission, f"{stress_server}/echo_post", json={"test": "patch"})
        assert r_patch.success is True

        r_delete = client.delete(base_mission, f"{stress_server}/echo_post")
        assert r_delete.success is True

        r_head = client.head(base_mission, f"{stress_server}/")
        assert r_head.success is True

        r_options = client.options(base_mission, f"{stress_server}/")
        assert r_options.success is True
