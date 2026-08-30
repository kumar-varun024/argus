# Test Suite, Mocking Infrastructure, and Test Conventions Survey (Sprint 13)

## 1. Observation

### 1.1 Test Suite Overview & Execution Metrics
- **Test Suite Command**: `python3 -m pytest tests/ --ignore=tests/workspace -x -q` (or `PYTHONPATH=. pytest tests/ --ignore=tests/workspace -x -q`).
  - *Observation Note*: Executing bare `pytest tests/` without setting `PYTHONPATH=.` or invoking via `python3 -m pytest` fails during test collection in `tests/analyzers/` and `tests/auth/` with `ModuleNotFoundError: No module named 'argus'`.
- **Total Test Count**: **1,127 passed tests** across 83 test files in 22 test directories.
- **Execution Time**: **~48.15 seconds** total running synchronously on Python 3.13.
- **Test Pass Rate**: **100% (1,127 passed, 0 failed, 0 errors)**.
- **Warnings**: 24,282 deprecation warnings primarily from `datetime.utcnow()` and Pydantic V2 class-based config deprecations.

### 1.2 Existing Collector Test Architectures
The codebase contains mature test suites for 6 existing vulnerability collectors in `tests/collectors/` and end-to-end integration tests in `tests/runtime/`:

| Collector Test File | Primary Subject | Line Count | Key Components Tested |
|---|---|---|---|
| `tests/collectors/test_sql_injection.py` | `SQLInjectionCollector` | 535 lines | Error-based, boolean-blind, time-blind SQLi, WAF mutations, DAG wiring, Graph reconstruction |
| `tests/collectors/test_sql_injection_adversarial.py` | `SQLInjectionCollector` (Adversarial) | 296 lines | Malformed URLs, empty missions, noisy baselines, soft-404 rejection |
| `tests/collectors/test_ssrf.py` | `SSRFCollector` | 660 lines | AWS/GCP/Azure IMDS, Redis/MySQL internal services, 9 bypass mutations, timing differentials |
| `tests/collectors/test_ssrf_adversarial.py` | `SSRFCollector` (Adversarial) | 450 lines | Baseline subtraction, partial reflection discarding, network exceptions |
| `tests/collectors/test_xss.py` | `XSSCollector` | 537 lines | Reflected XSS, stored XSS state persistence, context analysis, canary extraction |
| `tests/collectors/test_path_traversal.py` | `PathTraversalCollector` | 491 lines | Linux `/etc/passwd`, Windows `win.ini`, null-byte & encoding mutations, DAG task generation |
| `tests/collectors/test_command_injection.py` | `CommandInjectionCollector` | 613 lines | Echo delimiters, OS signatures (Linux/Windows), time-blind latency, pipe/semicolon operators |
| `tests/collectors/test_access_control.py` | `AccessControlCollector` | 448 lines | Horizontal IDOR, vertical privilege escalation, header bypasses (`X-Original-URL`), soft error filtering |
| `tests/runtime/test_e2e_sql_injection.py` | Full Mission Pipeline | 252 lines | Mission loop, `TaskGenerator`, `PluginExecutorAdapter`, `ControlledMission`, `AttackSurfaceGraphBuilder` |
| `tests/http/test_authenticated_http_client.py` | `AuthenticatedHttpClient` | 246 lines | Socket-bound ephemeral HTTP server, bearer/cookie/basic/API key injection, scope enforcement |

### 1.3 Mocking Infrastructures in Argus

#### Pattern A: Domain-Specific In-Memory Protocol Mock Clients (Unit/Component Level)
- **Location**: Defined directly within each collector test module (e.g., `MockSQLiHttpClient` at `test_sql_injection.py:29-131`, `MockSSRFHttpClient` at `test_ssrf.py:32-154`, `MockIDORHttpClient` at `test_access_control.py:23-57`).
- **Signature & Behavior**:
  ```python
  class MockCollectorHttpClient:
      def __init__(self, routes: Optional[Dict[str, Tuple[int, str, float]]] = None):
          self.routes: Dict[str, Tuple[int, str, float]] = routes or {}
          self.requested_urls: List[str] = []
          self.requested_posts: List[Dict[str, Any]] = []

      def set_route(self, key: str, status_code: int, body: str, elapsed: float = 0.05):
          self.routes[key] = (status_code, body, elapsed)

      def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
          target_url = url if url is not None else mission_or_url
          self.requested_urls.append(str(target_url))
          # Route lookup via target_url, header pattern (header:Key:Value), or query match
          ...
          return HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url=str(target_url), elapsed=0.05)

      def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
          target_url = url if url is not None else mission_or_url
          # Inspect kwargs['data'], kwargs['json'], kwargs['headers']
          ...
          return HttpResponse(success=True, status_code=200, raw_body="OK", body="OK", url=str(target_url), elapsed=0.05)
  ```
- **Constructor Injection**: Collector classes accept `http_client=mock_client` in `__init__`, falling back to `AuthenticatedHttpClient()` in production:
  `collector = SQLInjectionCollector(http_client=mock_client)`

#### Pattern B: Ephemeral In-Process HTTP Server Fixtures (Integration Level)
- **Location**: `tests/http/test_authenticated_http_client.py:95-106`.
- **Implementation**:
  ```python
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
  ```
- **Handler**: `MockAuthHttpHandler(BaseHTTPRequestHandler)` handles real HTTP verbs, evaluates `Authorization`, `Cookie`, `Set-Cookie` headers, latency/timeouts via `time.sleep()`, and returns standard JSON payloads.

#### Pattern C: Mocking External Tools and Services
- **Libraries**: `unittest.mock.patch`, `MagicMock`.
- **Usage**: Used for subprocess execution (`katana`, `nuclei`, `subfinder`), DNS resolvers, and AI research cards. No external HTTP mocking libraries (`respx`, `responses`, `aioresponses`) are installed or used.

### 1.4 Evidence, Findings, and Graph Assertion Conventions

#### Evidence Assertions
Evidence objects (`argus.evidence.model.Evidence`) are verified with standard attributes:
```python
assert len(evidence_list) >= 1
ev = evidence_list[0]
assert ev.category == "oauth_misconfiguration"  # or "session_management"
assert ev.severity in ["critical", "high", "medium", "low"]
assert ev.status == "CONFIRMED"
assert ev.confidence >= 0.90
assert ev.metadata["misconfiguration_type"] == "open_redirect"
assert ev.metadata["parameter"] == "redirect_uri"
assert "evidence_snippet" in ev.metadata
```

#### Mission State Assertions
Collectors register vulnerabilities directly into the mission state:
```python
assert len(mission.vulnerabilities) >= 1
assert mission.vulnerabilities[0]["severity"] == "critical"
assert mission.vulnerabilities[0]["category"] == "oauth_misconfiguration"
```

#### Knowledge Graph & AttackSurfaceGraphBuilder Assertions
```python
# Direct KnowledgeGraph checks
graph = mission.attack_surface_graph
assert len(graph.nodes_by_type("live_host")) >= 1
assert len(graph.nodes_by_type("endpoint")) >= 1
assert len(graph.nodes_by_type("vulnerability")) >= 1

# Edge connectivity
assert any(e.type == "HAS_ENDPOINT" for e in graph.edges)
assert any(e.type == "HAS_VULNERABILITY" for e in graph.edges)
assert graph.are_connected("endpoint:https://example.com/oauth/authorize", "vulnerability:oauth-open-redirect:https://example.com/oauth/authorize")

# Reconstruction via AttackSurfaceGraphBuilder
builder = AttackSurfaceGraphBuilder()
reconstructed = builder.build_from_evidence(list(mission.evidence), target="example.com")
assert any(e.type == "HAS_VULNERABILITY" for e in reconstructed.edges)
```

---

## 2. Logic Chain

1. **Test Suite Independence & Zero Regressions**:
   - The test suite requires `python3 -m pytest tests/ --ignore=tests/workspace -x -q` to guarantee python import paths resolve `argus` correctly.
   - All 1,127 existing tests are fully isolated and pass in under 50 seconds.
   - New Sprint 13 tests must avoid network I/O, heavy disk I/O, or long sleeps to keep the total test suite runtime fast and deterministic (<60s).

2. **Collector Design Alignment**:
   - Sprint 13 requires adding OAuth/OIDC, Token Validation, and Session Management capabilities following the established collector pattern (`BaseCollector`, `AuthenticatedHttpClient`, `EvidenceStore`, `KnowledgeGraph`).
   - Every prior collector (`SQLInjectionCollector`, `SSRFCollector`, `XSSCollector`, `CommandInjectionCollector`, `PathTraversalCollector`, `AccessControlCollector`) follows a three-tier design:
     1. **Payload/Variant Generator**: Generates protocol-specific mutation payloads (e.g. `OAuthPayloadGenerator`, `TokenPayloadGenerator`, `SessionPayloadGenerator`).
     2. **Analyzer**: Pure analysis logic evaluating HTTP status codes, headers, and bodies (e.g. `OAuthAnalyzer`, `TokenValidationAnalyzer`, `SessionAnalyzer`).
     3. **Collector**: Orchestrates endpoint fuzzing, calls `AuthenticatedHttpClient`, records `Evidence`, updates `mission.vulnerabilities`, and creates graph nodes and `HAS_VULNERABILITY` edges.

3. **Mocking Strategy for Sprint 13**:
   - Use **Pattern A** (`MockOAuthHttpClient` / `MockSessionHttpClient`) for unit and component tests. This enables testing 20+ scenarios in <0.5 seconds without port allocation or thread overhead.
   - Use **Pattern B** (`MockAuthHttpHandler` with `HTTPServer`) for end-to-end integration tests verifying real cookie jar synchronization, header injection, and session transition behaviors.

---

## 3. Caveats

- **No Third-Party Mock Frameworks**: The Argus codebase intentionally avoids third-party HTTP mocking frameworks like `respx` or `responses` in favor of custom in-memory protocol mocks (`Mock*HttpClient`) and standard library `HTTPServer` fixtures. New tests must adhere to this convention.
- **Python Module Resolution**: Running `pytest` directly in bash without `python3 -m pytest` or `PYTHONPATH=.` will fail on test collection. CI and audit commands must always use `python3 -m pytest`.
- **Graph Builder Routing**: `AttackSurfaceGraphBuilder.build_from_evidence()` processes evidence categories via explicit `if ev.category == "..."` branches. When introducing new evidence categories (`oauth_misconfiguration`, `token_validation`, `session_management`), `AttackSurfaceGraphBuilder` must be updated or the generic vulnerability handler will be used.

---

## 4. Conclusion & Concrete Test Templates

To satisfy R1–R5 (>=20 comprehensive tests with zero regressions), the following test suite structure and concrete templates are recommended for the implementation team.

### 4.1 Recommended Test File Organization
- `tests/collectors/test_oauth_oidc.py` (Unit & Component tests for OAuth/OIDC, Token Validation, and Session Management)
- `tests/collectors/test_oauth_oidc_adversarial.py` (Adversarial, boundary conditions, and false positive suppression)
- `tests/runtime/test_e2e_oauth_oidc.py` (Full DAG wiring, TaskGenerator, ToolRegistry, and AttackSurfaceGraphBuilder integration)

---

### 4.2 Comprehensive 23-Test Specification Matrix

#### Category A: OAuth/OIDC Flow Misconfigurations (R1) — 6 Tests
1. `test_oauth_redirect_uri_open_redirect_detection`: Fuzzes `redirect_uri` with external attacker domain (`https://attacker.com/callback`); verifies critical/high severity Evidence.
2. `test_oauth_redirect_uri_subdomain_bypass`: Fuzzes `redirect_uri` with unvalidated subdomain matching bypass (`https://target.com.attacker.com` / `https://attacker-target.com`).
3. `test_oauth_redirect_uri_path_traversal_bypass`: Fuzzes `redirect_uri` with path traversal bypass (`https://target.com/oauth/callback/../../attacker`).
4. `test_oauth_state_parameter_csrf_vulnerability`: Tests authorization requests omitting or providing static/predictable `state` parameters; confirms CSRF evidence generation.
5. `test_oauth_token_leakage_via_referer`: Verifies detection of authorization code or token leakage via `Referer` headers when redirecting to external assets.
6. `test_oauth_authorization_code_reuse_detection`: Tests authorization code replay against `/oauth/token`; detects when codes can be exchanged multiple times.

#### Category B: Token Validation & JWT Security (R2) — 7 Tests
7. `test_jwt_alg_none_signature_bypass`: Injects unsigned JWT with `{"alg": "none"}` into authenticated endpoint; confirms critical severity Evidence when accepted.
8. `test_jwt_invalid_signature_acceptance`: Modifies token payload claims with forged signature; confirms detection when server returns 200 OK without verifying signature.
9. `test_jwt_key_confusion_hs256_rs256`: Tests HMAC-SHA256 signature using the public RSA key as the secret; confirms key confusion vulnerability detection.
10. `test_jwt_expired_token_acceptance`: Sends expired token (`exp` timestamp in the past); detects missing expiration verification.
11. `test_jwt_missing_audience_and_issuer_validation`: Sends token with invalid `aud` (audience) or `iss` (issuer); detects lack of claim validation.
12. `test_jwt_not_before_nbf_violation_acceptance`: Sends token with future `nbf` (not before) claim; detects premature token acceptance.
13. `test_token_scope_escalation_detection`: Tests endpoints accepting tokens with stripped or modified `scope` claims for privileged operations.

#### Category C: Session & Authentication Flow Analysis (R3) — 6 Tests
14. `test_session_fixation_vulnerability_detection`: Tests pre-authentication session ID retention after successful login; verifies fixation Evidence.
15. `test_session_insufficient_logout_invalidation`: Issues logout request and verifies whether session cookie/token remains active for subsequent requests.
16. `test_session_cookie_missing_secure_and_httponly_flags`: Inspects `Set-Cookie` response headers; emits Evidence when `Secure` or `HttpOnly` flags are absent.
17. `test_session_cookie_samesite_attribute_validation`: Tests for missing or insecure `SameSite=None` (without Secure) cookie attributes.
18. `test_session_concurrent_session_handling`: Tests concurrent logins from distinct IP/identities to detect session collisions or invalidations.
19. `test_oauth_and_session_false_positive_rejection`: Validates that properly hardened OAuth flows, signed JWTs, and secure session cookies emit 0 false positive Evidence.

#### Category D: Pipeline, DAG, Registry & Graph Integration (R4 & R5) — 4 Tests
20. `test_oauth_collector_task_generator_dag_wiring`: Verifies `_RECON_TEMPLATES["oauth_oidc"]` exists with dependencies on `Discover API Endpoints` and category `TaskCategory.AUTHENTICATION_ANALYSIS`.
21. `test_oauth_collector_tool_registry_and_plugin_adapter`: Verifies `registry.get("oauth_oidc")` registration and `PluginExecutorAdapter` fallback instantiation.
22. `test_oauth_collector_attack_surface_graph_expansion`: Verifies that confirmed OAuth/Session findings generate `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges on `mission.attack_surface_graph`.
23. `test_e2e_oauth_collector_mission_loop_execution`: End-to-end mission loop execution via `ControlledMission` adapter verifying complete state and graph reconstruction.

---

### 4.3 Concrete Test Code Templates for Implementation

#### Template 1: Mock HTTP Client for OAuth / Token / Session Testing
```python
# Location: tests/collectors/test_oauth_oidc.py
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
from argus.http.client import HttpResponse

class MockOAuthHttpClient:
    """Mock HTTP client simulating OAuth authorization servers, token endpoints, and protected APIs."""

    def __init__(self):
        self.routes: Dict[str, Tuple[int, str, Dict[str, str], float]] = {}
        self.requested_urls: List[str] = []
        self.requested_posts: List[Dict[str, Any]] = []
        self.session_store: Dict[str, Dict[str, Any]] = {}

    def set_route(self, key: str, status_code: int, body: str, headers: Optional[Dict[str, str]] = None, elapsed: float = 0.05):
        self.routes[key] = (status_code, body, headers or {}, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        self.requested_urls.append(target_url)
        req_headers = kwargs.get("headers") or {}

        # 1. Check exact key match
        if target_url in self.routes:
            st, bd, hd, el = self.routes[target_url]
            return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=el)

        # 2. Check authorization header / token matching
        auth_header = req_headers.get("Authorization", "")
        if auth_header and f"auth:{auth_header}" in self.routes:
            st, bd, hd, el = self.routes[f"auth:{auth_header}"]
            return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=el)

        # 3. Check query param substring matching (e.g. redirect_uri, state)
        for key, (st, bd, hd, el) in self.routes.items():
            if key in target_url or key in urllib.parse.unquote_plus(target_url):
                return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=el)

        # Default benign fallback
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body='{"status": "ok"}',
            body='{"status": "ok"}',
            headers={"Content-Type": "application/json"},
            url=target_url,
            elapsed=0.05,
        )

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        data = kwargs.get("data")
        json_data = kwargs.get("json")
        req_headers = kwargs.get("headers") or {}
        self.requested_posts.append({"url": target_url, "data": data, "json": json_data, "headers": req_headers})

        # Check payload / route matching
        if target_url in self.routes:
            st, bd, hd, el = self.routes[target_url]
            return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=el)

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body='{"status": "success"}',
            body='{"status": "success"}',
            headers={"Content-Type": "application/json"},
            url=target_url,
            elapsed=0.05,
        )
```

#### Template 2: OAuth Open Redirect & Token Validation Tests
```python
def test_oauth_redirect_uri_open_redirect_detection():
    """R1: Test detection of open redirect via unvalidated redirect_uri parameter."""
    mission = Mission(target="oauth.target.com")
    mission.endpoints = [{"url": "https://oauth.target.com/oauth/authorize?client_id=app1&redirect_uri=https://target.com/callback&response_type=code"}]
    mission.live_hosts = ["https://oauth.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockOAuthHttpClient()
    # When redirect_uri is pointed to attacker.com, server returns 302 redirecting to attacker domain
    mock_client.set_route(
        "redirect_uri=https%3A%2F%2Fattacker.com%2Fcallback",
        302,
        "",
        headers={"Location": "https://attacker.com/callback?code=AUTH_CODE_123"},
    )

    collector = OAuthCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "oauth_misconfiguration"
    assert ev.severity in ["critical", "high"]
    assert ev.status == "CONFIRMED"
    assert ev.metadata["parameter"] == "redirect_uri"
    assert ev.metadata["misconfiguration_type"] == "open_redirect"


def test_jwt_alg_none_signature_bypass():
    """R2: Test detection of OIDC/JWT tokens accepted without signature verification (alg:none)."""
    mission = Mission(target="api.target.com")
    mission.endpoints = [{"url": "https://api.target.com/api/user/profile", "method": "GET"}]
    mission.live_hosts = ["https://api.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    # JWT with {"alg": "none"} header and admin payload
    # eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ.
    alg_none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ."

    mock_client = MockOAuthHttpClient()
    mock_client.set_route(
        f"auth:Bearer {alg_none_token}",
        200,
        '{"user": "admin", "role": "superuser", "secret_data": "top_secret_flag"}',
        headers={"Content-Type": "application/json"},
    )

    collector = OAuthCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) >= 1
    ev = next(e for e in evidence_list if e.metadata.get("misconfiguration_type") == "alg_none_bypass")
    assert ev.severity == "critical"
    assert ev.confidence >= 0.95
```

#### Template 3: Session Cookie Flags & Session Fixation Tests
```python
def test_session_cookie_missing_secure_and_httponly_flags():
    """R3: Test detection of session cookies missing Secure and HttpOnly flags."""
    mission = Mission(target="auth.target.com")
    mission.endpoints = [{"url": "https://auth.target.com/login", "method": "POST"}]
    mission.live_hosts = ["https://auth.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockOAuthHttpClient()
    # Insecure Set-Cookie without Secure or HttpOnly flags
    mock_client.set_route(
        "https://auth.target.com/login",
        200,
        '{"status": "authenticated"}',
        headers={"Set-Cookie": "session_id=insecure_token_12345; Path=/"},
    )

    collector = OAuthCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) >= 1
    ev = next(e for e in evidence_list if e.metadata.get("misconfiguration_type") == "insecure_cookie_attributes")
    assert ev.category == "session_management"
    assert ev.metadata["cookie_name"] == "session_id"
    assert "Secure" in ev.metadata["missing_flags"]
    assert "HttpOnly" in ev.metadata["missing_flags"]
```

---

## 5. Verification Method

To independently verify all findings and test suite behaviors:

1. **Verify Baseline Test Suite Execution**:
   ```bash
   python3 -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   *Expected Output*: `1127 passed, 24282 warnings in ~48s` (exit code 0).

2. **Verify Module Isolation**:
   ```bash
   python3 -m pytest tests/collectors/ -q
   python3 -m pytest tests/http/ -q
   python3 -m pytest tests/runtime/ -q
   ```
   *Expected Output*: All 15+ collector test files and HTTP test files pass with 0 errors.

3. **Verify DAG & Registry Integration**:
   Inspect `argus/planning/task_generator.py` line 13 (`_RECON_TEMPLATES`), `argus/runtime/registry.py` line 56 (`ToolRegistry`), and `argus/runtime/plugins.py` line 65 (`PluginExecutorAdapter._instantiate_specialist_fallback`).
