# Handoff Report: Explorer 3 — TestIdentity Model, Authenticated HTTP Client & Test Suite Survey

## 1. Observation

### 1.1 Existing Model Architecture & `Mission` Class
- **File**: `/home/varun/argus/argus/models/__init__.py`
  - Currently exports only `AuthenticationModel`:
    ```python
    from .authentication import AuthenticationModel
    __all__ = ["AuthenticationModel"]
    ```
- **File**: `/home/varun/argus/argus/models/authentication.py`
  - Uses standard Python `@dataclass`:
    ```python
    @dataclass
    class AuthenticationModel:
        authentication_type: str = "Unknown"
        token_type: str = "Unknown"
        confidence: int = 0
        observations: list[str] = field(default_factory=list)
        reasoning: list[str] = field(default_factory=list)
        research_questions: list[str] = field(default_factory=list)
        missing_evidence: list[str] = field(default_factory=list)
    ```
- **File**: `/home/varun/argus/argus/models/attack_surface.py`
  - Defines `@dataclass class AttackSurface` with list fields (`subdomains`, `live_hosts`, `endpoints`, `javascript`, `technologies`, `apis`, `graphql`, `websockets`, `source_maps`, `routes`, `parameters`).
- **File**: `/home/varun/argus/argus/runtime/mission.py`
  - `Mission` is defined as a dataclass (lines 76–259).
  - Existing identity/auth fields:
    - Line 91: `credentials: list[dict] = field(default_factory=list)`
    - Line 191: `authentication: AuthenticationModel = field(default_factory=AuthenticationModel)`
    - Line 201: `identities: list = field(default_factory=list)` (used by recon/auth plugins to store discovered user objects).
    - `test_identities` does not yet exist on `Mission`.
- **File**: `/home/varun/argus/argus/runtime/checkpoint.py`
  - Uses `pickle.dump(mission, f)` and `pickle.load(f)`. All attributes on `Mission` must be pickle-serializable (standard dataclasses with serializable fields).

### 1.2 Existing HTTP Client Architecture
- **File**: `/home/varun/argus/argus/http/client.py` (lines 84–295)
  - Defines `class AuthorizedHttpClient`:
    - Uses `httpx.request(...)` statelessly (no persistent session, no cookie jar).
    - Performs scope checking via `self.scope_resolver.check_scope(url, mission.id)` (lines 106–118).
    - Performs authorization checking via `authorization_gate.can_execute_action(user_id, action, url, mission.id)` (lines 121–134).
    - Sanitizes headers (`sanitize_headers`) and URLs (`sanitize_url`) when logging and creating Evidence records.
    - Emits `Evidence(category="HTTP Response", ...)` to `mission.evidence` (lines 226–274).
    - Provides HTTP method helpers: `get`, `post`, `put`, `patch`, `delete`, `head`, `options`.
- **File**: `/home/varun/argus/argus/http/__init__.py`
  - Currently exports `AuthorizedHttpClient` and `HttpResponse`.
- **Missing Features in Current Client**:
  - No session cookie management (cookies from `Set-Cookie` are not retained across subsequent requests).
  - No `TestIdentity` injection (does not apply active identity credentials, Bearer tokens, Basic auth, API keys, or cookies).
  - No scope gating for auth credential transmission (preventing leaking tokens to external hosts).
  - No `login()` method (cannot perform form/JSON auth to automatically retrieve session cookies or JWT tokens).
  - No proxy configuration parameter (`proxy="http://127.0.0.1:8080"`).
  - No retry policies with backoff for transient errors.

### 1.3 Test Suite Baseline & Patterns
- **Test Command**: `python3 -m pytest tests/ --ignore=tests/workspace -x -q`
- **Result**: `578 passed, 12348 warnings in 19.11s` (Exit code: 0).
- **Existing HTTP Tests**:
  - `tests/http/test_authorized_http_client.py`:
    - Spawns background thread running `http.server.HTTPServer` with `MockHttpHandler` on a free port.
    - Registers `test_mission` in `mission_manager._active_missions[mission.id] = mission`.
    - Tests scope blocking, auth gate blocking, header sanitization, timeout handling, connection errors, and evidence creation.
- **Fixture Pattern for Missions**:
  - Creating a `Mission(name="...", target="...")`, configuring `mission.scope = [...]`, and adding to `mission_manager._active_missions[mission.id] = mission`.

---

## 2. Logic Chain

### 2.1 `TestIdentity` Model Architecture Design
1. **Module Placement**:
   - Primary definition: `/home/varun/argus/argus/models/test_identity.py`.
   - Exported in `/home/varun/argus/argus/models/__init__.py` (`from .test_identity import TestIdentity, AuthType`).
   - Alias provided in `/home/varun/argus/argus/models/identity.py` (`from argus.models.test_identity import TestIdentity, AuthType`) to ensure seamless imports regardless of import path.
2. **Schema & Fields**:
   - `id: str = field(default_factory=lambda: str(uuid.uuid4()))`
   - `name: str = ""` (e.g. "admin_user", "tenant_a_user", "low_priv_user")
   - `role: str = "user"` (e.g. "admin", "user", "viewer", "guest", "anonymous")
   - `roles: list[str] = field(default_factory=list)`
   - `auth_type: str = "none"` (Enum `AuthType`: `BEARER`, `BASIC`, `API_KEY`, `COOKIE`, `OAUTH2`, `CUSTOM`, `NONE`)
   - `credentials: dict[str, Any] = field(default_factory=dict)` (e.g. `{"username": "...", "password": "..."}`, `{"token": "..."}`, `{"api_key": "...", "header_name": "X-API-Key"}`)
   - `headers: dict[str, str] = field(default_factory=dict)` (static or dynamic headers injected on requests)
   - `cookies: dict[str, str] = field(default_factory=dict)` (session cookies stored for this identity)
   - `is_active: bool = True`
   - `login_url: Optional[str] = None`
   - `login_payload: Optional[dict[str, Any]] = None`
   - `login_type: str = "json"` (`"json"`, `"form"`, `"basic"`)
   - `token: Optional[str] = None`
   - `metadata: dict[str, Any] = field(default_factory=dict)` (e.g. tenant_id, organization_id, permissions)
   - `created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())`
   - `updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())`
3. **Core Methods on `TestIdentity`**:
   - `to_dict() -> dict[str, Any]`
   - `classmethod from_dict(data: dict[str, Any]) -> TestIdentity`
   - `get_auth_headers() -> dict[str, str]`: Computes headers based on `auth_type`:
     - `bearer`: `{"Authorization": f"Bearer {self.token or self.credentials.get('token', '')}"}`
     - `basic`: `{"Authorization": "Basic " + base64(f"{u}:{p}")}`
     - `api_key`: `{header_name: key}`
     - `custom`: merges `self.headers`
     - `none`: `{}`
   - `get_cookies() -> dict[str, str]`
   - `update_session(cookies: dict = None, token: str = None, headers: dict = None)`
   - `clone(new_name: Optional[str] = None) -> TestIdentity`
4. **Integration with `Mission` (`argus/runtime/mission.py`)**:
   - Add fields to `Mission`:
     ```python
     test_identities: list[TestIdentity] = field(default_factory=list)
     active_identity_id: Optional[str] = None
     ```
   - Add helper methods to `Mission`:
     - `add_test_identity(self, identity: TestIdentity) -> TestIdentity`
     - `get_test_identity(self, identifier: str) -> Optional[TestIdentity]` (finds by ID or name)
     - `get_active_identity(self) -> Optional[TestIdentity]` (returns `active_identity_id` match, or first active `TestIdentity`, or None)
     - `set_active_identity(self, identifier: str) -> Optional[TestIdentity]`
     - `clear_test_identities(self) -> None`
     - `list_test_identities(self) -> list[TestIdentity]`

### 2.2 `AuthenticatedHttpClient` Architecture Design
1. **Module Placement & Compatibility**:
   - Location: `/home/varun/argus/argus/http/client.py`.
   - Exported in `/home/varun/argus/argus/http/__init__.py`.
   - Aliased in `/home/varun/argus/argus/client/authenticated.py` and `/home/varun/argus/argus/core/http.py`.
   - `AuthenticatedHttpClient` extends `AuthorizedHttpClient` to retain all existing capabilities (scope resolver, authorization gate, evidence recording, sanitization) while adding authentication persistence and login features.
2. **Session Cookie Management & Cookie Jar**:
   - Uses an underlying `httpx.Client(cookies=...)` or persistent `httpx.Cookies` jar across requests.
   - Automatically ingests cookies returned in `Set-Cookie` response headers.
   - If an active `TestIdentity` is used, updates `identity.cookies` with newly received session cookies.
   - Supports context manager (`__enter__` / `__exit__`) for clean session cleanup.
3. **Scope Gating on Auth Credential Transmission (Zero Credential Leakage)**:
   - Evaluates `self.scope_resolver.check_scope(url, mission.id)`.
   - If target domain is `OUT_OF_SCOPE`, blocks request immediately before any request headers/cookies are evaluated or dispatched over the wire.
   - Even on HTTP redirects, if follow redirects leads to an out-of-scope domain, credentials/cookies are stripped or redirect is blocked.
4. **Identity Injection**:
   - `request(mission, method, url, identity: Optional[TestIdentity] = None, ...)`
   - If `identity` is None, resolves `identity = getattr(self, "identity", None) or mission.get_active_identity()`.
   - If `identity` is present:
     - Injects headers from `identity.get_auth_headers()` unless overridden in explicit `headers` arg.
     - Injects cookies from `identity.get_cookies()` and client cookie jar.
5. **Automated `login()` Method**:
   - Signature: `login(self, mission, identity: TestIdentity, login_url: Optional[str] = None, payload: Optional[dict] = None, login_type: str = "json") -> HttpResponse`
   - Validates `login_url` against `ScopeResolver`.
   - Dispatches authentication request (POST JSON or Form data).
   - On success (2xx status):
     - Ingests `Set-Cookie` into `identity.cookies` and client cookie jar.
     - Inspects JSON response for token fields (`token`, `access_token`, `jwt`, `accessToken`, `data.token`, `auth_token`).
     - Updates `identity.token` and `identity.headers["Authorization"] = f"Bearer {token}"`.
     - Logs login success and creates Evidence entry.
6. **Proxy Support**:
   - Parameter `proxy: Optional[str] = None` in `__init__`.
   - Configures `httpx.Client(proxy=self.proxy, verify=False)` (allowing SSL inspection during authorized penetration testing).
7. **Retry & Timeout Policies**:
   - Configurable `timeout: float = 10.0`
   - Configurable `retries: int = 0` (or `max_retries: int = 3`) with exponential backoff on retryable status codes (`500, 502, 503, 504`) or transient network errors.

---

## 3. Caveats
- No caveats: Existing 578 tests pass completely with zero regressions.
- The `AuthorizedHttpClient` in `argus/http/client.py` is currently imported in GraphQL plugins (`argus/plugins/graphql/schema.py`) and tested in `tests/http/test_authorized_http_client.py`. `AuthenticatedHttpClient` must be fully backward-compatible with `AuthorizedHttpClient` so all existing imports and behaviors remain completely intact.

---

## 4. Conclusion
- `TestIdentity` should be implemented in `argus/models/test_identity.py` (with aliases and `__init__.py` export) as a comprehensive dataclass supporting full serialization (`to_dict`/`from_dict`), `AuthType` enum, auth header/cookie derivation, and session updates.
- `Mission` in `argus/runtime/mission.py` should be augmented with `test_identities: list[TestIdentity]` and helper methods (`add_test_identity`, `get_test_identity`, `get_active_identity`, `set_active_identity`, `clear_test_identities`, `list_test_identities`).
- `AuthenticatedHttpClient` should be implemented in `argus/http/client.py` (inheriting/extending `AuthorizedHttpClient`), exported in `argus/http/__init__.py`, supporting persistent `httpx.Client` cookie jar, scope gating before auth transmission, identity injection, automated `login()` for JSON and Form auth, proxy support, and retries.
- 15+ comprehensive unit and integration tests should be added across `tests/models/test_test_identity.py` and `tests/http/test_authenticated_http_client.py` using `mock_server` and `test_mission` fixtures.

---

## 5. Verification Method

### Test Commands
1. Run full test suite to verify zero regressions:
   ```bash
   python3 -m pytest tests/ --ignore=tests/workspace -x -q
   ```
2. Run HTTP client tests:
   ```bash
   python3 -m pytest tests/http/ -v
   ```
3. Run model tests:
   ```bash
   python3 -m pytest tests/models/ -v
   ```

### Verification Criteria
- All 578 existing tests pass with 0 failures.
- All new tests for `TestIdentity` and `AuthenticatedHttpClient` pass.
- `Mission` pickle serialization/deserialization with `TestIdentity` objects succeeds without errors.
- Out-of-scope requests to `AuthenticatedHttpClient` are blocked without transmitting auth headers or cookies.
- Form and JSON login properly extract cookies and JWT tokens into `TestIdentity`.
