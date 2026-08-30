# Sprint 13 Codebase Survey — Collector Architecture & Integration Blueprint

## 1. Observation

### 1.1 Existing Vulnerability Collectors and Base Class
We investigated the following collector implementations in `argus/collectors/`:
- **Base Collector Interface** (`argus/collectors/base.py`, lines 1-10):
  ```python
  from abc import ABC, abstractmethod

  class BaseCollector(ABC):
      @abstractmethod
      def collect(self, mission):
          """Collect information and update the mission."""
          pass
  ```
- **SQL Injection Collector** (`argus/collectors/sql_injection.py`, lines 533-1184):
  - Class: `SQLInjectionCollector(BaseCollector)`
  - Subcomponents: `SQLInjectionPayloadGenerator`, `SQLInjectionAnalyzer`
  - Techniques: Error-based, boolean-based blind, time-based blind delay with DBMS signatures (MySQL, PostgreSQL, MSSQL, Oracle, SQLite).
- **Cross-Site Scripting Collector** (`argus/collectors/xss.py`, lines 526-1079):
  - Class: `XSSCollector(BaseCollector)`
  - Subcomponents: `XSSPayloadGenerator`, `XSSAnalyzer`, `XSSContext`
  - Techniques: Reflected XSS, stored XSS (stateful POST then GET verification), DOM/attribute injection.
- **Path Traversal Collector** (`argus/collectors/path_traversal.py`, lines 225-591):
  - Class: `PathTraversalCollector(BaseCollector)`
  - Subcomponents: `PathTraversalPayloadGenerator`, `PathTraversalAnalyzer`
  - Signatures: UNIX (`/etc/passwd`, `/etc/shadow`, `/proc/self/environ`), Windows (`win.ini`, `boot.ini`).
- **Command Injection Collector** (`argus/collectors/command_injection.py`, lines 642-1339):
  - Class: `CommandInjectionCollector(BaseCollector)`
  - Subcomponents: `CommandInjectionPayloadGenerator`, `CommandInjectionAnalyzer`
  - Techniques: Result-based OS command injection, blind timing delay, error signatures.
- **SSRF Collector** (`argus/collectors/ssrf.py`, lines 942-1665):
  - Class: `SSRFCollector(BaseCollector)`
  - Subcomponents: `SSRFPayloadGenerator`, `SSRFAnalyzer`
  - Techniques: AWS/GCP/Azure/DigitalOcean metadata endpoints, internal RFC1918 probing, timing delays.
- **Access Control & IDOR Collector** (`argus/collectors/access_control.py`, lines 59-397):
  - Class: `AccessControlCollector(BaseCollector)`
  - Subcomponents: `ResponseDiscrepancyAnalyzer`
  - Techniques: Horizontal IDOR, vertical privilege escalation (admin route access by unprivileged user), reverse proxy header bypasses (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host`).
- **Information Disclosure Collector** (`argus/collectors/information_disclosure.py`, lines 23-556):
  - Class: `InformationDisclosureCollector(BaseCollector)`
  - Subcomponents: `SecretExtractor`

### 1.2 Collector Lifecycle Methods & Execution Pattern
Across all production collectors in Argus, the lifecycle follows an established 4-phase pattern:
1. **Instantiation (`__init__`)**:
   - Accepts optional `http_client` (defaults to `None` or instantiated `AuthenticatedHttpClient` / `MultiIdentitySessionCoordinator`), `payload_generator`, `analyzer`, and `timeout: float = 10.0`.
2. **Candidate Extraction (`_extract_candidate_endpoints(self, mission)`)**:
   - Reads `mission.endpoints` (can be list of dicts with `url`, `method`, `params`, `body`, `headers` or list of string URLs).
   - Reads `mission.live_hosts` and `mission.target` to construct base URLs and fallback probe routes.
   - Handles `ControlledMission` wrapper via `raw_mission = getattr(mission, "_mission", mission)`.
3. **Active Probing & Discrepancy/Vulnerability Analysis (`collect(self, mission) -> List[Evidence]`)**:
   - Executes HTTP requests via `_execute_request` or `_execute`.
   - Analyzes response body, status codes, headers, and response latency with dedicated Analyzers.
4. **State Mutation & Attack Surface Graph Expansion (`_create_evidence_and_update_state`)**:
   - Creates `Evidence` object (`argus/evidence/model.py`) with `status="CONFIRMED"`, `confidence` (0.95–1.0), and `severity` (`"critical"`, `"high"`, `"medium"`, `"low"`).
   - Appends to `raw_mission.evidence` (using `.add(ev)` if `EvidenceStore` or `.append(ev)` if `list`).
   - Appends finding dict to `raw_mission.vulnerabilities`.
   - Expands `mission.attack_surface_graph` / `mission.graph`:
     - Adds `Node(id="live_host:<host>", type="live_host", ...)`
     - Adds `Node(id="endpoint:<url>", type="endpoint", ...)`
     - Adds `Node(id="vulnerability:<template_id>:<url>...", type="vulnerability", ...)`
     - Connects `HAS_ENDPOINT` edge (`live_host` -> `endpoint`)
     - Connects `HAS_VULNERABILITY` edges (`live_host` -> `vulnerability` and `endpoint` -> `vulnerability`).
5. **Adapter Method (`execute(self, mission) -> List[Evidence]`)**:
   - Alias calling `self.collect(mission)` to support the plugin / specialist execution adapter interface.

### 1.3 HTTP Client Architecture & Authentication Management
Located in `argus/http/client.py` and `argus/http/coordinator.py`:
- **`AuthorizedHttpClient`** (`argus/http/client.py`, lines 86-298):
  - Wraps `httpx` with `ScopeResolver` (blocks requests to out-of-scope targets) and `authorization_gate` (verifies user/action permissions).
  - Sanitizes sensitive authorization headers, tokens, and cookies from audit logs while sending raw credentials on the wire.
  - Automatically emits `Evidence(category="HTTP Response", severity="info")` for every executed HTTP request.
- **`AuthenticatedHttpClient`** (`argus/http/client.py`, lines 300-587):
  - Subclasses `AuthorizedHttpClient`.
  - Maintains persistent `httpx.Client` session with connection pooling, retries, and backoff.
  - Injects `TestIdentity` credentials automatically into request headers (`Authorization: Bearer <token>`, `Authorization: Basic <base64>`, `X-API-Key`) and cookies.
  - Syncs incoming cookies from response headers back into `active_identity.cookies` via `active_identity.update_session(cookies=dict(response.cookies))`.
  - Implements `login(self, mission, identity, login_url, payload, login_type, headers)` to perform automated login and capture bearer/JWT tokens into identity state.
  - Supports context manager (`with AuthenticatedHttpClient(...) as client:`).
- **`MultiIdentitySessionCoordinator`** (`argus/http/coordinator.py`, lines 34-235):
  - Coordinates isolated `AuthenticatedHttpClient` instances per `TestIdentity.id` to guarantee isolated cookie jars and distinct session state.
  - Provides `get_client_for_identity(identity)` and `get_unauthenticated_client()`.
  - Provides `execute_as(identity, mission, method, url, **kwargs) -> HttpResponse`.
  - Provides `execute_comparison(mission, method, url, primary_identity, secondary_identity) -> MultiIdentityComparison`.

### 1.4 Pipeline Registration & Task DAG Architecture
- **Task Generator DAG** (`argus/planning/task_generator.py`, lines 13-146, 245-450):
  - `_RECON_TEMPLATES` catalog defines task metadata: `title`, `goal`, `category`, `required_inputs`, `expected_outputs`, `dependencies`, `metadata: {"tool_id": ...}`.
  - In `generate_recon_tasks()` and `_resolve_template_for_gap()`, collectors are scheduled with dependency on `katana_crawler` (i.e. `dependencies: ["Discover API Endpoints"]`).
- **Runtime Plugin Factory** (`argus/runtime/plugins.py`, lines 65-114):
  - `PluginExecutorAdapter._instantiate_specialist_fallback(plugin_id)` instantiates internal collectors by keyword matching (`sql_injection`, `access_control`, `path_traversal`, `xss`, `command_injection`, `ssrf`).
- **Attack Surface Graph Builder** (`argus/graph/attack_surface.py`, lines 454-630):
  - `AttackSurfaceGraphBuilder.build_from_evidence()` processes evidence categories and builds graph nodes and `HAS_VULNERABILITY` edges.
- **Baseline Test Suite**:
  - `python -m pytest tests/ --ignore=tests/workspace -x -q` passed with **1127 passed** in 48.43s.

---

## 2. Logic Chain

From the observations above, we establish the step-by-step logic for implementing Sprint 13 OAuth/OIDC, Token Validation, and Stateful Authentication collectors:

### Step 1: Collector Architecture & File Layout
To match the existing collector architecture (e.g. `SQLInjectionCollector`, `SSRFCollector`, `AccessControlCollector`), the new auth testing capabilities can be organized as either dedicated collectors or a cohesive module in `argus/collectors/oauth.py` (or `argus/collectors/auth_vulnerability.py` / `argus/collectors/oauth_oidc.py`):
1. **`OAuthOIDCCollector`** (or `OAuthCollector` in `argus/collectors/oauth.py` or `argus/collectors/oauth_oidc.py`):
   - Inherits from `BaseCollector`.
   - Coordinates tests across:
     - **OAuth/OIDC Flow Testing** (R1): Redirect URI manipulation, state parameter enforcement, token leakage via Referer, authorization code reuse.
     - **Token Validation Testing** (R2): Signature validation (`alg: none`, invalid signatures), claims validation (`exp`, `aud`, `iss`, `nbf`), token scope tampering.
     - **Stateful Authentication Testing** (R3): Session fixation, session invalidation on logout, cookie security attributes (`Secure`, `HttpOnly`, `SameSite`), concurrent session handling.
   - Includes subcomponents:
     - `OAuthPayloadGenerator`: Generates manipulated `redirect_uri` payloads (e.g., `https://attacker.com`, `https://target.com/../../attacker`, `https://target.com.attacker.com`, `https://attacker-target.com`), state manipulation vectors, and mock tokens.
     - `TokenValidationAnalyzer` / `JWTValidatorAnalyzer`: Generates tampered JWTs (`alg: none`, modified signatures, expired timestamps, forged claims, modified scopes) and evaluates whether endpoints accept or reject them.
     - `SessionWorkflowAnalyzer`: Inspects session cookies before and after login, post-logout invalidation, and validates cookie security attributes (`Secure`, `HttpOnly`, `SameSite`).

### Step 2: Evidence and Attack Surface Graph Integration
When a vulnerability is confirmed:
1. `Evidence` is created with:
   - `category`: `"oauth_oidc"` (or `"oauth_misconfiguration"`, `"token_validation"`, `"session_management"`).
   - `severity`: `"critical"` (for `alg:none` bypass, open redirect token leakage, invalid signature acceptance, session fixation) or `"high"` / `"medium"` (for missing state parameter, missing `Secure`/`HttpOnly` flags).
   - `status`: `"CONFIRMED"`.
   - `confidence`: `0.95` to `1.0`.
   - `tags`: `["oauth", "oidc", "token_validation", "session_management", template_id]`.
2. Graph Node & Edge Creation:
   - Adds `Node(id=lh_id, type="live_host", ...)`
   - Adds `Node(id=ep_id, type="endpoint", ...)`
   - Adds `Node(id=vuln_id, type="vulnerability", ...)`
   - Connects `graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")`
   - Connects `graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")`
3. Update `AttackSurfaceGraphBuilder` in `argus/graph/attack_surface.py` to ingest `"oauth_oidc"`, `"token_validation"`, and `"session_management"` categories into the graph.

### Step 3: Pipeline & Tool Registry Integration
1. **`argus/planning/task_generator.py`**:
   - Add `"oauth_oidc"` template to `_RECON_TEMPLATES`:
     ```python
     "oauth_oidc": {
         "title": "Analyze OAuth & OIDC Authentication",
         "goal": "Test OAuth/OIDC endpoints, token validation signatures/claims, and stateful session management using AuthenticatedHttpClient.",
         "category": TaskCategory.AUTHENTICATION_ANALYSIS,
         "required_inputs": ["endpoints"],
         "expected_outputs": ["vulnerabilities", "observations", "evidence"],
         "dependencies": ["Discover API Endpoints"],
         "required_specialists": [],
         "metadata": {"tool_id": "oauth_oidc"},
         "estimated_duration_minutes": 10,
         "priority": 0.82,
     }
     ```
   - Update `_resolve_template_for_gap()` to map auth gaps and keywords (`oauth`, `oidc`, `jwt`, `token validation`, `session management`) to `_RECON_TEMPLATES["oauth_oidc"]`.
2. **`argus/runtime/plugins.py`**:
   - Add `"oauth"` / `"oauth_oidc"` / `"oidc"` / `"token_validation"` cases in `PluginExecutorAdapter._instantiate_specialist_fallback` to return the new collector.
3. **`argus/collectors/__init__.py`**:
   - Export `OAuthOIDCCollector` (and any related analyzers/generators) and include in `__all__`.

---

## 3. Caveats

1. **Scope and Authorization Gate Enforcement**:
   - `AuthenticatedHttpClient` strictly verifies target URLs against `ScopeResolver`. During testing of `redirect_uri` manipulation pointing to external domains (e.g. `https://attacker.com`), requests sent directly to external domains might be blocked by the scope gate if not mocking client responses. The collector should test whether the *target authorization server* accepts and redirects to the manipulated URI (by analyzing the `Location` header in 302 responses or body from the in-scope target server) rather than attempting to navigate out of scope.
2. **Mock vs Real HTTP Client Injection**:
   - Following unit test patterns in `test_access_control.py` and `test_ssrf.py`, collectors must accept an optional `http_client` in `__init__`. The collector's `_execute_request` method must support injected mock clients with custom routing and response structures.
3. **Deprecation Warnings in Test Suite**:
   - Notice in the test output that `datetime.datetime.utcnow()` and per-request `cookies` produce deprecation warnings in Python 3.13. New code should use `datetime.now(timezone.utc).isoformat()` and standard cookie dictionaries.

---

## 4. Conclusion

The Argus collector subsystem is highly consistent across SQLi, XSS, Path Traversal, CMDi, SSRF, and Access Control. Implementing the Sprint 13 OAuth/OIDC and Stateful Authentication modules requires:

### Exact File & Class Implementation Blueprint

| Component | Target File | Class / Function Names | Responsibilities |
|---|---|---|---|
| **Collector Core** | `argus/collectors/oauth.py` (or `oauth_oidc.py`) | `OAuthOIDCCollector(BaseCollector)` | Orchestrates R1 (OAuth redirect/state/leakage/reuse), R2 (JWT alg:none, signature, claims, scope), and R3 (session fixation, logout invalidation, cookie attributes). |
| **Payload Generator** | `argus/collectors/oauth.py` | `OAuthPayloadGenerator` | Produces manipulated redirect URIs, forged JWTs (`alg:none`, expired `exp`, bad `aud`/`iss`, reduced scope), and test state parameters. |
| **Analyzers** | `argus/collectors/oauth.py` | `OAuthAnalyzer`, `TokenValidationAnalyzer`, `SessionSecurityAnalyzer` | Detects open redirects, missing state, signature bypasses, claim acceptance, session fixation, and missing cookie flags. |
| **Exports** | `argus/collectors/__init__.py` | Export `OAuthOIDCCollector`, etc. | Registers classes into collector module namespace. |
| **Graph Builder** | `argus/graph/attack_surface.py` | `AttackSurfaceGraphBuilder.build_from_evidence()` | Ingests `oauth_oidc`, `token_validation`, `session_management` evidence categories to construct `HAS_VULNERABILITY` edges. |
| **Task Generator** | `argus/planning/task_generator.py` | `_RECON_TEMPLATES["oauth_oidc"]`, `_resolve_template_for_gap` | Schedules OAuth/OIDC analysis in DAG after `Discover API Endpoints`. |
| **Plugin Adapter** | `argus/runtime/plugins.py` | `_instantiate_specialist_fallback` | Instantiates `OAuthOIDCCollector` on `oauth_oidc` / `oauth` / `token_validation` tool IDs. |
| **Test Suite** | `tests/collectors/test_oauth.py` (and adversarial tests) | Unit and integration tests (20+ tests) | Validates R1-R4 acceptance criteria: open redirect detection, alg:none rejection, session cookie flags, false positive suppression, DAG & graph edge verification. |

---

## 5. Verification Method

To verify existing functionality and any proposed changes:
1. Run the test suite:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   **Expected**: 1127+ passed, 0 failures.
2. Verify collector interface conformance:
   - Ensure `OAuthOIDCCollector` inherits from `BaseCollector` and implements both `collect(self, mission)` and `execute(self, mission)`.
   - Ensure `Evidence` created by the collector uses standard fields (`category`, `severity`, `confidence`, `metadata`, `provenance`).
   - Ensure graph nodes (`type="live_host"`, `type="endpoint"`, `type="vulnerability"`) and edges (`HAS_ENDPOINT`, `HAS_VULNERABILITY`) are created properly.
3. Verify test coverage:
   - Add new tests in `tests/collectors/test_oauth.py` (or `test_oauth_oidc.py`) covering all acceptance criteria with mock HTTP clients.
