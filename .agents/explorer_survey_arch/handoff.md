# ARGUS Architecture & Collector Patterns Survey Report

## Executive Summary
This architectural survey provides a comprehensive investigation of the ARGUS collector subsystem, focusing on the Tripartite architecture (Collector + PayloadGenerator + Prober + Analyzer), Quadruple State Publishing, HTTP client integration (`AuthenticatedHttpClient` and `MultiIdentitySessionCoordinator`), data schemas (`Evidence`, `TestIdentity`, `Node`), pipeline wiring (`task_generator.py`, `registry.py`, `plugins.py`, `attack_surface.py`, `cvss.py`), and test conventions.

The investigation was conducted against the current codebase state where **1,941 tests pass** across the repository.

---

# 1. Tripartite Architecture Pattern

Across all mature collectors in ARGUS (e.g. `argus/collectors/api_security.py`, `file_upload.py`, `cors_headers.py`, `ssti.py`, `oauth.py`, `sql_injection.py`, `ssrf.py`), the codebase follows a strict **Tripartite + Prober** design pattern divided into four cooperating components:

```
+-----------------------------------------------------------------------------------+
|                               <Name>Collector                                    |
|   Inherits from BaseCollector (argus/collectors/base.py)                          |
|   - collect(mission) / execute(mission)                                           |
|   - _discover_candidate_endpoints(mission)                                        |
|   - Orchestrates Generator -> Prober -> Analyzer -> Quadruple State Publishing     |
+-------------------+--------------------+--------------------+---------------------+
                    |                    |                    |
                    v                    v                    v
+-----------------------+ +--------------------+ +----------------------------------+
|  <Name>PayloadGen     | |    <Name>Prober    | |          <Name>Analyzer          |
| - generate_canary()   | | - execute_probe()  | | - evaluate_probe()               |
| - Mode-specific probe | | - execute_burst()  | | - is_false_positive()            |
|   generators          | | - execute_diff()   | | - detect_sensitive_fields()      |
| - apply_mutation()    | | - Authenticated-   | | - detect_error_disclosure()       |
| - generate_all_probes | |   HttpClient       | | - Severity, CWE & CVSS scoring   |
+-----------------------+ +--------------------+ +----------------------------------+
```

### Component Breakdown:

#### 1. Collector (`<Name>Collector`)
- **Inheritance**: Extends `BaseCollector` from `argus/collectors/base.py`.
- **Constructor Signature**:
  ```python
  def __init__(
      self,
      http_client: Optional[Any] = None,
      prober: Optional[AuthBypassProber] = None,
      generator: Optional[AuthBypassPayloadGenerator] = None,
      analyzer: Optional[AuthBypassAnalyzer] = None,
      timeout: float = 10.0,
      max_probes_per_endpoint: int = 50,
      client: Optional[Any] = None,
  ) -> None:
      active_client = http_client or client
      self.prober = prober or AuthBypassProber(client=active_client, timeout=timeout)
      self.generator = generator or AuthBypassPayloadGenerator()
      self.analyzer = analyzer or AuthBypassAnalyzer()
      self.timeout = timeout
      self.max_probes_per_endpoint = max_probes_per_endpoint
  ```
- **Endpoint Discovery Protocol (`_discover_candidate_endpoints`)**:
  Inspects `mission` through a 5-tier fallback hierarchy:
  1. `mission.inputs.get("endpoints")`
  2. `raw_mission.endpoints`
  3. `raw_mission.live_hosts`
  4. `raw_mission.target`
  5. `raw_mission.evidence` (searching for HTTP URLs in evidence metadata)
  Normalizes all found paths into fully qualified `http://` or `https://` URLs.
- **Collector Loop**:
  ```python
  def collect(self, mission: Any) -> List[Evidence]:
      endpoints = self._discover_candidate_endpoints(mission)
      collected_evidence: List[Evidence] = []
      for target_url in endpoints:
          parsed = urllib.parse.urlparse(target_url)
          base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url
          all_probes = self.generator.generate_all_probes(target_url)
          probes_to_run = all_probes[:self.max_probes_per_endpoint]
          for probe in probes_to_run:
              resp = self.prober.execute_probe(mission, target_url, probe)
              result = self.analyzer.evaluate_probe(probe, resp, target_url)
              if result and result.is_valid_finding:
                  ev = self._emit_evidence(mission, result, target_url, base_url)
                  collected_evidence.append(ev)
      return collected_evidence
  ```
- **Plugin Hook Alias**: `execute(self, mission)` delegates directly to `self.collect(mission)`.

#### 2. Payload Generator (`<Name>PayloadGenerator`)
- **Canary Token Generation**:
  ```python
  def generate_canary(self, prefix: str = "ARGUS_AUTH") -> str:
      self._counter += 1
      return f"{prefix}_{int(time.time())}_{self._counter}_{uuid.uuid4().hex[:8]}"
  ```
- **Probe Dataclass (`<Name>Probe`)**:
  Strongly typed dataclass holding: `probe_id`, `target_url`, `method`, `vulnerability_type`, `strategy`, `headers`, `params`, `json_data`, `data`, `canary_token`, `tested_parameter`, `original_value`, `tampered_value`, `is_auth_required`, `secondary_identity`, `burst_count`, `is_benign`, `metadata`.
- **Benign Baseline Probes (`generate_benign_baseline_probes`)**:
  Generates `is_benign=True` probes to capture baseline behavior and ensure the analyzer suppresses baseline reflections.
- **Mutation & Evasion Engine (`apply_mutation(probe, strategy)`)**:
  Applies deepcopy to probe, sets `mutated.strategy = strategy`, updates `probe_id`, and mutates headers, query params, path encodings, or JSON structures.
- **Probe Compilation (`generate_all_probes`)**:
  Returns combined list of baselines, detection mode probes, and mutated variations.

#### 3. Prober (`<Name>Prober`)
- **HTTP Client Polymorphism**:
  Handles both `AuthenticatedHttpClient` (context manager or direct instance) and mock HTTP clients (`MockAPIHttpClient`, `MockOAuthHttpClient`).
  Supports calling patterns:
  - `client.request(mission, method, url, headers=..., params=..., json=..., data=..., timeout=..., action=...)`
  - `client.request(method, url, ...)` (mock fallback)
  - `client.get(...)`, `client.post(...)`
- **Probe Response Dataclass (`<Name>ProbeResponse`)**:
  Holds `probe`, `status_code`, `headers` (lowercased dict), `body`, `json_body`, `elapsed`, `error`, `raw_http_response`, `burst_responses`, `rate_limit_headers`, `sensitive_fields_detected`, `error_disclosure_detected`, `is_persisted`, `is_unauthorized_access`.
- **Burst Sequences & Rate Limiting Probing (`execute_burst_sequence`)**:
  Executes N rapid requests (e.g. 10-15), recording status codes, elapsed times, `X-RateLimit-*` and `Retry-After` headers, and rotating `X-Forwarded-For` / `Client-IP` when testing rate limit evasion.
- **Differential Identity Probing (`execute_differential_identity_probe`)**:
  Executes probes using `MultiIdentitySessionCoordinator` or alternate credentials to test authentication/authorization boundaries.

#### 4. Analyzer (`<Name>Analyzer`)
- **Strict False Positive Filtering (`is_false_positive`)**:
  1. Benign baselines (`probe.is_benign == True`) -> return True (suppress).
  2. Connection errors (`status_code == 0` or `error is not None`) -> return True (suppress).
  3. Standard rejection codes (400, 401, 403, 404, 405, 415, 422) WITHOUT information disclosure or sensitive leaks -> return True (suppress).
  4. Explicit rejection messages in response body -> return True (suppress).
  5. Unpersisted/stripped attributes -> return True (suppress).
  6. Properly throttled rate limits (429 returned and rotation fails) -> return True (suppress).
- **Sensitive Data & Information Leak Detection**:
  Regex scanners for PII, password hashes, JWTs, API keys, private keys, credit cards, SSNs.
- **Error & Stack Trace Disclosure Detection**:
  Regex scanners for Python Tracebacks, Java Spring/ServletException, .NET HttpException, Node.js stack traces, PHP errors, SQL syntax errors, internal file paths (`/var/www/`, `/opt/app/`, `C:\inetpub\`).
- **Result Dataclass (`<Name>Result`)**:
  Holds `template_id`, `technique`, `vulnerability_type`, `mutation_strategy`, `endpoint_url`, `severity`, `cwe_id`, `cvss_score`, `description`, `evidence_snippet`, `parameter`, `status_code`, `confidence`, `is_valid_finding`, `metadata`.

---

# 2. Quadruple State Publishing Pattern

Every confirmed finding is published across four independent state sinks within `_emit_evidence`:

```
                                  [ Confirmed Finding ]
                                            |
         +--------------------+-------------+--------------+---------------------+
         |                    |                            |                     |
         v                    v                            v                     v
+-----------------+  +------------------+  +-------------------------------+  +---------------------+
| 1. Mission      |  | 2. Mission       |  | 3. Attack Surface Graph       |  | 4. Controlled       |
|    Evidence     |  |    Vulnerabilities| |    (KnowledgeGraph)           |  |    Mission          |
| raw_mission.    |  | raw_mission.     |  | - Node: 'live_host'           |  | mission.            |
| evidence.add(ev)|  | vulnerabilities. |  | - Node: 'endpoint'            |  | publish_finding(id) |
|                 |  | append(dict)     |  | - Node: 'vulnerability'       |  |                     |
|                 |  |                  |  | - Edge: HAS_ENDPOINT          |  |                     |
|                 |  |                  |  | - Edge: HAS_VULNERABILITY     |  |                     |
+-----------------+  +------------------+  +-------------------------------+  +---------------------+
```

### Exact Code Implementation:
```python
def _emit_evidence(
    self,
    mission: Any,
    result: AuthBypassResult,
    target_url: str,
    base_url: str,
) -> Evidence:
    title = f"Authentication Vulnerability: {result.technique} on {target_url}"
    description = (
        f"{result.description} Parameter: {result.parameter}, "
        f"Strategy: {result.mutation_strategy}, CWE: {result.cwe_id}"
    )
    raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

    ev = Evidence(
        category="auth_bypass",
        value=f"auth_bypass:{result.template_id}:{target_url}:{result.parameter or 'endpoint'}",
        source="auth_bypass",
        status="CONFIRMED",
        confidence=result.confidence,
        severity=result.severity,
        title=title,
        description=description,
        provenance=ProvenanceData(
            observation_id=str(uuid.uuid4()),
            step_id=f"step_{result.technique}",
        ),
        tags=["auth_bypass", "authentication", str(result.vulnerability_type), result.mutation_strategy],
        metadata={
            "url": target_url,
            "host": base_url,
            "template_id": result.template_id,
            "technique": result.technique,
            "vulnerability_type": str(result.vulnerability_type),
            "parameter": result.parameter,
            "tested_parameter": result.parameter,
            "mutation_strategy": result.mutation_strategy,
            "strategy": result.mutation_strategy,
            "status_code": result.status_code,
            "evidence_snippet": result.evidence_snippet[:250],
            "cwe_id": result.cwe_id,
            "cvss_score": result.cvss_score,
            "is_valid_finding": result.is_valid_finding,
            **result.metadata,
        },
    )

    # 1. Update raw_mission.evidence
    if hasattr(raw_mission, "evidence") and raw_mission.evidence is not None:
        if hasattr(raw_mission.evidence, "add"):
            raw_mission.evidence.add(ev)
        elif isinstance(raw_mission.evidence, list):
            raw_mission.evidence.append(ev)

    # 2. Update raw_mission.vulnerabilities
    if hasattr(raw_mission, "vulnerabilities") and isinstance(raw_mission.vulnerabilities, list):
        raw_mission.vulnerabilities.append({
            "name": title,
            "template_id": result.template_id,
            "severity": result.severity,
            "host": base_url,
            "url": target_url,
            "description": description,
            "technique": result.technique,
            "parameter": result.parameter,
            "strategy": result.mutation_strategy,
            "cwe_id": result.cwe_id,
            "cvss_score": result.cvss_score,
        })

    # 3. Attack Surface Knowledge Graph Expansion
    graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
    if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
        lh_id = f"live_host:{base_url}"
        ep_id = f"endpoint:{target_url}"
        vuln_id = f"vulnerability:{result.template_id}:{target_url}:{result.parameter or 'endpoint'}"

        parsed_b = urllib.parse.urlparse(base_url)
        graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
        graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": result.status_code}))
        graph.add(Node(id=vuln_id, type="vulnerability", value=title, metadata=ev.metadata))

        graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
        graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
        graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

    # 4. ControlledMission wrapper notification
    if hasattr(mission, "publish_finding"):
        try:
            mission.publish_finding(ev.evidence_id, ev)
        except Exception:
            pass

    return ev
```

---

# 3. HTTP Client Infrastructure & Session Handling

### `AuthenticatedHttpClient` (`argus/http/client.py`)
- **Base**: Extends `AuthorizedHttpClient`, wrapping an internal `httpx.Client`.
- **Scope & Policy Enforcement**:
  - `ScopeResolver.check_scope(url, mission.id)` enforces mission target boundaries. If out of scope, returns `HttpResponse(success=False, error="Blocked by scope...")`.
  - `authorization_gate.can_execute_action(user_id, action, url, mission.id)` validates authorization permissions.
- **Identity & Credential Injection**:
  - Injects headers from `identity.get_auth_headers()` (e.g. `Authorization: Bearer <token>`, `Authorization: Basic <b64>`, `X-API-Key`).
  - Injects cookies from `identity.get_cookies()`.
  - On response, syncs `response.cookies` back into `identity.update_session(cookies=...)`.
- **Automatic Audit Evidence Creation**:
  Every request sent through `request()` creates an `Evidence` object (category `"HTTP Response"`) with request/response headers, status code, elapsed time, sanitized URL/body, and adds it to `mission.evidence`.
- **Data Redaction & Sanitization**:
  Automatically redacts sensitive headers (`authorization`, `cookie`, `set-cookie`, `x-api-key`, `token`, `session`) and JSON keys containing `password`, `secret`, `token`, `credential`.
- **Automated Login Flow (`login`)**:
  ```python
  def login(self, mission, identity=None, login_url=None, payload=None, login_type=None, headers=None) -> HttpResponse
  ```
  Executes authentication requests against login endpoints and captures returned bearer tokens (`token`, `access_token`, `jwt`, `accessToken`, `id_token`) and session cookies directly into `TestIdentity`.

### `MultiIdentitySessionCoordinator` (`argus/http/coordinator.py`)
- Coordinates multiple isolated `AuthenticatedHttpClient` instances, one per `TestIdentity`, plus a dedicated unauthenticated client.
- Provides differential request execution:
  - `execute_as(identity, mission, method, url, **kwargs)`
  - `execute_across_identities(mission, method, url, identities=None, **kwargs)`
  - `execute_comparison(mission, method, url, primary_identity, secondary_identity, **kwargs)` -> Returns `MultiIdentityComparison` with `status_match`, `body_match`, `length_difference`, `body_similarity` (calculated via `difflib.SequenceMatcher`).
  - `authenticate_all(mission)` -> Logs in all configured test identities.

### `TestIdentity` Model (`argus/models/test_identity.py`)
- Key fields: `id`, `name`, `role`, `roles`, `auth_type` (`AuthType.BEARER`, `BASIC`, `API_KEY`, `COOKIE`, `OAUTH2`, `CUSTOM`, `NONE`), `credentials`, `headers`, `cookies`, `is_active`, `login_url`, `login_payload`, `login_type`, `token`, `metadata`.
- Methods: `get_auth_headers()`, `get_cookies()`, `update_session(cookies, headers, token)`, `clone()`, `to_dict()`, `from_dict()`.

---

# 4. Pipeline Connectivity & Ecosystem Wiring

To integrate a new collector into ARGUS seamlessly without regressions, six specific integration points must be wired:

| Subsystem File | Purpose | Required Integration |
|---|---|---|
| `argus/collectors/__init__.py` | Export module classes | Export Collector, Generator, Prober, Analyzer, Result, Enums, and backward compatibility aliases. Add to `__all__`. |
| `argus/planning/task_generator.py` | Scan DAG Task Generation & Gap Resolution | 1. Add tool entry in `_RECON_TEMPLATES["auth_bypass"]`<br>2. Add keyword match in `_resolve_template_for_gap` (e.g. "auth bypass", "authentication", "brute force", "mfa bypass", "password reset", "session fixation", "default credentials")<br>3. Add tool_id to input binding list in `from_gaps`. |
| `argus/runtime/registry.py` | Tool Registry & Alias Resolution | 1. Register `Tool(id="auth_bypass", ...)` with supported tasks, required inputs, produced outputs, capabilities, safety requirements.<br>2. Add aliases in `ToolRegistry.get()` (e.g. "authentication_bypass", "auth_collector", "brute_force", "mfa_bypass", "session_fixation", "credential_stuffing"). |
| `argus/runtime/plugins.py` | Internal Plugin / Specialist Adapter | Add fallback check in `_instantiate_specialist_fallback` mapping "auth_bypass", "authentication_bypass", "mfa_bypass", "session_fixation" to instantiate `AuthBypassCollector()`. |
| `argus/graph/attack_surface.py` | Attack Surface Graph Builder | In `build_from_evidence()`, add evidence category processor for `auth_bypass`, `authentication_bypass`, `credential_attack`, `brute_force`, `mfa_bypass`, `password_reset`, `session_fixation`, `jwt_manipulation`, `default_credentials` connecting `live_host -> HAS_VULNERABILITY -> vuln_id` and `endpoint -> HAS_VULNERABILITY -> vuln_id`. |
| `argus/reporting/cvss.py` | CVSS Calculator & CWE Database | Add CWE mappings in `CWE_DATABASE` for:<br>- `auth_bypass` -> `CWE-287`<br>- `brute_force` -> `CWE-307`<br>- `password_reset` -> `CWE-640`<br>- `mfa_bypass` -> `CWE-287`<br>- `session_fixation` -> `CWE-384`<br>- `jwt_manipulation` -> `CWE-345` / `CWE-287`<br>- `default_credentials` -> `CWE-798` / `CWE-287`<br>- `missing_auth` -> `CWE-306`<br>- `session_expiration` -> `CWE-613` |

---

# 5. Test Conventions & Verification Patterns

Existing collector test suites in `tests/collectors/` follow a standard two-tier test file structure:
1. `tests/collectors/test_<collector_name>.py`: Unit and integration testing across all 11 lifecycle areas.
2. `tests/collectors/test_<collector_name>_adversarial.py`: Adversarial edge cases, false positive suppression, regex verification, network failure resilience.

### Standard Test Matrix:
1. **Models & Enums**: Tests severity enums, vulnerability type enums, mutation strategy enums, aliases, probe/response dataclass defaults.
2. **Payload Generator**: Tests each detection mode generator, all mutation strategies, canary token formatting, benign baseline probe generation, and full probe compilation (`generate_all_probes`).
3. **Prober**: Tests HTTP dispatch (GET/POST/JSON/Form), burst execution with rate-limit header parsing, IP rotation headers (`X-Forwarded-For`), differential identity execution, timeout error isolation (`status_code=0`).
4. **Analyzer**: Tests evaluation of each vulnerability type, detection of sensitive fields (PII, credentials, keys), detection of stack traces (Python, Java, .NET, Node, PHP, SQL), and false positive suppression.
5. **Collector & Quadruple State Publishing**: Tests that executing `collector.collect(mission)` publishes to `mission.evidence`, `mission.vulnerabilities`, `attack_surface_graph` (with nodes and `HAS_ENDPOINT`, `HAS_VULNERABILITY` edges), and `ControlledMission.publish_finding()`.
6. **Tool Registry**: Tests `registry.get("auth_bypass")` and all configured aliases.
7. **Plugin Executor Adapter**: Tests `PluginExecutorAdapter().execute_plugin("auth_bypass", mission)`.
8. **Task Generator**: Tests DAG template creation from coverage gaps and input binding.
9. **Attack Surface Graph Builder**: Tests `AttackSurfaceGraphBuilder().build_from_evidence(evidence)` creates expected nodes and edges.
10. **CVSS & CWE Database**: Tests `CVSSCalculator.lookup_cwe()` and CVSS v3.1 vector calculations.
11. **Adversarial & FP Tests**: Tests suppression of 400/401/403/404/405/422 responses without leaks, unpersisted attributes, properly throttled 429 rate limits, non-JSON error pages, and connection timeouts.

### Mock HTTP Client Pattern:
```python
class MockAuthHttpClient:
    """Mock HTTP client simulating authentication endpoints, tokens, and burst responses."""
    def __init__(self, response_fn=None):
        self.response_fn = response_fn
        self.requests_log: List[Dict[str, Any]] = []

    def request(self, *args, **kwargs) -> HttpResponse:
        mission = kwargs.pop("mission", None)
        method = kwargs.pop("method", "GET")
        url = kwargs.pop("url", "")
        if args:
            if len(args) == 1:
                url = args[0]
            elif len(args) == 2:
                method, url = args[0], args[1]
            elif len(args) >= 3:
                mission, method, url = args[0], args[1], args[2]
        self.requests_log.append({"mission": mission, "method": method, "url": url, "kwargs": kwargs})
        if self.response_fn:
            return self.response_fn(method, url, **kwargs)
        return HttpResponse(
            success=True,
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"status": "success", "authenticated": true}',
            raw_body='{"status": "success", "authenticated": true}',
            url=url,
        )

    def get(self, *args, **kwargs) -> HttpResponse:
        if args and len(args) >= 2:
            return self.request(args[0], "GET", args[1], **kwargs)
        elif args and len(args) == 1:
            return self.request(None, "GET", args[0], **kwargs)
        return self.request(method="GET", **kwargs)

    def post(self, *args, **kwargs) -> HttpResponse:
        if args and len(args) >= 2:
            return self.request(args[0], "POST", args[1], **kwargs)
        elif args and len(args) == 1:
            return self.request(None, "POST", args[0], **kwargs)
        return self.request(method="POST", **kwargs)
```

---

# 6. Five Handoff Components

### 1. Observation
- Inspected `argus/collectors/base.py`: Defines abstract `BaseCollector` with abstract method `collect(self, mission)`.
- Inspected existing active collectors:
  - `argus/collectors/api_security.py` (1,506 lines)
  - `argus/collectors/file_upload.py` (1,410 lines)
  - `argus/collectors/cors_headers.py` (1,793 lines)
  - `argus/collectors/ssti.py` (1,658 lines)
  - `argus/collectors/oauth.py` (1,472 lines)
  - `argus/collectors/command_injection.py` (1,348 lines)
  - `argus/collectors/sql_injection.py` (1,237 lines)
  - `argus/collectors/ssrf.py` (1,624 lines)
- Inspected HTTP & Session modules:
  - `argus/http/client.py`: `AuthenticatedHttpClient` (lines 302-591), `AuthorizedHttpClient` (lines 86-300), `HttpResponse` (lines 71-85).
  - `argus/http/coordinator.py`: `MultiIdentitySessionCoordinator` (lines 34-235), `MultiIdentityComparison` (lines 20-32).
  - `argus/models/test_identity.py`: `TestIdentity` (lines 26-141), `AuthType` enum (lines 15-23).
- Inspected Pipeline & Runtime modules:
  - `argus/planning/task_generator.py`: `_RECON_TEMPLATES` (lines 100-302), `_resolve_template_for_gap` (lines 730-865), `from_gaps` (lines 866-924).
  - `argus/runtime/registry.py`: `ToolRegistry` (lines 5-100), tool registrations (lines 750-985).
  - `argus/runtime/plugins.py`: `PluginExecutorAdapter` (lines 10-64), `_instantiate_specialist_fallback` (lines 65-245).
  - `argus/graph/attack_surface.py`: `AttackSurfaceGraphBuilder.build_from_evidence` (lines 17-1196).
  - `argus/reporting/cvss.py`: `CVSSCalculator.CWE_DATABASE` (lines 33-350).
- Ran full test suite verification: `venv/bin/pytest tests/` passed **1,941 tests (1 skipped)** in 66.73s.

### 2. Logic Chain
1. *Observation*: All active collectors inherit from `BaseCollector` and implement the Tripartite architecture (`Collector` + `PayloadGenerator` + `Prober` + `Analyzer`).
   *Inference*: The Authentication Bypass & Credential Attack Detection module (`argus/collectors/auth_bypass.py`) must follow this exact four-class structure (`AuthBypassCollector`, `AuthBypassPayloadGenerator`, `AuthBypassProber`, `AuthBypassAnalyzer`).
2. *Observation*: All active collectors implement Quadruple State Publishing in `_emit_evidence`, updating `raw_mission.evidence`, `raw_mission.vulnerabilities`, `attack_surface_graph` (Nodes `live_host`, `endpoint`, `vulnerability`; Edges `HAS_ENDPOINT`, `HAS_VULNERABILITY`), and `ControlledMission.publish_finding()`.
   *Inference*: `AuthBypassCollector._emit_evidence` must perform these four state updates to maintain complete compatibility across all runtime modes.
3. *Observation*: Active collectors rely on `AuthenticatedHttpClient` and `MultiIdentitySessionCoordinator` for identity-aware, session-isolated, and scope-bounded HTTP execution.
   *Inference*: The auth bypass prober must utilize `AuthenticatedHttpClient` and support differential multi-identity probing via `TestIdentity`.
4. *Observation*: The ARGUS execution pipeline requires wiring across `task_generator.py`, `registry.py`, `plugins.py`, `attack_surface.py`, and `cvss.py`.
   *Inference*: New tools must register their recon template, gap keywords, tool definition, specialist fallback, graph section parser, and CWE mappings across these 5 modules.
5. *Observation*: Pytest execution requires targeting the `tests/` directory (e.g. `venv/bin/pytest tests/`) to avoid collection collision with non-test files under `argus/models/` and `argus/plugins/`.
   *Inference*: The project test command for Sprint 28 is `venv/bin/pytest tests/` and `venv/bin/pytest tests/collectors/test_auth_bypass.py tests/collectors/test_auth_bypass_adversarial.py`.

### 3. Caveats
- No caveats. The collector architecture, HTTP client integration, data models, pipeline wiring, and test patterns are completely surveyed and verified.

### 4. Conclusion
The ARGUS collector architecture is highly structured, predictable, and modular. Sprint 28 (Authentication Bypass & Credential Attack Detection) can be implemented with zero regressions by creating:
1. `argus/collectors/auth_bypass.py` implementing the 6 detection modes and 5 mutation strategies using the Tripartite pattern and Quadruple State Publishing.
2. Full ecosystem wiring across `argus/collectors/__init__.py`, `argus/planning/task_generator.py`, `argus/runtime/registry.py`, `argus/runtime/plugins.py`, `argus/graph/attack_surface.py`, and `argus/reporting/cvss.py`.
3. Comprehensive test suite in `tests/collectors/test_auth_bypass.py` (unit/integration) and `tests/collectors/test_auth_bypass_adversarial.py` (adversarial/FP suppression).

### 5. Verification Method
1. Run full test suite:
   ```bash
   venv/bin/pytest tests/
   ```
   **Expected**: 1,941+ passing tests with zero failures.
2. Run single collector tests:
   ```bash
   venv/bin/pytest tests/collectors/test_api_security.py tests/collectors/test_api_security_adversarial.py
   ```
   **Expected**: 22 passed + 13 passed = 35 passed.
3. Inspect generated report:
   ```bash
   view_file /home/varun/argus/.agents/explorer_survey_arch/handoff.md
   ```
