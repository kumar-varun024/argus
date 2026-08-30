# Codebase Architecture Survey & Handoff Report — ARGUS Sprint 9 (Database Query Safety Validation Engine)

## 1. Observation

### 1.1 Base Collector & Existing Implementations
- **Base Collector Interface**:
  - Defined in `argus/collectors/base.py` (lines 4–9):
    ```python
    class BaseCollector(ABC):
        @abstractmethod
        def collect(self, mission):
            """Collect information and update the mission."""
            pass
    ```
- **Sprint 5 (Information Disclosure Collector)**:
  - File: `argus/collectors/information_disclosure.py` (588 lines).
  - Structure:
    - `DEFAULT_WORDLIST`: Static list of sensitive probe paths (`.git/config`, `.env`, `phpinfo.php`, `/actuator/env`, etc.).
    - `SecretExtractor`: Regex catalog for credentials (AWS keys, Google API keys, Stripe keys, GitHub tokens, Slack webhooks, JWTs, DB connection strings) and internal domains/IPs.
    - `InformationDisclosureCollector(BaseCollector)`: Probes target endpoints and live hosts using `AuthenticatedHttpClient`, parses responses, emits `Evidence(category="information_disclosure", severity="high")`, and populates `mission.evidence`, `mission.vulnerabilities`, and `mission.attack_surface_graph` with `HAS_ENDPOINT`, `HAS_VULNERABILITY`, `EXPOSES_SECRET`, `DISCLOSED_SUBDOMAIN`.
- **Sprint 6 (Access Control / IDOR Collector)**:
  - File: `argus/collectors/access_control.py` (397 lines).
  - Structure:
    - Multi-identity test execution across `TestIdentity` pairs via `MultiIdentitySessionCoordinator`.
    - Differential comparison via `ResponseDiscrepancyAnalyzer` (`argus/analyzers/response_discrepancy.py`).
    - Input extraction unwraps `raw_mission = getattr(mission, "_mission", mission)` (line 263).
    - Emits `Evidence(category="broken_access_control", severity="critical")`.
- **Sprint 8 (Path Traversal Collector)**:
  - File: `argus/collectors/path_traversal.py` (591 lines).
  - Structure:
    - `DEFAULT_TRAVERSAL_PAYLOADS`: Path traversal sequences (relative `../../`, nested `....//`, URL encoded `%2e%2e%2f`, double encoded `%252e%252e%252f`, overlong UTF-8, null byte bypasses `%00`, Windows `c:\windows\win.ini`, `c:\boot.ini`).
    - `PathTraversalPayloadGenerator`: Returns base payloads and customizable variations.
    - `PathTraversalAnalyzer`: OS signature matching (`UNIX_PASSWD_REGEX`, `UNIX_SHADOW_REGEX`, `UNIX_ENVIRON_REGEX`, `WINDOWS_INI_REGEX`, `WINDOWS_BOOT_REGEX`), baseline differential filtering, reflection guard.
    - `PathTraversalCollector(BaseCollector)`: Actively fuzzes GET query parameters (`urllib.parse.parse_qs` / `urlencode`) and path segments (`parsed.path.rstrip("/") + "/" + payload`). Emits `Evidence(category="path_traversal", severity="critical")` and links graph nodes via `HAS_ENDPOINT` and `HAS_VULNERABILITY`.
- **Sprint 9 Precedent / Draft (SQL Injection Collector)**:
  - File: `argus/collectors/sql_injection.py` (1,172 lines).
  - Structure:
    - `DBMS_ERROR_SIGNATURES`: Error regexes for MySQL, PostgreSQL, MSSQL, Oracle, SQLite.
    - `SQLInjectionPayloadGenerator`: Implements base error payloads, boolean TRUE/FALSE pairs, time delay templates (`SLEEP({delay})`, `pg_sleep`, `WAITFOR DELAY`, `dbms_pipe.receive_message`), and 5 distinct WAF bypass mutation strategies:
      1. Case alternation (`mutate_case_alternation`)
      2. Inline comment insertion (`mutate_comment_insertion`)
      3. URL percent encoding (`mutate_url_encoding`)
      4. Double URL percent encoding (`mutate_double_url_encoding`)
      5. Whitespace substitution (`mutate_whitespace_substitution`)
    - `SQLInjectionAnalyzer`: Techniques:
      1. `analyze_error_based`: Matches response bodies against `DBMS_ERROR_SIGNATURES`.
      2. `analyze_boolean_blind`: Differential length and status analysis between TRUE/FALSE responses.
      3. `analyze_time_blind`: Measures injected request latency against baseline (threshold >= 4.0s).
      4. `is_false_positive`: Discards pure reflections and generic non-DBMS errors.
    - `SQLInjectionCollector(BaseCollector)`: Fuzzes 4 vectors:
      1. Query parameters (`GET`)
      2. POST body fields (both JSON `json_data` and form-urlencoded `data`)
      3. Path segments (e.g. `/api/v1/users/123{payload}`)
      4. HTTP headers (`Cookie`, `Referer`, `X-Forwarded-For`, `User-Agent`)

### 1.2 HTTP Client Architecture (`AuthenticatedHttpClient`)
- Defined in `argus/http/client.py`:
  - `AuthorizedHttpClient`: Base wrapper over `httpx.request`. Enforces `ScopeResolver.check_scope()` and `authorization_gate.can_execute_action()`. Automatically creates `Evidence(category="HTTP Response", severity="info")`.
  - `AuthenticatedHttpClient(AuthorizedHttpClient)`: Context-manager-enabled HTTP client with connection pooling, cookie management, automatic authentication injection from `TestIdentity`, proxy support, and configurable timeouts/retries.
  - Key methods: `client.get(mission, url, params=..., headers=..., cookies=..., timeout=...)`, `client.post(mission, url, data=..., json=..., headers=..., cookies=..., timeout=...)`, `client.request(mission, method, url, ...)`.
  - Also supports being mocked via duck-typed classes implementing `.get()`, `.post()`, `.request()`, or `__call__()`.

### 1.3 TaskGenerator DAG & Pipeline Connectivity
- File: `argus/planning/task_generator.py`:
  - Recon templates defined in `_RECON_TEMPLATES`:
    - `subfinder` (Category: `TECHNOLOGY_DISCOVERY`, dependencies: `[]`, inputs: `["target"]`)
    - `httpx` (Category: `TECHNOLOGY_DISCOVERY`, dependencies: `["Discover Subdomains"]`, inputs: `["subdomains"]`)
    - `katana_crawler` (Category: `API_DISCOVERY`, dependencies: `["Fingerprint Live Hosts"]`, inputs: `["live_hosts"]`, outputs: `["endpoints"]`)
    - `nuclei` (Category: `EVIDENCE_CORRELATION`, dependencies: `["Fingerprint Live Hosts"]`)
    - `info_disclosure` (Category: `EVIDENCE_CORRELATION`, dependencies: `["Fingerprint Live Hosts"]`)
    - `access_control` (Category: `AUTHORIZATION_ANALYSIS`, dependencies: `["Discover API Endpoints"]`)
    - `path_traversal` (Category: `EVIDENCE_CORRELATION`, dependencies: `["Discover API Endpoints"]`)
    - `sql_injection` (Category: `EVIDENCE_CORRELATION`, dependencies: `["Discover API Endpoints"]`, required_inputs: `["endpoints"]`, metadata: `{"tool_id": "sql_injection"}`)
  - Gap resolution: `_resolve_template_for_gap(gap)` maps coverage gaps with keywords `"sql"`, `"sqli"`, `"database injection"`, `"sql injection"` to `_RECON_TEMPLATES["sql_injection"]`.
  - DAG sequencing: `TaskGenerator.from_gaps(gaps)` converts detected gaps into `ResearchTask` instances with correct dependencies.

### 1.4 Tool Registry & Plugin Adapter
- Tool Registry: `argus/runtime/registry.py`:
  - Global registry singleton: `registry = ToolRegistry()`.
  - Registration pattern:
    ```python
    registry.register(
        Tool(
            id="sql_injection",
            name="SQL Injection Collector",
            capability="sql_injection_detector",
            description="Actively injects SQL payloads into discovered endpoint parameters (query, body, headers) detecting error-based, boolean-based, and time-based blind SQLi.",
            supported_tasks=["SQL Injection Detection", "SQL Injection", "Vulnerability Scanning", "Evidence Correlation", "API Discovery"],
            required_inputs=["endpoints"],
            produced_outputs=["vulnerabilities", "observations", "evidence"],
            capabilities=["sql_injection_detector", "sql_injection_collector"],
            safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
            timeout=300.0,
            priority=95,
        )
    )
    ```
- Plugin Executor Adapter: `argus/runtime/plugins.py`:
  - `PluginExecutorAdapter.execute_plugin(plugin_id, mission)`:
    - Wraps `mission` in `ControlledMission(mission)` (`argus/plugins/interfaces.py`).
    - Fallback instantiation via `_instantiate_specialist_fallback(plugin_id)`:
      ```python
      elif "sql_injection" in plugin_id or "sqli" in plugin_id or plugin_id == "sql":
          from argus.collectors.sql_injection import SQLInjectionCollector
          return SQLInjectionCollector()
      ```
    - Executes `plugin.execute(controlled_mission)` or `plugin.collect(mission)`.

### 1.5 Attack Surface Graph & Models
- Models:
  - `Evidence` (`argus/evidence/model.py`):
    - `category="sql_injection"`
    - `severity="critical"` (for error-based and time-based) or `"high"` (for boolean differential)
    - `provenance=ProvenanceData(step_id="sql_injection_collector")`
    - `metadata={"url": ..., "host": ..., "path": ..., "parameter": ..., "parameter_type": ..., "payload": ..., "technique": ..., "template_id": ..., "dbms": ..., "status_code": ..., "evidence_snippet": ...}`
  - `Node` (`argus/graph/node.py`): `Node(id, type, value, metadata)`.
    - `live_host`: `id=f"live_host:{base_url}"`, `type="live_host"`, `value=base_url`
    - `endpoint`: `id=f"endpoint:{target_url}"`, `type="endpoint"`, `value=target_url`
    - `vulnerability`: `id=f"vulnerability:{template_id}:{target_url}:{param}"`, `type="vulnerability"`, `value=f"SQL Injection ({technique})"`
  - `Edge` (`argus/graph/edge.py`): `Edge(source, target, type, metadata)`.
    - `HAS_ENDPOINT`: `(live_host -> endpoint)`
    - `HAS_VULNERABILITY`: `(live_host -> vulnerability)`
    - `HAS_VULNERABILITY`: `(endpoint -> vulnerability)`
  - Graph Rebuilder (`argus/graph/attack_surface.py`):
    - `AttackSurfaceGraphBuilder.build_from_evidence()` processes evidence items with `category == "sql_injection"` and connects `live_host -> endpoint (HAS_ENDPOINT)`, `live_host -> vulnerability (HAS_VULNERABILITY)`, and `endpoint -> vulnerability (HAS_VULNERABILITY)`.

---

## 2. Logic Chain

1. **Inheritance & Polymorphism**:
   All active collectors (`InformationDisclosureCollector`, `AccessControlCollector`, `PathTraversalCollector`, `SQLInjectionCollector`) inherit from `BaseCollector` in `argus/collectors/base.py` and implement `collect(self, mission) -> List[Evidence]`. To support plugin execution via `PluginExecutorAdapter`, they also provide `execute(self, mission) -> List[Evidence]` as an adapter hook.

2. **ControlledMission Unwrapping**:
   When called from `PluginExecutorAdapter`, the mission object is wrapped in `ControlledMission(mission)` (`argus/plugins/interfaces.py`). Because `ControlledMission` only explicitly exposes `.target`, `.evidence`, and `.publish_finding()`, collectors must safely access the raw mission via `raw_mission = getattr(mission, "_mission", mission)` (precedent established in `AccessControlCollector` at `access_control.py:263`). This ensures `raw_mission.endpoints`, `raw_mission.live_hosts`, `raw_mission.attack_surface_graph`, and `raw_mission.vulnerabilities` are accessed seamlessly.

3. **HTTP Client Lifecycle & Scope Safety**:
   `AuthenticatedHttpClient` automatically executes scope checks before any request is sent over the network. In unit and integration tests, collectors accept an injected `http_client` mock via `__init__(self, http_client=...)`. Duck typing inside `_execute_request` ensures compatibility with both real `AuthenticatedHttpClient` instances and test mock objects.

4. **Multi-Vector Injection Mechanics**:
   Discovered endpoints in `mission.endpoints` can be specified as plain URL strings or rich dictionaries containing `{url, path, method, params, body, headers}`.
   The collector probes 4 distinct vectors:
   - Query Parameters (`GET` / `POST` query strings)
   - POST Request Bodies (handling both JSON payloads `json.dumps(dict)` and `application/x-www-form-urlencoded` fields)
   - Path Segments (e.g. `/api/v1/items/42` -> `/api/v1/items/42'`)
   - HTTP Headers (`Cookie`, `Referer`, `X-Forwarded-For`, `User-Agent`)

5. **Multi-Technique SQLi Validation Logic**:
   - **Error-Based**: Matches against multi-DBMS error signature regexes for MySQL, PostgreSQL, MSSQL, Oracle, and SQLite.
   - **Boolean-Based Blind**: Compares TRUE vs FALSE response characteristics (status codes and byte length delta > 25 bytes), validating against baseline responses to eliminate noise.
   - **Time-Based Blind**: Sends delay payloads (`SLEEP(5)`, `pg_sleep(5)`, `WAITFOR DELAY`, `dbms_pipe.receive_message`) and measures elapsed latency relative to baseline (delay_delta >= 4.0s).
   - **False Positive Elimination**: Rejects responses that merely reflect the injected string without database execution, as well as generic application error pages lacking DBMS error signatures.

6. **Graph Integration & State Synchronization**:
   When a vulnerability is confirmed:
   - An `Evidence` record is appended to `raw_mission.evidence`.
   - A vulnerability summary dictionary is appended to `raw_mission.vulnerabilities`.
   - If `raw_mission.attack_surface_graph` exists, `Node` entries for `live_host`, `endpoint`, and `vulnerability` are registered, and `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges are established.
   - `AttackSurfaceGraphBuilder.build_from_evidence()` deterministically reconstructs these nodes and edges from the `EvidenceStore`.

---

## 3. Caveats

1. **Existing Baseline Tests**:
   - Running the test suite currently executes 896 tests with 894 passing and 2 failing tests in `tests/collectors/test_sql_injection.py` and `tests/runtime/test_e2e_sql_injection.py`.
   - Root causes identified during survey:
     - In `SQLInjectionAnalyzer.is_false_positive()`, when no DBMS signature is present and clean payload reflection is detected in standard HTML responses, `is_false_positive` must return `True` (reflection discard).
     - In `SQLInjectionCollector`, `raw_mission = getattr(mission, "_mission", mission)` must be used across `collect`, `_extract_candidate_endpoints`, and `_create_evidence_and_update_state` so `ControlledMission` objects are properly unwrapped.
2. **Timing Sensitivity in Tests**:
   - Time-based blind tests should mock `HttpResponse.elapsed` (e.g. `elapsed=5.05` vs baseline `elapsed=0.05`) rather than actually blocking with `time.sleep()`, ensuring fast and deterministic test runs.
3. **No Code Modification During Exploration**:
   - Per read-only explorer constraints, no source code or test files were modified during this investigation.

---

## 4. Conclusion & Architecture Mapping

### Summary Architecture Map for Sprint 9:

| Component | Target File Location | Core Responsibility |
|---|---|---|
| **Base Collector** | `argus/collectors/base.py` | Defines abstract `BaseCollector.collect(mission)`. |
| **SQLi Collector Engine** | `argus/collectors/sql_injection.py` | `SQLInjectionCollector(BaseCollector)`, `SQLInjectionPayloadGenerator`, `SQLInjectionAnalyzer`, `DBMS_ERROR_SIGNATURES`. |
| **Tool Registry** | `argus/runtime/registry.py` | Registers `Tool(id="sql_injection", ...)` with priority 95 and required capabilities. |
| **Task DAG Generator** | `argus/planning/task_generator.py` | Maps `CoverageGap` to `_RECON_TEMPLATES["sql_injection"]` with dependency on `Discover API Endpoints`. |
| **Plugin Executor Adapter** | `argus/runtime/plugins.py` | Dispatches `sql_injection` via `_instantiate_specialist_fallback` and executes on `ControlledMission`. |
| **Graph Attack Surface** | `argus/graph/attack_surface.py` | `AttackSurfaceGraphBuilder.build_from_evidence` builds `endpoint`, `vulnerability`, `HAS_ENDPOINT`, `HAS_VULNERABILITY`. |
| **HTTP Client** | `argus/http/client.py` | `AuthenticatedHttpClient` enforces scope boundaries and issues GET/POST requests. |
| **Unit & Adversarial Tests** | `tests/collectors/test_sql_injection.py`<br>`tests/collectors/test_sql_injection_adversarial.py` | Unit tests for error-based, boolean-based, time-based detection, 5 mutation strategies, false-positive reflection discard. |
| **E2E Integration Tests** | `tests/runtime/test_e2e_sql_injection.py` | Full mission loop, TaskGenerator scheduling, DAG gap resolution, and graph verification. |

---

## 5. Verification Method

To verify the architecture and run all tests independently:

1. **Verify Collector Unit & Adversarial Tests**:
   ```bash
   python -m pytest tests/collectors/test_sql_injection.py tests/collectors/test_sql_injection_adversarial.py -v
   ```

2. **Verify End-to-End Integration Tests**:
   ```bash
   python -m pytest tests/runtime/test_e2e_sql_injection.py -v
   ```

3. **Verify Full Workspace Test Suite (Zero Regression)**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
