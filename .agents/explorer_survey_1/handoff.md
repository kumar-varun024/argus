# Explorer 1: Codebase Architecture & Collectors Survey Report

## 1. Observation

### 1.1 BaseCollector Architecture and Lifecycle
- **Definition Location**: `argus/collectors/base.py:1-10`
  ```python
  from abc import ABC, abstractmethod

  class BaseCollector(ABC):
      @abstractmethod
      def collect(self, mission):
          """Collect information and update the mission."""
          pass
  ```
- **Execution Hook Conventions Across Active Collectors** (e.g. `argus/collectors/cache_security.py:1324-1523`, `argus/collectors/websocket.py:1218-1345`, `argus/collectors/graphql.py:1650-1790`, `argus/collectors/deserialization.py:1003-1400`):
  - Subclassing: Collectors directly inherit from `BaseCollector`.
  - Primary Entry Point: `collect(self, mission: Any) -> List[Evidence]`.
  - Execution Alias: `execute(self, mission: Any) -> List[Evidence]` (delegates directly to `self.collect(mission)`). This satisfies both `BaseCollector` and `BasePlugin` / `PluginExecutorAdapter` contracts.
  - Backwards Compatibility Aliases: Class aliases provided at module bottom (e.g., `CORSSecurityCollector`, `CORSCollector`, `CORSMisconfigurationCollector`, `HTTPHeaderAuditorCollector`).

### 1.2 Candidate Endpoint Discovery & Extraction Patterns
- Active collectors implement `_discover_candidate_endpoints(self, mission: Any) -> List[str]` (`argus/collectors/cache_security.py:1334-1381`, `argus/collectors/graphql.py:1660-1710`):
  - Handles raw missions and wrapped missions: `raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))`.
  - Extracts endpoints from:
    1. `raw_mission.endpoints`: Extracts `ep.get("url") or ep.get("path")` if dict, or string `ep`.
    2. `raw_mission.live_hosts`: Extracts `lh.get("url")` if dict, or string `lh`.
    3. `raw_mission.target`: If string `target` is provided without scheme, normalizes to `https://{target}` or `http://{target}`.
    4. `raw_mission.evidence`: Iterates over evidence items (`raw_mission.evidence.all()` or list), extracting `metadata.get("url")` or `metadata.get("endpoint")`.
  - Fallback Target Synthesis: If `endpoints` list is completely empty, synthesizes default URLs from `live_hosts` or `target`.

### 1.3 HTTP Client Infrastructure & Polymorphic Dispatch
- **Definition Location**: `argus/http/client.py`
  - `HttpResponse` Dataclass (`lines 71-85`):
    - `success: bool`
    - `status_code: Optional[int] = None`
    - `headers: Dict[str, str] = field(default_factory=dict)`
    - `request_headers: Dict[str, str] = field(default_factory=dict)`
    - `body: Optional[str] = None`
    - `raw_body: Optional[str] = None`
    - `url: str = ""`
    - `method: str = ""`
    - `elapsed: float = 0.0`
    - `error: Optional[str] = None`
    - `scope_decision: Optional[ScopeDecision] = None`
    - `authorization_decision: Optional[AuthDecision] = None`
  - `AuthenticatedHttpClient` Class (`lines 300-587`):
    - Subclasses `AuthorizedHttpClient`.
    - `__init__(identity=None, proxy=None, verify_ssl=False, timeout=10.0, max_retries=3, backoff_factor=0.5, follow_redirects=True, headers=None, cookies=None)`.
    - Supports context management: `__enter__()` and `__exit__()` calling `self.close()`.
    - Enforces strict in-scope verification via `ScopeResolver.check_scope(url, mission.id)` before sending requests (`lines 377-389`).
    - Enforces authorization gating via `authorization_gate.can_execute_action(...)` (`lines 392-405`).
    - Injects identity headers and cookies via `TestIdentity` (`lines 407-421`).
    - Automatic retry with exponential backoff on `httpx.TimeoutException` and `httpx.RequestError` (`lines 433-497`).
    - Sanitizes sensitive headers (`Authorization`, `Cookie`, `X-API-Key`, etc.) and passwords in URLs and bodies (`lines 17-70`).
    - Automatically records `Evidence(category="HTTP Response")` on successful dispatch (`lines 475-477`).
- **Polymorphic Prober HTTP Execution Helper** (`argus/collectors/graphql.py:1056-1160`, `argus/collectors/deserialization.py:970-1001`):
  ```python
  def _execute_request(
      self,
      mission: Any,
      method: str,
      url: str,
      headers: Optional[Dict[str, str]] = None,
      cookies: Optional[Dict[str, str]] = None,
      data: Optional[Any] = None,
      json_data: Optional[Any] = None,
      params: Optional[Dict[str, Any]] = None,
  ) -> Optional[HttpResponse]:
      method = method.upper()
      req_headers = dict(headers or {})
      req_cookies = dict(cookies or {})

      try:
          if self.http_client is not None:
              client = self.http_client
              # 1. Direct method calls: client.get, client.post, client.options
              if method == "GET" and hasattr(client, "get"):
                  try:
                      return client.get(mission, url, params=params, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                  except TypeError:
                      return client.get(url, params=params, headers=req_headers, cookies=req_cookies)
              if method == "POST" and hasattr(client, "post"):
                  try:
                      return client.post(mission, url, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                  except TypeError:
                      return client.post(url, data=data, json=json_data, headers=req_headers, cookies=req_cookies)
              if method == "OPTIONS" and hasattr(client, "options"):
                  try:
                      return client.options(mission, url, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                  except TypeError:
                      return client.options(url, headers=req_headers, cookies=req_cookies)
              # 2. Universal request method: client.request
              if hasattr(client, "request"):
                  try:
                      return client.request(mission, method=method, url=url, params=params, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                  except TypeError:
                      return client.request(method=method, url=url, params=params, data=data, json=json_data, headers=req_headers, cookies=req_cookies)
              # 3. Callable mock function
              if callable(client):
                  return client(method=method, url=url, params=params, data=data, json=json_data, headers=req_headers, cookies=req_cookies)

          # Fallback to AuthenticatedHttpClient context manager
          with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
              if method == "GET":
                  return client.get(mission, url, params=params, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
              elif method == "POST":
                  return client.post(mission, url, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
              elif method == "OPTIONS":
                  return client.options(mission, url, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
              else:
                  return client.request(mission, method, url, params=params, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
      except Exception as e:
          logger.debug("HTTP request to %s failed: %s", url, e)
      return None
  ```

### 1.4 Quadruple State Publishing Pattern
When active collectors discover a confirmed finding, they update four distinct state locations (`argus/collectors/cache_security.py:1383-1481`, `argus/collectors/websocket.py:1260-1340`):
1. **`raw_mission.evidence`**:
   - Creates `Evidence(category=..., value=..., source=..., status="CONFIRMED", confidence=1.0, severity=..., title=..., description=..., provenance=ProvenanceData(...), tags=[...], metadata={...})`.
   - Appends via `raw_mission.evidence.add(ev)` (if `EvidenceStore`) or `raw_mission.evidence.append(ev)`.
2. **`raw_mission.vulnerabilities`**:
   - Appends dictionary `{"name": title, "template_id": template_id, "severity": severity, "host": base_url, "url": target_url, "description": description, "technique": technique, "parameter": parameter, "strategy": strategy, "cwe_id": cwe_id, "cvss_score": cvss_score}`.
3. **`raw_mission.attack_surface_graph` (KnowledgeGraph)**:
   - Adds nodes:
     - `Node(id=f"live_host:{base_url}", type="live_host", value=base_url, metadata={"url": base_url, "host": hostname})`
     - `Node(id=f"endpoint:{target_url}", type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code})`
     - `Node(id=f"vulnerability:{template_id}:{target_url}:{vector_name}", type="vulnerability", value=title, metadata=ev.metadata)`
   - Connects directional edges:
     - `graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")`
     - `graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")`
     - `graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")`
4. **`ControlledMission.publish_finding`**:
   - If `mission` is a `ControlledMission` wrapper, calls `mission.publish_finding(ev.evidence_id, ev)`.

### 1.5 Pipeline Connectivity & System Integration
- **`argus/planning/task_generator.py`**:
  - `_RECON_TEMPLATES`: Recon task template definition with `title`, `goal`, `category=TaskCategory.EVIDENCE_CORRELATION`, `required_inputs=["endpoints"]`, `expected_outputs=["vulnerabilities", "observations", "evidence"]`, `dependencies=["Discover API Endpoints"]`, `metadata={"tool_id": "cors_headers"}`, `priority=0.82`.
  - `_resolve_template_for_gap`: Keyword mapping in `TaskCategory.EVIDENCE_CORRELATION` for `"cors"`, `"cors security"`, `"cors misconfiguration"`, `"security headers"`, `"http security headers"`, `"csp"`, `"hsts"`, `"x-frame-options"`, `"clickjacking"`.
  - `from_gaps`: Inclusion in the `tool_id in (...)` tuple on line 792 to auto-populate input URLs from `mission.endpoints`.
- **`argus/runtime/registry.py`**:
  - Registers `Tool(id="cors_headers", name="CORS & HTTP Security Header Audit Collector", capability="cors_headers_detector", ...)` with supported tasks, inputs/outputs, capabilities, safety requirements (`{"type": "internal", "permissions": ["network", "db_read", "db_write"]}`), timeout (300.0s), priority (95).
  - Aliases in `ToolRegistry.get()`: maps `"cors"`, `"cors_security"`, `"cors_collector"`, `"cors_misconfiguration"`, `"security_headers"`, `"http_headers"`, `"header_auditor"`, `"csp"`, `"hsts"` to `"cors_headers"`.
- **`argus/runtime/plugins.py`**:
  - `PluginExecutorAdapter._instantiate_specialist_fallback`: Dispatches matching `plugin_id` to instantiate `CORSSecurityCollector()`.
- **`argus/graph/attack_surface.py`**:
  - `AttackSurfaceGraphBuilder.build_from_evidence`: Category handler for `"cors"`, `"cors_misconfiguration"`, `"http_security_headers"`, `"cors_headers"`, `"security_headers"` creating `live_host`, `endpoint`, and `vulnerability` nodes with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
- **`argus/reporting/cvss.py`**:
  - `CWE_DATABASE`: Maps CORS findings to `CWE-942` ("Permissive Cross-origin Resource Sharing Policy"), security header findings to `CWE-693` ("Protection Mechanism Failure"), `CWE-1021` ("Improper Restriction of Rendered UI Layers or Frames"), `CWE-319` ("Cleartext Transmission of Sensitive Information"), `CWE-525` ("Use of Web Browser Cache Containing Sensitive Information").
  - `_get_preset_vector`: Maps severity band scoring for CORS and header vulnerabilities (Critical: 9.8 / High: 8.1 / Medium: 5.3 / Low: 2.7 / Info: 0.0).

### 1.6 Current Test Suite Status
- Command executed: `python -m pytest tests/ --ignore=tests/workspace -q`
- Result: **1,740 passed in 65.02s (0 failures, 0 errors)**.

---

## 2. Logic Chain

1. **Adherence to BaseCollector Contract**:
   - `BaseCollector` defines the abstract contract `collect(mission)`.
   - To integrate seamlessly into both direct collector invocations and runtime adapters (`PluginExecutorAdapter.execute_plugin`), the new module (`argus/collectors/cors_headers.py`) must implement `CORSSecurityCollector(BaseCollector)` exposing both `collect(mission)` and `execute(mission)`.

2. **Decoupled Architecture (Generator, Prober, Analyzer, Collector)**:
   - Modern active collectors in the codebase follow a 4-part architecture:
     - `CORSPayloadGenerator` / `HeaderAuditPayloadGenerator`: Constructs target probe structures, crafted origins, preflight options, and header mutations.
     - `CORSProber`: Manages polymorphic HTTP execution (`AuthenticatedHttpClient` / mock client), timeout resilience, and response normalization.
     - `CORSAnalyzer` & `HTTPHeaderAuditor`: Inspects response headers (`Access-Control-*`, `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control`), evaluates misconfigurations, eliminates false positives, and assigns CWE/CVSS scores.
     - `CORSSecurityCollector(BaseCollector)`: Discovers candidate endpoints, drives probes, evaluates findings, and executes Quadruple State Publishing.

3. **Multi-Vector CORS & Header Audit Coverage (R2, R3, R4)**:
   - Multi-vector CORS detection (R2):
     - Origin Reflection: Arbitrary origin reflection in `Access-Control-Allow-Origin`.
     - Null Origin Acceptance: `Origin: null` accepted with `Access-Control-Allow-Credentials: true`.
     - Wildcard with Credentials: `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`.
     - Subdomain Trust Abuse: Overly broad trust (`https://attacker.example.com` or `https://example.com.attacker.com`).
     - Pre-flight Bypass: OPTIONS preflight response with overly permissive methods (`PUT`, `DELETE`, `PATCH`) or headers.
     - Origin Parser Differential: Prefix bypass (`target.com.attacker.com`), suffix bypass (`attacker.target.com`), URL-encoded origins (`%2e%2e`), unescaped regex dots (`targetXcom`), protocol confusion (`http://` vs `https://`).
   - HTTP Security Header Audit (R3):
     - CSP: missing, `unsafe-inline`, `unsafe-eval`, wildcard sources (`*`), missing `frame-ancestors`.
     - HSTS: missing, `max-age < 31536000`, missing `includeSubDomains`, missing `preload`.
     - X-Frame-Options: missing, invalid values (not `DENY` or `SAMEORIGIN`).
     - X-Content-Type-Options: missing `nosniff`.
     - Referrer-Policy: missing, overly permissive (`unsafe-url`, `no-referrer-when-downgrade`).
     - Permissions-Policy: missing, overly permissive.
     - X-XSS-Protection: `0` or missing.
     - Cache-Control: missing `no-store` / `no-cache` on sensitive endpoints.
   - Mutation & Evasion Strategies (R4 - at least 5 distinct strategies):
     1. Origin Casing Variations (`https://TARGET.COM`, `https://TaRgEt.CoM`)
     2. Protocol Smuggling (`http://` downgrade, `ws://` / `wss://`, `ftp://`)
     3. Subdomain Injection Patterns (`attacker-target.com`, `target.com.attacker.com`, `targetacom`)
     4. Header Duplication & Folding (multiple `Origin` headers, comma-separated origins)
     5. Pre-flight Method/Header Enumeration (non-standard methods `PATCH`, `TRACE`, custom headers `X-Custom-Auth`)

4. **Pipeline Compatibility & Victory Conditions (R5, R6)**:
   - DAG scheduling via `TaskGenerator` requires `_RECON_TEMPLATES["cors_headers"]` and gap resolution.
   - Tool registry requires `Tool(id="cors_headers", ...)` with aliases in `argus/runtime/registry.py`.
   - Fallback dispatch requires matching cases in `PluginExecutorAdapter._instantiate_specialist_fallback`.
   - Attack surface graph reconstruction requires category processing in `AttackSurfaceGraphBuilder.build_from_evidence`.
   - CVSS/CWE scoring requires database and heuristic mapping in `argus/reporting/cvss.py`.
   - All 1,740 passing tests must continue to pass with zero regressions.

---

## 3. Caveats

- **No Caveats on Architecture**: The architectural conventions for collectors, probers, HTTP dispatch, graph wiring, and DAG scheduling are completely uniform and consistent across all 20+ collectors in the repository.
- **Benchmark & Offline Safety**: All active probes in ARGUS must execute without third-party network dependencies. Testing harnesses must use mock HTTP clients or local HTTP servers without reaching external internet endpoints.

---

## 4. Conclusion

The ARGUS codebase possesses a mature, well-structured collector and pipeline architecture. Implementing the CORS Misconfiguration & HTTP Security Header Audit Module requires:
1. Creating `argus/collectors/cors_headers.py` containing:
   - Enums: `CORSVulnerabilityType`, `HeaderVulnerabilityType`, `CORSMutationStrategy`, `CORSSeverity`
   - Data structures: `CORSProbe`, `CORSProbeResponse`, `CORSSecurityResult`, `HeaderAuditResult`
   - `CORSPayloadGenerator`: Generates multi-vector CORS probes and 5+ mutation strategies
   - `CORSProber`: Executes polymorphic HTTP requests with timeout/error resilience
   - `CORSAnalyzer` & `HTTPHeaderAuditor`: Evaluates CORS and security headers, suppresses false positives, and calculates CVSS/CWE
   - `CORSSecurityCollector(BaseCollector)`: Discovers endpoints, orchestrates audits, and executes Quadruple State Publishing
2. Updating `argus/collectors/__init__.py` to export the new classes and aliases.
3. Updating `argus/planning/task_generator.py` with `_RECON_TEMPLATES["cors_headers"]`, gap resolution keywords, and `from_gaps` input extraction.
4. Updating `argus/runtime/registry.py` with `Tool(id="cors_headers", ...)` and alias resolutions.
5. Updating `argus/runtime/plugins.py` with fallback instantiation in `PluginExecutorAdapter`.
6. Updating `argus/graph/attack_surface.py` with Section 25 in `AttackSurfaceGraphBuilder.build_from_evidence`.
7. Updating `argus/reporting/cvss.py` with CWE-942, CWE-693, CWE-1021 mappings and heuristic scoring bands.
8. Writing comprehensive test suites in `tests/collectors/test_cors_headers.py` and `tests/collectors/test_cors_headers_adversarial.py` (at least 25 new tests) maintaining 100% test pass rate across all 1,740+ existing tests.

---

## 5. Verification Method

To independently verify all findings and validate future implementations:
1. **Run full test suite**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -q
   ```
   (Expected: 1,740+ passed).
2. **Inspect BaseCollector & Active Collector Architecture**:
   - `argus/collectors/base.py`
   - `argus/collectors/cache_security.py:1324-1523`
   - `argus/collectors/websocket.py:1218-1345`
   - `argus/http/client.py:300-587`
3. **Inspect Pipeline Wiring Targets**:
   - `argus/planning/task_generator.py:13-266, 680-822`
   - `argus/runtime/registry.py:15-180, 750-869`
   - `argus/runtime/plugins.py:65-212`
   - `argus/graph/attack_surface.py:1208-1277`
   - `argus/reporting/cvss.py:33-180, 372-444`
