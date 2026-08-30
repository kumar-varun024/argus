# Test Infrastructure & Verification Analysis: Sprint 10 (XSS Detection Engine & Environment Detector)

## 1. Observation

### 1.1 Baseline Test Suite Execution
- **Command Executed**: `python -m pytest tests/ --ignore=tests/workspace -x -q`
- **Working Directory**: `/home/varun/argus`
- **Result**: `896 passed, 13480 warnings in 20.73s` (Exit Code: 0)
- **Baseline Pass Count**: 896 tests passing across all active modules.
- **Deprecation Warnings**: Primarily `datetime.datetime.utcnow()` deprecation notices in models and lifecycle transitions.

### 1.2 Test Suite Architecture and Organization
The ARGUS test suite spans multiple specialized directories in `tests/`:
1. `tests/collectors/` (9 test files):
   - `test_sql_injection.py` (535 lines, 15 tests): Tests `SQLInjectionPayloadGenerator`, `SQLInjectionAnalyzer`, `SQLInjectionCollector`, DAG reconnaissance templates, ToolRegistry, and `AttackSurfaceGraphBuilder` integration.
   - `test_sql_injection_adversarial.py` (296 lines, 9 tests): Tests boundary value conditions, dynamic noise filtering, WAF mutations, malformed endpoints, and `ControlledMission` publishing.
   - `test_path_traversal.py` (491 lines, 15 tests): Tests traversal payload generation, analyzer heuristics, Linux/Windows signatures, collector parameter injection, and DAG scheduling.
   - `test_path_traversal_adversarial.py` (386 lines, 12 tests): Tests false positive suppression on benign paths, encoding tricks, and socket exceptions.
   - `test_access_control.py` (448 lines, 12 tests): Tests horizontal IDOR, vertical privilege escalation, and proxy header bypasses.
   - `test_challenger2_access_control_adversarial.py` (626 lines, 18 tests): Stress and adversarial testing for access control.
   - `test_information_disclosure.py` (434 lines, 14 tests): Secret extraction, sensitive file probing, and graph building.
   - `test_information_disclosure_adversarial.py` (368 lines, 11 tests): High-noise false positive handling.
2. `tests/runtime/` (12 test files):
   - `test_e2e_sql_injection.py` (252 lines): End-to-end integration proving `Mission` -> `TaskGenerator` -> `PluginExecutorAdapter` -> `SQLInjectionCollector` -> `KnowledgeGraph` expansion -> `AttackSurfaceGraphBuilder` reconstruction.
   - `test_e2e_path_traversal.py` (248 lines): End-to-end integration for path traversal detection.
   - `test_e2e_access_control.py` (220 lines): End-to-end integration for access control & IDOR.
   - `test_e2e_info_disclosure.py` (215 lines): End-to-end integration for information disclosure.
   - `test_e2e_mission.py` (182 lines): Full pipeline loop testing with mock subfinder, httpx, katana, and nuclei.
   - `test_mission_runtime.py` (230 lines): State machine transitions and runtime loop execution.
   - `test_runtime_orchestrator.py` (210 lines): Task dispatching, tool resolution, and event bus emissions.
3. `tests/planning/` (6 test files):
   - `test_task_generator.py`: Verifies reconnaissance DAG task templates (`_RECON_TEMPLATES`), dependency resolution, and `CoverageGap` resolution via `from_gaps()`.
   - `test_research_planner.py`: Tests gap identification and research priority scheduling.
4. `tests/graph/` (5 test files):
   - `test_attack_surface_builder.py`: Verifies standard node counts, edge relationships (`RESOLVES_TO`, `HOSTS`, `HAS_ENDPOINT`, `HAS_VULNERABILITY`), and evidence ingestion.
   - `test_knowledge_graph.py`: Graph operations, node indexing, and edge traversals.
5. `tests/http/` (4 test files):
   - `test_authenticated_http_client.py`: Session persistence, identity injection, cookie management, scope gating, and retry backoff.
   - `test_authorized_http_client.py`: Authorization gate decisions (`ScopeState.IN_SCOPE` vs `ScopeState.OUT_OF_SCOPE`).
6. `tests/tools/` & `tests/test_dnsx.py`:
   - `test_dnsx.py`: CLI arg builder, JSONL/text parsing in `ReconParser`, and runtime subprocess mocking.

### 1.3 Mocking Strategies and Patterns in ARGUS
Across all sprints, ARGUS implements standardized in-memory mocking abstractions that prevent external network egress while testing realistic HTTP interactions:

1. **Mock HTTP Client Pattern**:
   ```python
   class MockXSSHttpClient:
       """Mock HTTP client that matches URLs, query parameters, POST data, or headers."""
       def __init__(self, routes=None):
           self.routes: Dict[str, Tuple[int, str, float]] = routes or {}
           self.call_history: List[str] = []
           self.posted_data: List[Dict[str, Any]] = []
           self.exception_on_url: Dict[str, Exception] = {}

       def set_route(self, key: str, status: int, body: str, elapsed: float = 0.05):
           self.routes[key] = (status, body, elapsed)

       def set_exception(self, url: str, exc: Exception):
           self.exception_on_url[url] = exc

       def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
           target_url = url if url is not None else mission_or_url
           if not isinstance(target_url, str):
               target_url = str(target_url)
           self.call_history.append(target_url)
           if target_url in self.exception_on_url:
               raise self.exception_on_url[target_url]
           # Check header injection matches
           headers = kwargs.get("headers") or {}
           for hk, hv in headers.items():
               if f"header:{hk}:{hv}" in self.routes:
                   st, bd, el = self.routes[f"header:{hk}:{hv}"]
                   return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, url=target_url, elapsed=el)
           # Check exact or partial URL match
           if target_url in self.routes:
               st, bd, el = self.routes[target_url]
               return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, url=target_url, elapsed=el)
           return HttpResponse(success=True, status_code=200, raw_body="<html><body>Normal Page</body></html>", body="<html><body>Normal Page</body></html>", url=target_url, elapsed=0.05)

       def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
           target_url = url if url is not None else mission_or_url
           if not isinstance(target_url, str):
               target_url = str(target_url)
           data = kwargs.get("data")
           json_data = kwargs.get("json")
           self.posted_data.append({"url": target_url, "data": data, "json": json_data})
           # Route matching for POST payloads
           ...
   ```

2. **Mission Context & Knowledge Graph Setup**:
   ```python
   mission = Mission(target="target.corp")
   mission.scope = ["target.corp"]
   mission.live_hosts = [{"url": "https://target.corp", "host": "target.corp"}]
   mission.endpoints = [{"url": "https://target.corp/search?q=test", "path": "/search", "params": {"q": "test"}}]
   mission.evidence = EvidenceStore()
   mission.vulnerabilities = []
   mission.attack_surface_graph = KnowledgeGraph()
   mission.environment = {}
   ```

3. **Subprocess & Environment Mocking**:
   - `unittest.mock.patch("shutil.which")` or `unittest.mock.patch("subprocess.run")` to simulate presence/absence of CLI tools (`subfinder`, `httpx`, `nuclei`, `katana`, `dnsx`, `node`, `npm`).
   - `socket.gethostbyname` or `dns.resolver` mocking for DNS connectivity checks.
   - `httpx.get` mocking for cloud metadata endpoint reachability (`http://169.254.169.254/...`).

---

## 2. Logic Chain

### 2.1 Requirements Decomposition for Sprint 10
From `ORIGINAL_REQUEST.md`, Sprint 10 requires:
1. **R1: XSS Detection Engine**:
   - Reflected XSS with canary echo verification.
   - Stored XSS with two-step POST-then-GET pattern.
   - Context-Aware Payloads (HTML body, HTML attribute, JS string, URL context).
   - False positive rejection when HTML-escaped (`<` -> `&lt;`, `"` -> `&quot;`, `'` -> `&#39;`, `&#x27;`).
2. **R2: Environment Detector**:
   - Tool availability check (`subfinder`, `httpx`, `nuclei`, `katana`, `dnsx`, `node`, `npm`).
   - Target domain reachability & DNS connectivity check.
   - Cloud metadata accessibility check (AWS/GCP/Azure SSRF prep).
   - Structured result dict populating `mission.environment`.
3. **R3: Pipeline Connectivity**:
   - Tool registration in `argus/runtime/registry.py` (`id="xss"`).
   - DAG scheduling in `argus/planning/task_generator.py` (`_RECON_TEMPLATES["xss"]` depending on `"Discover API Endpoints"`).
   - Dynamic instantiation in `argus/runtime/plugins.py` (`_instantiate_specialist_fallback("xss")`).
   - Attack surface graph integration (`HAS_VULNERABILITY` and `HAS_ENDPOINT` edges with severities: stored = `critical`, reflected = `high`, DOM/header = `medium`).
   - Graph reconstruction in `argus/graph/attack_surface.py`.
4. **R4: Zero Regression & Verification**:
   - 896 baseline tests must continue to pass.
   - >= 20 new tests added across 4 tiers.

### 2.2 Test Architecture Strategy
To guarantee complete isolation, test reliability, and speed (<30s runtime), the test architecture should follow a 4-tier matrix:
- **Tier 1: Feature Coverage (Unit & Functional)** — Validates core algorithmic logic in `XSSPayloadGenerator`, `XSSAnalyzer`, `EnvironmentDetector`, and `XSSCollector`.
- **Tier 2: Boundary & Corner Cases** — Validates false positive rejection (HTML entity escapes, attribute escaping, JSON/image content types), malformed inputs, timeouts, socket errors, and missing headers.
- **Tier 3: Cross-Feature Interactions** — Validates DAG gap analysis, tool registry resolution, plugin adapter execution, severity mapping in graph edges, and mission lifecycle state updates (`mission.environment`).
- **Tier 4: Real-World E2E Scenarios** — Validates end-to-end mission loop execution on complex multi-endpoint and multi-vulnerability targets.

---

## 3. Caveats

1. **No External Network Dependencies**: All network probes, tool execution checks, DNS resolutions, and cloud metadata requests must be fully mockable in unit and integration tests. No live requests to `169.254.169.254` or external domains during tests.
2. **Subprocess / CLI Isolation**: `EnvironmentDetector` tool checks must use `shutil.which` or mocked subprocess execution so tests run predictably on systems without Go or Node security tools installed.
3. **Threading in E2E Missions**: When testing `MissionController.start()`, tests should ensure deterministic wait loops with timeouts or direct runtime step execution to prevent lingering threads.
4. **HTML Parsing Robustness**: The XSS analyzer should parse HTML responses safely using `BeautifulSoup` (or resilient regex/tokenization) without failing on malformed HTML or non-UTF8 bytes.

---

## 4. Conclusion & Sprint 10 Test Matrix

A comprehensive 29-test matrix across 4 tiers is designed for Sprint 10 to ensure zero regression and exhaustive feature validation.

### Sprint 10 Test Matrix (29 Tests)

| Tier | Test ID | Target Component | Description & Expected Outcome |
|---|---|---|---|
| **Tier 1: Feature Coverage** | `T1.1` | `XSSPayloadGenerator` | `test_xss_payload_generator_context_sets`: Asserts generation of >= 3 distinct payload sets: HTML body (`<script>`, `<img>`), attribute context (`" onfocus=`), JS string (`';alert(1)//`), and URL context. |
| | `T1.2` | `XSSAnalyzer` | `test_xss_analyzer_reflected_html_body_unencoded`: Asserts raw canary `<script>alert(1)</script>` in HTML body returns `high` severity finding with exact snippet. |
| | `T1.3` | `XSSAnalyzer` | `test_xss_analyzer_reflected_attribute_context`: Asserts attribute breakout `\" onfocus=\"alert(1)\"` inside `<input value="...">` is detected as `high` severity. |
| | `T1.4` | `XSSAnalyzer` | `test_xss_analyzer_reflected_js_string_context`: Asserts JS string breakout `';alert(1)//` inside `<script>var x = '...';</script>` is detected as `high` severity. |
| | `T1.5` | `XSSAnalyzer` | `test_xss_analyzer_stored_post_then_get`: Asserts stored XSS detected when canary submitted via POST is rendered unescaped in subsequent GET, returning `critical` severity. |
| | `T1.6` | `XSSCollector` | `test_xss_collector_query_param_reflected`: Asserts GET parameter fuzzing emits `Evidence(category="xss", severity="high")`, updates `mission.vulnerabilities`, and creates graph nodes. |
| | `T1.7` | `XSSCollector` | `test_xss_collector_post_body_stored`: Asserts POST body parameter fuzzing followed by GET verification emits `Evidence(category="xss", severity="critical")`. |
| | `T1.8` | `XSSCollector` | `test_xss_collector_headers_reflection`: Asserts header reflection (e.g. `User-Agent`, `Referer`) emits `Evidence(category="xss", severity="medium")`. |
| | `T1.9` | `EnvironmentDetector` | `test_environment_detector_tools_all_installed`: Asserts all CLI tools (`subfinder`, `httpx`, `nuclei`, `katana`, `dnsx`, `node`, `npm`) report `True` when present. |
| | `T1.10` | `EnvironmentDetector` | `test_environment_detector_tools_missing_graceful`: Asserts missing tools report `False` in structured dict without raising unhandled exceptions. |
| | `T1.11` | `EnvironmentDetector` | `test_environment_detector_network_connectivity_success`: Asserts DNS resolution and HTTP reachability report `reachable: True` for live domain. |
| | `T1.12` | `EnvironmentDetector` | `test_environment_detector_cloud_metadata_accessible`: Asserts detection of accessible cloud metadata service (AWS/GCP/Azure) with `metadata_accessible: True`. |
| **Tier 2: Boundary & Corner Cases** | `T2.1` | `XSSAnalyzer` | `test_xss_analyzer_false_positive_html_entity_escaping`: Asserts `<script>` escaped as `&lt;script&gt;` or `&#60;script&#62;` returns `None` (no false positive). |
| | `T2.2` | `XSSAnalyzer` | `test_xss_analyzer_false_positive_attribute_quote_escaping`: Asserts quotes escaped as `&quot;` or `&#39;` inside attributes return `None`. |
| | `T2.3` | `XSSAnalyzer` | `test_xss_analyzer_false_positive_json_content_type`: Asserts reflection inside `application/json` API responses is rejected. |
| | `T2.4` | `XSSAnalyzer` | `test_xss_analyzer_false_positive_plain_text_content_type`: Asserts reflection inside `text/plain` responses is rejected. |
| | `T2.5` | `XSSAnalyzer` | `test_xss_analyzer_malformed_html_handling`: Asserts analyzer parses unclosed tags, truncated HTML, and binary data gracefully. |
| | `T2.6` | `XSSCollector` | `test_xss_collector_network_timeout_and_unreachable`: Asserts collector survives HTTP timeout, 502/504 gateways, and connection drops without crashing. |
| | `T2.7` | `XSSCollector` | `test_xss_collector_empty_mission_and_invalid_endpoints`: Asserts collector handles empty missions, `None` endpoints, and malformed URLs gracefully. |
| | `T2.8` | `XSSCollector` | `test_xss_collector_special_characters_in_params`: Asserts fuzzing handles spaces, unicode characters, null bytes (`%00`), and array params. |
| | `T2.9` | `EnvironmentDetector` | `test_environment_detector_dns_failure_handling`: Asserts NXDOMAIN or socket DNS errors return `dns_resolvable: False` gracefully. |
| | `T2.10` | `EnvironmentDetector` | `test_environment_detector_cloud_metadata_timeout`: Asserts connection timeouts when probing `169.254.169.254` return `metadata_accessible: False` within timeout budget. |
| **Tier 3: Cross-Feature Interactions** | `T3.1` | `TaskGenerator` | `test_xss_task_generator_dag_wiring`: Asserts `_RECON_TEMPLATES["xss"]` has category `EVIDENCE_CORRELATION` and dependency on `Discover API Endpoints`. |
| | `T3.2` | `TaskGenerator` | `test_xss_gap_analyzer_resolution`: Asserts `TaskGenerator.from_gaps()` resolves `"xss"`, `"stored xss"`, and `"cross-site scripting"` coverage gaps to XSS tasks. |
| | `T3.3` | `ToolRegistry` & `Plugins` | `test_xss_tool_registry_and_plugin_adapter`: Asserts `registry.get("xss")` returns valid Tool and `PluginExecutorAdapter` instantiates `XSSCollector`. |
| | `T3.4` | `AttackSurfaceGraph` | `test_xss_attack_surface_graph_edges_and_severities`: Asserts stored XSS creates `HAS_VULNERABILITY` with `critical`, reflected XSS with `high`, and header XSS with `medium`. |
| | `T3.5` | `AttackSurfaceGraphBuilder` | `test_attack_surface_graph_builder_reconstructs_xss`: Asserts `build_from_evidence()` creates complete graph from XSS evidence records. |
| | `T3.6` | `MissionRuntime` | `test_mission_initialization_populates_environment`: Asserts mission controller runs `EnvironmentDetector` during startup and populates `mission.environment`. |
| **Tier 4: Real-World E2E Scenarios** | `T4.1` | Mission Loop | `test_e2e_reflected_xss_mission_lifecycle`: Full mission execution against reflected XSS target endpoint, verifying DAG scheduling, plugin execution, evidence generation, and graph edges. |
| | `T4.2` | Mission Loop | `test_e2e_stored_xss_mission_lifecycle`: Full mission execution against stored XSS target (POST comment -> GET page), verifying critical evidence and graph integration. |
| | `T4.3` | Mission Loop | `test_e2e_multi_vulnerability_mission_xss_and_sqli`: Multi-vulnerability mission with both SQL injection and XSS endpoints, verifying concurrent categorization, independent evidence stores, and knowledge graph integrity. |

### Proposed Test File Placement
1. `tests/collectors/test_xss.py` (Unit, functional, and collector tests: T1.1 to T1.8, T3.1 to T3.5)
2. `tests/collectors/test_xss_adversarial.py` (Adversarial, boundary, and false positive tests: T2.1 to T2.8)
3. `tests/tools/test_environment_detector.py` (Environment detector tool tests: T1.9 to T1.12, T2.9 to T2.10, T3.6)
4. `tests/runtime/test_e2e_xss.py` (End-to-end integration and mission loop tests: T4.1 to T4.3)

---

## 5. Verification Method

### 5.1 Pre-Implementation Verification (Baseline)
```bash
# Verify baseline passes 896 tests with zero failures
python -m pytest tests/ --ignore=tests/workspace -x -q
```

### 5.2 Post-Implementation Verification (Sprint 10)
```bash
# 1. Run full test suite including new XSS and Environment Detector tests (Target: 916+ passing)
python -m pytest tests/ --ignore=tests/workspace -x -q

# 2. Run new Sprint 10 test files specifically
python -m pytest tests/collectors/test_xss.py tests/collectors/test_xss_adversarial.py tests/tools/test_environment_detector.py tests/runtime/test_e2e_xss.py -v

# 3. Verify AttackSurfaceGraphBuilder and TaskGenerator regressions
python -m pytest tests/graph/test_attack_surface_builder.py tests/planning/test_task_generator.py -v
```
