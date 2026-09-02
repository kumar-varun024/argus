# Handoff Report: Test Infrastructure, Fixtures, Mocking Patterns & Test Matrix for Sprint 29

**Agent**: `survey_explorer_3` (Explorer Subagent)  
**Task**: Test Infrastructure, Fixtures, Mocking Patterns, Baseline Suite Audit & Test Matrix Formulation for Sprint 29 (Prototype Pollution & Client-Side Attack Detection Module)  
**Date**: 2026-09-02T13:47:00Z  

---

## 1. Observation

### 1.1 Baseline Test Suite Execution & Test Distribution
- **Pytest Execution**: Executed `python -m pytest tests/ --ignore=tests/workspace -q`.
  - **Result**: `1929 passed, 51114 warnings in 63.60s (0:01:03)`
  - **Exit Code**: `0` (Zero existing regressions across the baseline).
- **Test Suite Distribution** (audited via `pytest --collect-only`):
  - Total test files: **113 test files** (excluding `tests/workspace`).
  - Total test count: **1,929 tests**.
  - Breakdown by directory:
    - `tests/collectors`: **1,015 tests** across 47 test files (52.6% of entire test suite).
    - `tests` (root): **127 tests**
    - `tests/runtime`: **126 tests**
    - `tests/learning`: **97 tests**
    - `tests/planning`: **75 tests**
    - `tests/graph`: **69 tests**
    - `tests/scanning`: **62 tests**
    - `tests/reporting`: **60 tests**
    - `tests/http`: **44 tests**
    - `tests/correlation`: **35 tests**
    - `tests/tools`: **29 tests**
    - `tests/hypothesis`: **25 tests**
    - `tests/plugins/graphql`: **23 tests**
    - `tests/pipeline`: **22 tests**
    - `tests/investigation`: **17 tests**
    - `tests/plugins/javascript`: **17 tests**
    - `tests/benchmark/leaderboard`: **14 tests**
    - `tests/auth`: **10 tests**
    - `tests/analyzers`: **8 tests**
    - `tests/authorization`: **8 tests**
    - `tests/benchmark/*`: **28 tests** (datasets, ground_truth, metrics, reports, runner)
    - `tests/explain`: **5 tests**
    - `tests/performance`: **5 tests**
    - `tests/orchestration`: **4 tests**
    - `tests/evidence`: **3 tests**
    - `tests/plugins`: **1 test**

### 1.2 Fixture Conventions & HTTP Mocking Infrastructure
1. **Fixture Architecture**:
   - There is **no root `tests/conftest.py`** (`tests/workspace/conftest.py` is excluded from the test runner).
   - Test files are strictly **self-contained and modular**. They do not depend on global session-scoped fixtures or external network daemons.
   - Fixtures in `tests/collectors/` (when used, e.g. `tests/collectors/test_cors_security.py:31-41`) provide clean, lightweight local instances of `PayloadGenerator`, `Analyzer`, or `Collector`.
2. **HTTP Mocking Patterns**:
   - Zero reliance on external network mock libraries (e.g., `responses` and `aioresponses` are not used in `tests/collectors`).
   - Mocking is performed via **in-memory polymorphic mock HTTP clients** returning deterministic `HttpResponse` objects (`argus.http.client.HttpResponse`).
   - Observed Mock Client Implementations:
     - `MockAuthHttpClient` (`tests/collectors/test_auth_bypass.py:44-208`): Route-dictionary matcher mapping exact target URLs, header patterns (`auth:<token>`, `hdr:<Header-Name>:<val>`), JSON payload content (`user:<username>:<password>`, `token:<token>`), and cookie headers (`cookie:<name>`).
     - `MockXSSHttpClient` (`tests/collectors/test_xss.py:23-112`): URL router supporting stored state simulation, header matching (`header:X-Forwarded-For:value`), and query parameter reflection parsing (`param:<key>:<val>`).
     - `MockFileUploadHttpClient` (`tests/collectors/test_file_upload.py:51-89`): Function-callback based dispatch accepting `post_response_fn` and `get_response_fn`.
     - `MockAdversarialHttpClient` (`tests/collectors/test_auth_bypass_adversarial.py:41-94`): Handler list with callable predicate matchers `matcher(method, url, headers, json, data)` or substring matchers, simulating latency jitter, exceptions, and WAF rejections.
     - `AdversarialFileUploadHttpClient` (`tests/collectors/test_file_upload_adversarial.py:38-80`): Mode-switched mock supporting `"legitimate_validation"`, `"waf_403"`, `"unsupported_media_type_415"`, and socket drops.
3. **Domain Models & Graph Fixtures**:
   - `Mission`: Instantiated directly as `Mission(target="http://example.com")` with optional attributes `endpoints=[...]`, `live_hosts=[...]`.
   - `ControlledMission`: Instantiated as `ControlledMission(mission)` to wrap the mission for plugin interface compatibility.
   - `Evidence`: Instantiated using `Evidence(category="...", source="...", confidence=..., metadata={...}, title=...)` (`argus/evidence/model.py:26-56`).
   - `KnowledgeGraph`: Instantiated directly via `KnowledgeGraph()` (`argus/graph/graph.py`).

### 1.3 Collector Test File Architecture Patterns
Recent sprints (Sprint 28 Auth Bypass, Sprint 27 File Upload, Sprint 26 API Security) standardize on a multi-file collector test layout:
1. **Core Unit & Component Test File** (e.g., `tests/collectors/test_auth_bypass.py`, 949 lines, 28 tests):
   - Enums and compatibility aliases (`Severity`, `VulnerabilityType`, `MutationStrategy`).
   - `PayloadGenerator` tests (validating probe generation across every mode, parameters, benign baseline probes, `apply_mutation`).
   - `Prober` tests (verifying HTTP request dispatch, custom headers, query params, timeout handling).
   - `Analyzer` tests (verifying detection logic on vulnerable responses, CWE/CVSS scoring calibration, and false positive rejection on benign/sanitized responses).
   - `Collector` lifecycle tests (verifying `collect()`, endpoint extraction from mission inputs, live hosts, and fallback target URL).
   - **Quadruple State Publishing** tests (verifying publication to `raw_mission.evidence`, `raw_mission.vulnerabilities`, `attack_surface_graph`, and `ControlledMission.publish_finding`).
2. **Adversarial & Edge-Case Test File** (e.g., `tests/collectors/test_auth_bypass_adversarial.py`, 462 lines, 19 tests):
   - Evasion & mutation strategy verification (encoding variations, Unicode normalization, content-type manipulation, URL layer bypasses).
   - WAF and rate limit rejection tests (ensuring HTTP 403 WAF blocks, 429 rate limit responses, and 415 unsupported media types do NOT trigger false positives).
   - Network fault tolerance (socket hang, HTTP timeout, empty responses, malformed JSON/HTML).
   - Extreme boundary conditions (empty target URLs, massive payloads, recursive objects).
3. **Pipeline Connectivity Test File** (e.g., `tests/collectors/test_auth_bypass_pipeline.py`, 392 lines, 20 tests):
   - `ToolRegistry` registration & priority (`argus/runtime/registry.py`).
   - `ToolRegistry` alias resolution (15-20+ aliases resolving to primary ID).
   - `PluginExecutorAdapter` fallback instantiation (`argus/runtime/plugins.py`).
   - `TaskGenerator` `_RECON_TEMPLATES` DAG definition (`argus/planning/task_generator.py`).
   - `TaskGenerator` gap resolution (`_template_for_gap` resolving coverage gap strings).
   - `AttackSurfaceGraphBuilder` Section ingestion into `KnowledgeGraph` (`argus/graph/attack_surface.py`).
   - `CVSSCalculator` CWE database mappings (`argus/reporting/cvss.py`).

### 1.4 Codebase Locations Requiring Pipeline Wiring for Sprint 29
- `argus/collectors/prototype_pollution.py` (New primary collector module).
- `argus/runtime/registry.py` (Tool definition with id `"prototype_pollution"` + 20+ aliases).
- `argus/runtime/plugins.py` (`PluginExecutorAdapter._instantiate_specialist_fallback`).
- `argus/planning/task_generator.py` (`_RECON_TEMPLATES["prototype_pollution"]`, gap resolution, and `generate_recon_tasks`).
- `argus/graph/attack_surface.py` (Section 29: Ingestion of `prototype_pollution`, `client_side`, `dom_clobbering`, `open_redirect`, `clickjacking` evidence into `KnowledgeGraph`).
- `argus/reporting/cvss.py` (CWE mappings for `CWE-1321`, `CWE-79`, `CWE-601`, `CWE-1021`).

---

## 2. Logic Chain

1. **Baseline Invariance**:
   - Observation 1.1 establishes that 1,929 tests currently pass with 0 failures across all 113 test files.
   - Therefore, Sprint 29 must ensure strict zero-regression compliance (1,929 existing tests continue to pass + >=25 new tests).
2. **Mocking & Isolation Determinism**:
   - Observation 1.2 demonstrates that the entire test suite executes in ~63 seconds because it uses deterministic in-memory `HttpResponse` mocking rather than socket-bound servers or heavy mocking frameworks.
   - Therefore, Sprint 29 tests must implement lightweight, configurable mock HTTP clients (`MockPrototypePollutionHttpClient` and `MockAdversarialHttpClient`) to ensure high-speed, 100% deterministic test execution without network flakiness.
3. **Test Suite Modularity**:
   - Observation 1.3 shows that splitting the test suite into 3 dedicated test files (`test_prototype_pollution.py`, `test_prototype_pollution_adversarial.py`, `test_prototype_pollution_pipeline.py`) provides clean separation of concerns: core functionality, adversarial robustness, and end-to-end pipeline wiring.
   - Therefore, Sprint 29 should follow this 3-file pattern to achieve >=25 (targeting 50-70) high-coverage tests.
4. **Pipeline Connectivity Completeness**:
   - Observation 1.4 identifies the exact 5 touchpoints in the runtime/graph/planning/reporting subsystems.
   - Therefore, dedicated pipeline tests must verify all 5 integration points (Registry, Adapter, TaskGenerator DAG, AttackSurfaceGraphBuilder Section 29, CVSSCalculator CWE mappings).

---

## 3. Caveats

- **No Live Browser / Headless Engine**: ARGUS active collectors operate via HTTP probing (`AuthenticatedHttpClient` and heuristic DOM/AST analyzers) rather than spawning heavy headless browsers (Puppeteer/Playwright). Tests simulate DOM clobbering and client-side gadget execution via deterministic response inspection and syntax/structure validation.
- **Deprecation Warnings in Test Output**: The baseline test execution outputs datetime deprecation warnings (`utcnow()` vs timezone-aware datetimes) from legacy modules; these do not affect test execution and should not be modified to avoid out-of-scope regressions.
- **Workspace Test Exclusion**: Tests in `tests/workspace/` are benchmark/temporary test targets and are excluded via `--ignore=tests/workspace`.

---

## 4. Conclusion & Recommended Test Matrix for Sprint 29

### 4.1 Recommended Test File Architecture

We recommend creating 3 dedicated test files in `tests/collectors/` totaling **50+ test cases**:

```
tests/collectors/
├── test_prototype_pollution.py             # ~25-30 Unit, Component & Analyzer Tests
├── test_prototype_pollution_adversarial.py # ~15-20 Adversarial, Evasion & Robustness Tests
└── test_prototype_pollution_pipeline.py    # ~15-20 Pipeline, DAG, Graph & CVSS Tests
```

---

### 4.2 Comprehensive Test Matrix

#### Suite 1: `tests/collectors/test_prototype_pollution.py` (Core Unit & Component Tests)
| Test Function | Target Component | Description / Acceptance Criteria Tested |
|---|---|---|
| `test_prototype_pollution_severity_enums_and_aliases` | Enums | Validates `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `CRIT` alias. |
| `test_prototype_pollution_vulnerability_type_enums_and_aliases` | Enums | Validates all 8 vulnerability types and compatibility aliases. |
| `test_prototype_pollution_mutation_strategy_enums_and_aliases` | Enums | Validates 5 mutation strategies + `STANDARD` and aliases. |
| `test_payload_generator_server_side_pollution_probes` | Generator (R2.1) | Generates `__proto__` and `constructor.prototype` JSON body injection payloads. |
| `test_payload_generator_client_side_pollution_probes` | Generator (R2.2) | Generates URL query and hash gadget payloads (`location.hash`, `__proto__[key]`). |
| `test_payload_generator_dom_clobbering_probes` | Generator (R2.3) | Generates HTML payloads shadowing `document.cookie`, `document.body`, `document.getElementById`. |
| `test_payload_generator_open_redirect_probes` | Generator (R2.4) | Generates redirect probes for parameters `url=`, `next=`, `redirect=`, `return_to=`, `continue=`. |
| `test_payload_generator_clickjacking_probes` | Generator (R2.5) | Generates inspection requests for sensitive endpoints (login, settings, payment). |
| `test_payload_generator_framework_gadget_probes` | Generator (R3) | Generates Express, Lodash, Handlebars, and jQuery specific gadget payloads. |
| `test_payload_generator_dos_and_rce_gadget_probes` | Generator (R3) | Generates `toString`/`valueOf` DoS and `child_process.exec` options RCE payloads. |
| `test_payload_generator_benign_baseline_probes` | Generator | Generates clean non-polluting baseline probes for comparative differential analysis. |
| `test_prober_http_dispatch_and_history` | Prober (R1) | Dispatches probes through `AuthenticatedHttpClient`, captures request/response telemetry. |
| `test_prober_error_and_timeout_resilience` | Prober (R1) | Handles network timeouts, connection drops, and HTTP 500 errors gracefully. |
| `test_analyzer_server_side_pollution_detection` | Analyzer (R2.1) | Detects server-side prototype pollution via status code/header/body side effects. |
| `test_analyzer_client_side_pollution_detection` | Analyzer (R2.2) | Detects client-side prototype pollution via DOM mutation/XSS sink indicators. |
| `test_analyzer_dom_clobbering_detection` | Analyzer (R2.3) | Detects DOM clobbering injection; calibrates High (XSS) vs Medium (logic corruption). |
| `test_analyzer_open_redirect_single_hop_detection` | Analyzer (R2.4) | Detects unvalidated external redirection (301/302/307/308 / Meta refresh / JS redirect). |
| `test_analyzer_open_redirect_multi_hop_chain_detection`| Analyzer (R2.4) | Traces multi-hop redirect chains (`A -> B -> C -> evil.com`) and reports complete path. |
| `test_analyzer_clickjacking_missing_headers_detection` | Analyzer (R2.5) | Flags sensitive pages missing `X-Frame-Options` and CSP `frame-ancestors`. |
| `test_analyzer_framework_gadget_classification` | Analyzer (R3) | Correctly identifies Lodash/Express/Handlebars gadget chains and assigns High/Crit severity. |
| `test_analyzer_rce_gadget_classification` | Analyzer (R3) | Identifies Node.js `child_process` pollution and assigns Critical severity. |
| `test_analyzer_fp_rejection_proto_sanitization` | Analyzer (AC FP) | Rejects endpoints that strip/sanitize `__proto__` keys without side effects. |
| `test_analyzer_fp_rejection_same_origin_redirects` | Analyzer (AC FP) | Rejects redirects restricted to same-origin or allowlisted domains. |
| `test_analyzer_fp_rejection_proper_frame_busting` | Analyzer (AC FP) | Rejects pages with `X-Frame-Options: DENY`/`SAMEORIGIN` or CSP `frame-ancestors 'self'`. |
| `test_analyzer_fp_rejection_standard_error_codes` | Analyzer (AC FP) | Rejects standard 400/404/405/422 responses without pollution side effects. |
| `test_collector_endpoint_extraction_and_lifecycle` | Collector (R1) | Extracts endpoints from mission inputs, live hosts, and fallback target URL. |
| `test_collector_quadruple_state_publishing` | Collector (R1) | Verifies findings published to `evidence`, `vulnerabilities`, `graph`, and `publish_finding`. |
| `test_collector_empty_target_and_resilience` | Collector | Verifies graceful degradation when mission target or endpoints are empty. |

---

#### Suite 2: `tests/collectors/test_prototype_pollution_adversarial.py` (Adversarial, Evasion & Mutation Tests)
| Test Function | Strategy / Attack Vector | Description / Acceptance Criteria Tested |
|---|---|---|
| `test_mutation_strategy_json_key_encoding_variations` | Mutation 1 (R4.1) | Tests `\u005f\u005fproto\u005f\u005f`, `constructor["prototype"]`, `__proto__.polluted`. |
| `test_mutation_strategy_content_type_manipulation` | Mutation 2 (R4.2) | Tests `application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`. |
| `test_mutation_strategy_url_encoding_layers_redirect` | Mutation 3 (R4.3) | Tests double URL encoding `%252f%252fevil.com`, unicode normalization, backslash `\/`. |
| `test_mutation_strategy_scheme_relative_and_auth_bypass` | Mutation 3 (R4.3) | Tests scheme-relative `//evil.com` and authority prefix `https://example.com@evil.com`. |
| `test_mutation_strategy_dom_clobbering_variants` | Mutation 4 (R4.4) | Tests `<form id="...">`, `<object id="...">`, `<a id="x" name="y">`, nested clobbering. |
| `test_mutation_strategy_frame_busting_bypass_techniques`| Mutation 5 (R4.5) | Tests `sandbox` attribute framing, double framing, and `data:` URI framing. |
| `test_adversarial_waf_403_rejection` | Robustness | Ensures WAF 403 Forbidden responses are NOT misidentified as vulnerabilities. |
| `test_adversarial_rate_limiting_429_rejection` | Robustness | Ensures 429 Too Many Requests responses are NOT misidentified as DoS or pollution. |
| `test_adversarial_unsupported_media_type_415` | Robustness | Ensures 415 Unsupported Media Type responses are ignored gracefully. |
| `test_adversarial_malformed_json_and_html_handling` | Robustness | Validates parser resilience against truncated, unclosed, or invalid JSON/HTML. |
| `test_adversarial_deeply_nested_prototype_traversal` | Deep Traversal (R3)| Validates traversal depth analysis on deeply nested JSON structures (`a.b.c.d.__proto__`). |
| `test_adversarial_network_timeout_and_socket_drop` | Fault Tolerance | Validates collector handles socket hang-ups and timeouts without crashing mission. |
| `test_adversarial_high_concurrency_burst` | Stress | Validates thread safety and probe state isolation under concurrent probe dispatch. |
| `test_adversarial_unicode_fullwidth_homoglyphs` | Evasion | Tests fullwidth ASCII (e.g., `＿＿ｐｒｏｔｏ＿＿`) and unicode compatibility mapping. |

---

#### Suite 3: `tests/collectors/test_prototype_pollution_pipeline.py` (Pipeline & DAG Integration Tests)
| Test Function | Pipeline Component | Description / Acceptance Criteria Tested |
|---|---|---|
| `test_tool_registry_registration` | ToolRegistry (R5) | Verifies `prototype_pollution` tool registered with capabilities, inputs, outputs. |
| `test_tool_registry_alias_resolution` | ToolRegistry (R5) | Verifies 15-20+ aliases resolve correctly to `prototype_pollution`. |
| `test_plugin_executor_adapter_instantiation` | PluginExecutorAdapter (R5)| Verifies primary ID and all aliases instantiate `PrototypePollutionCollector`. |
| `test_task_generator_dag_recon_template_definition` | TaskGenerator DAG (R5) | Verifies `_RECON_TEMPLATES["prototype_pollution"]` definition and dependencies. |
| `test_task_generator_direct_gap_resolution` | TaskGenerator DAG (R5) | Verifies coverage gap names ("prototype pollution", "client side", "dom clobbering", "open redirect", "clickjacking") resolve to template. |
| `test_task_generator_generate_recon_tasks_wiring` | TaskGenerator DAG (R5) | Verifies task generation from discovered endpoints in mission workflow. |
| `test_attack_surface_graph_section29_node_creation` | AttackSurfaceGraph (R5) | Verifies Section 29 creates `vulnerability` and `endpoint` nodes in `KnowledgeGraph`. |
| `test_attack_surface_graph_section29_has_vulnerability_edges`| AttackSurfaceGraph (R5)| Verifies `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges connect `live_host` and `endpoint`. |
| `test_attack_surface_graph_reconstruction_from_evidence` | AttackSurfaceGraph (R5)| Verifies offline reconstruction of graph directly from `EvidenceStore`. |
| `test_cvss_calculator_cwe_mappings` | CVSSCalculator (R5) | Verifies `CWE-1321`, `CWE-79`, `CWE-601`, `CWE-1021` mapped in `CVSSCalculator._CWE_MAP`. |
| `test_cvss_calculator_severity_and_score_calibration` | CVSSCalculator (R5) | Verifies accurate CVSS score computation across prototype pollution findings. |
| `test_controlled_mission_compatibility` | ControlledMission (R1) | Verifies full compatibility with `ControlledMission` interface. |

---

## 5. Verification Method

To independently verify all findings and test suite integrity:

1. **Verify Baseline Test Suite Execution**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -q
   ```
   *Expected Output*: `1929 passed` with exit code `0`.

2. **Verify Fast Test Collection and Breakdown**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace --collect-only -q
   ```
   *Expected Output*: `1929 tests collected in ~2.1s`.

3. **Verify Sprint 29 Test Execution (Post-Implementation)**:
   ```bash
   python -m pytest tests/collectors/test_prototype_pollution*.py -v
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   *Expected Output*: All 1,929 existing tests pass + >=25 new Sprint 29 tests pass (>= 1,954 total passing, 0 regressions, exit code `0`).

4. **Invalidation Conditions**:
   - Any failure in the existing 1,929 baseline tests.
   - Any external network dependencies introduced in collector unit tests.
   - Any missing alias resolution in `ToolRegistry` or unmapped CWE in `CVSSCalculator`.
