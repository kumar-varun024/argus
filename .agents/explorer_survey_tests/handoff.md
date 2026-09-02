# Handoff Report: ARGUS API Security Testing Module — Test Architecture Survey & Test Matrix Design

**Role**: Explorer 3 (Test Architecture Explorer)  
**Working Directory**: `/home/varun/argus/.agents/explorer_survey_tests`  
**Parent Task ID**: `fbd25589-2cf3-4a0d-b7b4-71b26863ee78`  
**Date/Timestamp**: 2026-09-02T03:07:30+05:30  
**Artifact**: `/home/varun/argus/.agents/explorer_survey_tests/handoff.md`  

---

## 1. Observation

Direct observations from the ARGUS codebase, test runners, and architecture analysis:

### 1.1 Baseline Test Suite Execution
- **Command executed**: `python -m pytest tests/ --ignore=tests/workspace -x -q`
- **Result**: `1828 passed, 50964 warnings in 63.43s (0:01:03)`
- **Exit Code**: `0`
- **Baseline Test Count**: Exactly **1,828 passing tests**, with zero failures or errors across the existing suite.

### 1.2 Collector Test Suite Structure & Conventions
Examined existing collector test suites:
- `tests/collectors/test_file_upload.py` (740 lines, 25 tests across 9 sections):
  - Models & Enums (`FileUploadSeverity`, `FileUploadTechnique`, `FileUploadMutationStrategy`)
  - Payload Generator (`FileUploadPayloadGenerator` with detection modes & mutations)
  - Prober (`FileUploadProber` handling multipart requests & storage URL resolution)
  - Analyzer (`FileUploadAnalyzer` with path/error disclosure & false positive rejection)
  - Collector lifecycle & Quadruple State Publishing (`raw_mission.evidence`, `raw_mission.vulnerabilities`, `attack_surface_graph`, `ControlledMission`)
  - ToolRegistry & Plugin Adapter fallback instantiation
  - TaskGenerator DAG template (`_RECON_TEMPLATES`) & gap resolution (`_resolve_template_for_gap`)
  - AttackSurfaceGraphBuilder Section 26 graph expansion (`HAS_ENDPOINT`, `HAS_VULNERABILITY` edges)
  - CVSSCalculator CWE mappings (`CWE-434`, `CWE-436`)
- `tests/collectors/test_file_upload_adversarial.py` (386 lines, 12 tests):
  - False positive rejection of hardened endpoints (proper server-side validation)
  - WAF 403 Forbidden & security block suppression
  - 415 Unsupported Media Type rejection handling
  - Error reflection without persistent storage
  - Safe UUID renaming and extension stripping
  - Network timeouts, connection drops, socket disconnect resilience
  - Malformed JSON / HTML body response resilience
  - Empty mission inputs / missing candidate endpoints graceful exit
  - Probe budget limit enforcement (`max_probes_per_endpoint`)
  - ControlledMission exception resilience
- `tests/collectors/test_cache_security.py` (628 lines):
  - Mock HTTP caching simulator (`MockCacheHttpClient`) modeling CDN cache keys, HIT/MISS headers, and unkeyed header reflections.
- `tests/collectors/test_cors_security.py` (203 lines):
  - Differential CORS probe analyzer testing origin reflection, null origin, wildcard credentials, and parser differentials.
- `tests/collectors/test_access_control.py` (448 lines):
  - Multi-identity testing using `TestIdentity` (Alice vs Bob) and `MockIDORHttpClient` verifying BOLA/IDOR detection and false positive rejection on 403.
- `tests/collectors/test_business_logic.py` (623 lines):
  - Parameter tampering (price/quantity) and mass assignment (`role`, `isAdmin`) workflow probing and analysis.

### 1.3 HTTP Mocking & Quadruple State Publishing Patterns
- **`AuthenticatedHttpClient`**: Found in `argus/http/client.py`. Used across collectors via dependency injection (`http_client: Optional[AuthenticatedHttpClient] = None`). Probers and collectors fall back to `AuthenticatedHttpClient(timeout=...)` if no mock client is supplied.
- **`HttpResponse` dataclass**: Found in `argus/http/client.py` (fields: `success`, `status_code`, `headers`, `request_headers`, `body`, `raw_body`, `url`, `method`, `elapsed`, `error`, `scope_decision`, `authorization_decision`).
- **Graph Node & Edge Conventions**:
  - Live Host node: `id="live_host:<host>"`, `type="live_host"`
  - Endpoint node: `id="endpoint:<url>"`, `type="endpoint"`
  - Vulnerability node: `id="vulnerability:<template_id>:<url>:<param>"`, `type="vulnerability"`
  - Edges: `live_host -> endpoint` (`HAS_ENDPOINT`), `live_host -> vulnerability` (`HAS_VULNERABILITY`), `endpoint -> vulnerability` (`HAS_VULNERABILITY`).
- **CVSS & CWE Mappings**:
  - Handled in `argus/reporting/cvss.py` via `CVSSCalculator.CWE_DATABASE`. Requirement R5 mandates mappings for `CWE-639` (BOLA/IDOR), `CWE-915` (Mass Assignment), and `CWE-770` (Rate Limiting).

---

## 2. Logic Chain

From the baseline observations and module requirements (R1–R6), we derive the complete test architecture specification:

1. **Tripartite Architecture Isolation**: The new module must follow the established collector architecture:
   - `APISecurityCollector` (inheriting from `BaseCollector`)
   - `APISecurityPayloadGenerator`
   - `APISecurityProber`
   - `APISecurityAnalyzer`
   Each component must be independently tested in unit tests, followed by collector lifecycle and pipeline integration tests.

2. **Full Requirement Coverage**:
   - **R1 & R2 (6 Detection Modes)**: Parameter Tampering, Mass Assignment, Rate Limiting Bypass, BOLA/IDOR, Excessive Data Exposure, Method Tampering.
   - **R3 (API Response Analysis)**: Schema violations, authorization boundaries, rate limit headers (`X-RateLimit-*`, `Retry-After`), error information disclosure, pagination/bulk extraction indicators.
   - **R4 (5 Mutation & Evasion Strategies)**: Content-Type Switching, Parameter Pollution, Header-Based Auth Bypass, Version Downgrade, Encoding Variations.
   - **R5 (Pipeline Connectivity)**: DAG scheduling, tool registry aliases, graph expansion (`HAS_VULNERABILITY` edges), CVSS/CWE mappings (CWE-639, CWE-915, CWE-770).
   - **R6 (Zero Regression & Test Count)**: >= 25 new tests across `test_api_security.py` and `test_api_security_adversarial.py`.

3. **Test Segregation Strategy**:
   - `tests/collectors/test_api_security.py`: 17 unit and integration tests covering happy-path detection, analyzer calibration, mutations, Quadruple State Publishing, registry, DAG, graph builder, and CVSS.
   - `tests/collectors/test_api_security_adversarial.py`: 12 adversarial and resilience tests covering false positive rejection on hardened endpoints, WAF handling, network failures, malformed payloads, rate limit enforcement, corrupted schemas, probe budgets, and wrapper errors.
   - Total planned tests: **29 tests** (exceeds the 25 test requirement).

---

## 3. Test Matrix Specification

### 3.1 `tests/collectors/test_api_security.py` (17 Tests)

| # | Test Function Name | Tested Component | Description & Acceptance Criteria |
|---|--------------------|------------------|-----------------------------------|
| 1 | `test_api_security_severity_enums_and_aliases` | Enums & Models | Verifies `APISecuritySeverity` values (CRITICAL, HIGH, MEDIUM, LOW, INFO) and aliases (`CRIT`). |
| 2 | `test_api_security_technique_enums_and_aliases` | Enums & Models | Verifies all 6 `APISecurityTechnique` / `APIVulnerabilityType` values (`PARAMETER_TAMPERING`, `MASS_ASSIGNMENT`, `RATE_LIMIT_BYPASS`, `BOLA_IDOR`, `EXCESSIVE_DATA_EXPOSURE`, `METHOD_TAMPERING`) and aliases. |
| 3 | `test_api_security_mutation_strategy_enums` | Enums & Models | Verifies all 5 `APIMutationStrategy` values (`CONTENT_TYPE_SWITCHING`, `PARAMETER_POLLUTION`, `HEADER_AUTH_BYPASS`, `VERSION_DOWNGRADE`, `ENCODING_VARIATIONS`). |
| 4 | `test_api_security_result_properties` | Enums & Models | Verifies `APISecurityResult` fields, default values, and computed properties (`is_valid_finding`, `cvss_score`, `cwe_id`). |
| 5 | `test_payload_generator_parameter_tampering_probes` | PayloadGenerator | Verifies generation of price, quantity, role, and discount mutation probes in JSON bodies and query parameters. |
| 6 | `test_payload_generator_mass_assignment_probes` | PayloadGenerator | Verifies injection of privileged properties (`isAdmin`, `role`, `balance`, `verified`, `tier`) into request payloads. |
| 7 | `test_payload_generator_rate_limit_bypass_probes` | PayloadGenerator | Verifies probe generation with rotating headers (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, `X-Originating-IP`). |
| 8 | `test_payload_generator_bola_idor_probes` | PayloadGenerator | Verifies probe generation across alternate user identifiers and resource ID substitutions. |
| 9 | `test_payload_generator_excessive_data_exposure_probes` | PayloadGenerator | Verifies generation of baseline and parameter expansion probes to inspect response field exposure. |
| 10 | `test_payload_generator_method_tampering_probes` | PayloadGenerator | Verifies generation of alternate HTTP method probes (PUT, DELETE, PATCH, OPTIONS) for discovered GET/POST endpoints. |
| 11 | `test_payload_generator_mutation_strategies` | PayloadGenerator | Verifies `apply_mutation` produces valid transformed probes across all 5 mutation strategies. |
| 12 | `test_analyzer_detection_modes_and_severity_calibration` | Analyzer | Verifies calibration: BOLA/IDOR -> High (CWE-639, CVSS 8.5+), Mass Assignment -> High (CWE-915, CVSS 7.5+), Parameter Tampering -> High (CWE-915/602), Rate Limiting Bypass -> Medium (CWE-770), Excessive Data Exposure -> Medium (CWE-200). |
| 13 | `test_analyzer_error_and_schema_information_disclosure` | Analyzer | Verifies detection of internal stack traces, database errors, and debug paths in 500 error responses (CWE-200). |
| 14 | `test_collector_full_lifecycle_and_quadruple_publishing` | Collector | Verifies end-to-end collection, generating Evidence and publishing across: (1) `mission.evidence`, (2) `mission.vulnerabilities`, (3) `mission.attack_surface_graph`, (4) `ControlledMission.publish_finding`. |
| 15 | `test_tool_registry_and_plugin_adapter_api_security` | Tool Registry | Verifies `registry.get("api_security")`, aliases (`api_security_collector`, `api_security_specialist`, `rest_api_security`), and `PluginExecutorAdapter` fallback. |
| 16 | `test_task_generator_dag_api_security_template_and_gap` | TaskGenerator DAG | Verifies `_RECON_TEMPLATES["api_security"]` DAG dependencies (`["Discover API Endpoints"]`) and gap resolution. |
| 17 | `test_attack_surface_graph_and_cvss_api_security_expansion` | Graph & CVSS | Verifies Section 27 graph node/edge creation (`HAS_ENDPOINT`, `HAS_VULNERABILITY`) and `CVSSCalculator` mappings for CWE-639, CWE-915, CWE-770. |

---

### 3.2 `tests/collectors/test_api_security_adversarial.py` (12 Tests)

| # | Test Function Name | Adversarial / Edge Scenario | Expected Resilient Behavior |
|---|--------------------|------------------------------|-----------------------------|
| 1 | `test_adversarial_legitimate_api_proper_auth_no_evidence` | Hardened API returns 401/403 for unauthorized BOLA accesses and 400 for tampered params. | 0 false positive findings, 0 evidence emitted. |
| 2 | `test_adversarial_rate_limiting_properly_enforced_no_evidence` | Origin enforces strict IP/token rate limits (429 Too Many Requests + Retry-After) despite header spoofing. | 0 rate limit bypass findings emitted. |
| 3 | `test_adversarial_reflected_parameter_in_validation_error_no_finding` | Server reflects invalid input parameter in error message body without persisting or executing changes. | No false positive parameter tampering or mass assignment finding. |
| 4 | `test_adversarial_filtered_response_no_excessive_data_exposure` | API response returns clean public DTOs without sensitive fields (passwords, tokens, SSNs). | No excessive data exposure finding emitted. |
| 5 | `test_adversarial_waf_403_rejection_patterns_no_evidence` | Cloudflare / AWS WAF returns 403 Forbidden with security block HTML signatures. | Suppresses all false positive findings. |
| 6 | `test_adversarial_network_timeout_and_socket_disconnect_resilience` | Mock client raises `TimeoutError`, `ConnectionResetError`, `httpx.ConnectError`. | Prober/collector catches errors gracefully; returns empty list without crashing. |
| 7 | `test_adversarial_malformed_json_and_html_error_response_resilience` | Server returns corrupted/truncated JSON bodies, HTML 502/504 pages, or binary responses. | Response analyzer safely parses without unhandled exceptions. |
| 8 | `test_adversarial_deeply_nested_and_corrupted_json_payloads` | Payloads with recursive objects, invalid types, or huge strings. | Payload generator & prober handle serialization without stack overflow. |
| 9 | `test_adversarial_empty_candidate_endpoints_graceful_exit` | Mission target has empty endpoints, live hosts, and inputs. | Collector exits cleanly, returning `[]`. |
| 10 | `test_adversarial_probe_budget_limit_enforcement` | Configured `max_probes_per_endpoint = 5` with 20 candidate probes. | Collector dispatches exactly 5 HTTP requests per endpoint, adhering strictly to budget. |
| 11 | `test_adversarial_missing_test_identities_graceful_bola_skip` | Mission contains zero or single test identity. | BOLA prober skips dual-context probes cleanly without `IndexError` or false positives. |
| 12 | `test_adversarial_controlled_mission_exception_resilience` | `ControlledMission.publish_finding` throws `RuntimeError`. | Collector continues publishing to `raw_mission` and graph without aborting scan. |

---

## 4. Caveats

- **Network Dependency**: Baseline test run confirms local unit and mock-based tests run fully offline without external network dependencies. All new tests must use mock HTTP clients (`MockAPISecurityHttpClient` / `AdversarialAPISecurityHttpClient`) to prevent network flakiness.
- **Python Deprecation Warnings**: Observed 50,964 warnings during pytest run relating to `datetime.utcnow()` deprecation in existing models. This is an existing codebase artifact and does not cause test failures.
- **Execution Time**: The full test suite takes ~63 seconds. Individual collector test suites run in under 0.5 seconds.

---

## 5. Conclusion

1. **Baseline Health**: Exactly **1,828 tests are passing** across the repository with zero regressions.
2. **Architecture Compliance**: The API Security Testing Module must follow the established tripartite pattern (`APISecurityCollector`, `APISecurityPayloadGenerator`, `APISecurityProber`, `APISecurityAnalyzer`) with Quadruple State Publishing and DAG integration.
3. **Complete Test Suite Matrix**: A concrete matrix of **29 new tests** (17 unit + 12 adversarial) has been designed to validate all 6 detection modes, 5 mutation strategies, response analysis, pipeline connectivity, and adversarial edge cases, satisfying requirement R6.

---

## 6. Verification Method

To independently verify the test suite baseline and future changes:

```bash
# 1. Run full baseline test suite (expected: 1,828 passed)
python -m pytest tests/ --ignore=tests/workspace -x -q

# 2. Run file upload collector tests as reference
python -m pytest tests/collectors/test_file_upload.py tests/collectors/test_file_upload_adversarial.py -v

# 3. Upon implementation of API security tests, verify target suite
python -m pytest tests/collectors/test_api_security.py tests/collectors/test_api_security_adversarial.py -v

# 4. Verify total test count increases by >= 25 (expected: >= 1,853 passed)
python -m pytest tests/ --ignore=tests/workspace -x -q
```
