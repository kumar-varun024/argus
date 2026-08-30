# Test & Mission Workflow Investigation & Sprint 9 Test Plan

**Agent**: `survey_explorer_3` (Test & Mission Workflow Explorer)  
**Milestone**: Sprint 9 — Database Query Safety Validation Engine  
**Working Directory**: `/home/varun/argus/.agents/survey_explorer_3/`  
**Target Repository**: `/home/varun/argus`  

---

## 1. Observation

### 1.1 Test Suite Inventory & Baseline Performance
- **Pytest Execution Command**: `python3 -m pytest tests/ --ignore=tests/workspace -q`
- **Total Test Discovery**: 896 tests collected in 1.57s.
- **Baseline Test Suite**: 861 existing tests passing without regression.
- **Sprint 9 SQL Injection Test Inventory**: 35 total tests created across 3 dedicated test files:
  1. `tests/collectors/test_sql_injection.py` (20 tests)
  2. `tests/collectors/test_sql_injection_adversarial.py` (12 tests)
  3. `tests/runtime/test_e2e_sql_injection.py` (3 tests)
- **Current Run Status**: 894 passed, 2 failed (both failure mechanisms identified in Section 1.4).

### 1.2 Collector Test Architecture (Sprint 5, 6, 8, 9)
Across all sprint iterations, ARGUS collectors follow a consistent test architecture:
- **Sprint 5 (Information Disclosure)**: `tests/collectors/test_information_disclosure.py` & `test_information_disclosure_adversarial.py`
  - Pattern: Tests regex extractors (`SecretExtractor`), endpoint probes (`.env`, `.git/config`, `/actuator/env`, `phpinfo.php`, `.js.map`), 404/non-200 exclusion, and `KnowledgeGraph` expansion (`live_host`, `endpoint`, `vulnerability`, `secret`, `subdomain` nodes with `EXPOSES_SECRET`, `DISCLOSED_SUBDOMAIN` edges).
- **Sprint 6 (Access Control & IDOR)**: `tests/collectors/test_access_control.py` & `test_challenger2_access_control_adversarial.py`
  - Pattern: Tests `TestIdentity` multi-identity execution (`execute_as`), `ResponseDiscrepancyAnalyzer`, horizontal IDOR, vertical privilege escalation, proxy header bypasses (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host`), soft-403/login form rejection, and `ControlledMission` unpacking.
- **Sprint 8 (Path & Directory Traversal)**: `tests/collectors/test_path_traversal.py`, `test_path_traversal_adversarial.py`, `tests/runtime/test_e2e_path_traversal.py`
  - Pattern: Tests `PathTraversalPayloadGenerator` (relative, double encoded, null-byte, windows/unix), `PathTraversalAnalyzer` (OS file signatures for `/etc/passwd`, `/etc/shadow`, `win.ini`, `boot.ini`), candidate endpoint extraction from query params and path segments, DAG reconnaissance templates, `registry.py` registration, and `AttackSurfaceGraphBuilder` reconstruction.
- **Sprint 9 (Database Query Safety Validation)**: `tests/collectors/test_sql_injection.py`, `test_sql_injection_adversarial.py`, `tests/runtime/test_e2e_sql_injection.py`
  - Pattern: Tests `SQLInjectionPayloadGenerator`, `SQLInjectionAnalyzer`, `SQLInjectionCollector`, `TaskGenerator` DAG wiring, `registry.py` tool entry, `PluginExecutorAdapter` dispatch, multi-DBMS error matching, boolean differential analysis, time delay analysis (>4.0s), and WAF bypass mutation strategies.

### 1.3 Mocking & Fixtures Infrastructure
1. **Route-Based HTTP In-Memory Mocks**:
   - `MockSQLiHttpClient` (`tests/collectors/test_sql_injection.py:29-131`): Supports route mapping keyed by exact URL, `header:<name>:<val>`, or `payload:<json/data_val>`. Returns `HttpResponse(success, status_code, raw_body, body, url, elapsed)`.
   - `MockAdversarialSQLiHttpClient` (`tests/collectors/test_sql_injection_adversarial.py:22-86`): Allows registering specific network exceptions (e.g. `TimeoutError`, `ConnectionError`) on target URLs to verify collector resilience.
   - `MockE2ESQLiHttpClient` (`tests/runtime/test_e2e_sql_injection.py:28-89`): Emulates realistic web applications with multi-technique SQLi endpoints, baseline latency timing, and call history tracking.
2. **Local HTTP Test Servers**:
   - `HTTPServer` on dynamic ephemeral ports (`find_free_port()`) using `MockAuthHttpHandler` in `tests/http/test_authenticated_http_client.py` and `tests/http/test_sprint4_empirical_stress.py`.
3. **Registry Isolation Fixtures**:
   - `isolated_tool_registry` fixture in `tests/runtime/test_e2e_mission.py` saves `registry.tools`, registers test mocks, and restores the global state upon test completion.

### 1.4 Test Failure Diagnostic Analysis
1. **Failure 1**: `tests/collectors/test_sql_injection.py::test_sql_injection_analyzer_reflection_discard`
   - **Line**: `tests/collectors/test_sql_injection.py:372`
   - **Observation**: `assert analyzer.is_false_positive(reflection_resp, payload="' OR 1=1--") is True` evaluated to `False is True`.
   - **Root Cause**: In `argus/collectors/sql_injection.py:311-316`, `is_false_positive()` checks for generic error keywords when `not has_dbms_sig`. When a response has no DBMS signature but reflects the payload verbatim (e.g. `<p>You searched for: ' OR 1=1--</p>`), `is_false_positive` skipped the reflection check and returned `False`.
   - **Fix**: In `SQLInjectionAnalyzer.is_false_positive()`, when `not has_dbms_sig`, if `clean_payload in body_str`, return `True` (as it is a pure reflection without DB error).
2. **Failure 2**: `tests/runtime/test_e2e_sql_injection.py::test_e2e_sql_injection_mission_loop_flow`
   - **Line**: `tests/runtime/test_e2e_sql_injection.py:145`
   - **Observation**: `evidence_list = collector.execute(controlled_mission); assert len(evidence_list) >= 1` returned `0 >= 1`.
   - **Root Cause**: `controlled_mission` wraps `_mission` and does not directly expose `.endpoints` or `.live_hosts`. `SQLInjectionCollector.collect()` checked `getattr(mission, "endpoints", [])` instead of unpacking `raw_mission = getattr(mission, "_mission", mission)`.
   - **Fix**: In `SQLInjectionCollector.collect(self, mission: Any)`, unpack `raw_mission = getattr(mission, "_mission", mission)` (identical to `AccessControlCollector.collect` at `argus/collectors/access_control.py:263`).

---

## 2. Logic Chain

```
[User Request / Sprint 9 Requirements]
                 │
                 ▼
[Inspect Baseline Test Suite] ──> 861 existing tests passing, 0 regressions
                 │
                 ▼
[Survey Existing Collectors] ──> Sprint 5 (.env/secrets), Sprint 6 (IDOR/Authz), Sprint 8 (LFI/Traversal)
                 │               All use BaseCollector, AuthenticatedHttpClient, EvidenceStore, KnowledgeGraph
                 ▼
[Audit Mocking Patterns] ─────> In-memory MockHttpClient route dictionaries with elapsed timing + headers
                 │
                 ▼
[Audit E2E Mission Flow] ─────> TaskGenerator DAG -> registry.py -> PluginExecutorAdapter -> ControlledMission
                 │               -> Evidence(category="sql_injection", severity="critical") -> AttackSurfaceGraph
                 ▼
[Sprint 9 Test Plan Design] ──> 35 comprehensive tests covering all 8 required categories
                 │
                 ▼
[Diagnose 2 Test Failures] ───> 1) is_false_positive reflection logic; 2) ControlledMission unpacking in collect()
```

---

## 3. Caveats

1. **Read-Only Explorer Scope**: In accordance with the prompt guidelines, no modifications were made to `/home/varun/argus/argus/collectors/sql_injection.py`. The two identified code adjustments are documented with exact diffs for the implementer agent.
2. **Deprecation Warnings in Test Output**: The test run emits deprecation warnings regarding `datetime.utcnow()` and `pydantic` v1 config dicts in existing test files (`tests/orchestration/test_orchestrator.py`, `argus/runtime/models.py`). These are standard library deprecation warnings from prior sprints and do not affect test execution.
3. **No External Network Dependencies**: All 35 tests operate in-memory with deterministic mock HTTP clients without relying on external network services.

---

## 4. Conclusion & Sprint 9 Test Plan

### 4.1 Detailed Test Plan Matrix (35 Tests Across 8 Categories)

| # | Test Name | File | Technique / Category | Assertions & Expected Outcomes |
|---|---|---|---|---|
| **Category 1: Error-Based DBMS Detection** |
| 1 | `test_sql_injection_analyzer_error_mysql` | `test_sql_injection.py` | Error-Based (MySQL) | Matches syntax error / manual regex; emits `dbms='mysql'`, `severity='critical'`, `template_id='sqli-error-mysql'`. |
| 2 | `test_sql_injection_analyzer_error_postgres` | `test_sql_injection.py` | Error-Based (PostgreSQL) | Matches `pg_query()`, `PSQLException`; emits `dbms='postgresql'`, `severity='critical'`, `template_id='sqli-error-postgresql'`. |
| 3 | `test_sql_injection_analyzer_error_mssql` | `test_sql_injection.py` | Error-Based (MSSQL) | Matches `[SQL Server]`, `[ODBC SQL Server Driver]`, unclosed quote; emits `dbms='mssql'`, `severity='critical'`, `template_id='sqli-error-mssql'`. |
| 4 | `test_sql_injection_analyzer_error_oracle` | `test_sql_injection.py` | Error-Based (Oracle) | Matches `ORA-01756`, quoted string not terminated; emits `dbms='oracle'`, `severity='critical'`, `template_id='sqli-error-oracle'`. |
| 5 | `test_sql_injection_analyzer_error_sqlite` | `test_sql_injection.py` | Error-Based (SQLite) | Matches `sqlite3.OperationalError`, `SQLITE_ERROR`; emits `dbms='sqlite'`, `severity='critical'`, `template_id='sqli-error-sqlite'`. |
| 6 | `test_sql_injection_collector_query_param_error_based` | `test_sql_injection.py` | GET Query Fuzzing | Fuzzes `?id=1` with `'`, creates `Evidence(category='sql_injection', status='CONFIRMED', confidence=0.95)`, updates mission vulnerabilities & graph. |
| 7 | `test_sql_injection_collector_post_body_json` | `test_sql_injection.py` | POST JSON Body Fuzzing | Fuzzes POST JSON `{"username": "admin"}`, detects PostgreSQL error, emits `parameter_type='post_body'`. |
| 8 | `test_sql_injection_collector_headers` | `test_sql_injection.py` | HTTP Header Fuzzing | Injects payload into `X-Forwarded-For`, `Cookie`, `Referer`; flags MSSQL error with `parameter_type='header'`. |
| **Category 2: Boolean-Based Differential Analysis** |
| 9 | `test_sql_injection_analyzer_boolean_differential_length` | `test_sql_injection.py` | Length Differential | Compares TRUE (2000B) vs FALSE (100B) responses; emits `severity='high'`, `length_delta=1900`, `template_id='sqli-boolean-blind'`. |
| 10 | `test_sql_injection_analyzer_boolean_differential_status` | `test_sql_injection.py` | Status Differential | Compares TRUE (200 OK) vs FALSE (404 Not Found); emits `subtype='status_code_differential'`, `severity='high'`. |
| 11 | `test_sql_injection_analyzer_boolean_identical_reject` | `test_sql_injection.py` | Invariant Check | Ensures identical TRUE/FALSE responses return `None` (no false positive). |
| 12 | `test_adversarial_dynamic_token_noise_filter` | `test_sql_injection_adversarial.py` | Dynamic Noise Filter | Dynamic CSRF token / timestamp length variations (1-5 bytes) are rejected as benign noise. |
| **Category 3: Time-Based Blind Differential Analysis** |
| 13 | `test_sql_injection_analyzer_time_delay_confirmed` | `test_sql_injection.py` | Time Delay >= 4.0s | Baseline 0.08s, Injected 5.12s (delta > 4.0s); emits `technique='time_blind'`, `severity='critical'`, `template_id='sqli-time-blind'`. |
| 14 | `test_sql_injection_analyzer_time_delay_rejected` | `test_sql_injection.py` | Time Delay < 4.0s Reject | Baseline 4.30s, Injected 4.60s (delta 0.30s < 4.0s threshold); returns `None`. |
| 15 | `test_sql_injection_generator_base_payloads` | `test_sql_injection.py` | Generator Payload Integrity | Verifies presence of `SLEEP(5)`, `pg_sleep(5)`, `WAITFOR DELAY`, and `dbms_pipe.receive_message`. |
| **Category 4: False Positive Prevention & Evasion** |
| 16 | `test_sql_injection_analyzer_false_positive_rejection` | `test_sql_injection.py` | Generic Error Rejection | Generic HTML error title `<title>Application Error</title>` containing word "database" rejected. |
| 17 | `test_sql_injection_analyzer_reflection_discard` | `test_sql_injection.py` | Reflection Suppression | Echoed search string `<p>You searched for: ' OR 1=1--</p>` rejected as reflection. |
| 18 | `test_adversarial_pre_existing_baseline_db_error` | `test_sql_injection_adversarial.py` | Pre-existing Error Guard | Baseline 500 DB error is not attributed to injected payload. |
| 19 | `test_adversarial_malformed_url_and_empty_endpoints` | `test_sql_injection_adversarial.py` | Input Robustness | None/empty/malformed URLs handled gracefully with 0 crashes. |
| 20 | `test_adversarial_http_exception_and_timeout` | `test_sql_injection_adversarial.py` | Network Fault Tolerance | Network timeout exceptions handled gracefully without crashing collector. |
| **Category 5: 5+ Input Mutation Strategies** |
| 21 | `test_sql_injection_generator_waf_mutations` | `test_sql_injection.py` | All 5 WAF Strategies | Verifies: 1. Case Alternation (`uNiOn`), 2. Comment Insertion (`/**/`), 3. URL Encoding (`%27`), 4. Double Encoding (`%2527`), 5. Whitespace Substitution (`%09`). |
| 22 | `test_adversarial_waf_case_alternation_execution` | `test_sql_injection_adversarial.py` | Case Alternation Variant | Validates multi-keyword case alternation across complex SQL statements. |
| 23 | `test_adversarial_waf_comment_insertion_execution` | `test_sql_injection_adversarial.py` | Inline Comments Variant | Validates `/**/` keyword splitting. |
| 24 | `test_adversarial_waf_url_and_double_encoding` | `test_sql_injection_adversarial.py` | Multi-tier Encoding | Validates percent and double-percent quote encoding. |
| 25 | `test_adversarial_waf_whitespace_substitutions` | `test_sql_injection_adversarial.py` | Whitespace Alternatives | Validates tabs `%09`, newlines `%0a`, and comments `/**/`. |
| **Category 6: Graph Edge (HAS_VULNERABILITY) Creation** |
| 26 | `test_sql_injection_attack_surface_graph_builder_reconstruction` | `test_sql_injection.py` | Graph Builder Reconstruction | Reconstructs `KnowledgeGraph` from `EvidenceStore`; confirms `live_host -> HAS_ENDPOINT -> endpoint` and `HAS_VULNERABILITY` edges. |
| 27 | `test_adversarial_multiple_parameters_on_same_endpoint` | `test_sql_injection_adversarial.py` | Graph Collision Avoidance | Separate parameters (`user`, `cat`) on same endpoint create distinct graph vulnerability nodes. |
| 28 | `test_adversarial_non_ascii_unicode_in_parameters` | `test_sql_injection_adversarial.py` | Unicode Node Handling | Non-ASCII/Unicode parameter names and values processed cleanly into graph. |
| 29 | `test_adversarial_nested_and_deep_json_body` | `test_sql_injection_adversarial.py` | Nested JSON Graphing | Deeply nested JSON structures fuzzed and mapped to endpoint nodes. |
| **Category 7: Pipeline / TaskGenerator Integration** |
| 30 | `test_sql_injection_task_generator_dag_wiring` | `test_sql_injection.py` | Task DAG Templates | Verifies `_RECON_TEMPLATES["sql_injection"]` depends on "Discover API Endpoints"; resolves `CoverageGap(area="sql injection")`. |
| 31 | `test_sql_injection_tool_registry_and_plugin_adapter` | `test_sql_injection.py` | ToolRegistry & Adapter | Verifies `registry.get("sql_injection")` has `sql_injection_detector` capability and `PluginExecutorAdapter` fallback. |
| 32 | `test_e2e_sql_injection_gap_analysis_and_replanning` | `test_e2e_sql_injection.py` | Gap Replanning | Verifies `TaskGenerator` maps `CoverageGap(area="sql_injection")` to task with priority and dependencies. |
| **Category 8: E2E Mission Workflow Integration** |
| 33 | `test_e2e_sql_injection_mission_loop_flow` | `test_e2e_sql_injection.py` | Full Mission Loop | Full pipeline: Target -> Scope -> DAG -> Registry -> Adapter -> ControlledMission -> Evidence -> Graph -> Reconstructed Graph. |
| 34 | `test_e2e_sql_injection_multi_technique_mission` | `test_e2e_sql_injection.py` | Multi-Technique Mission | Multi-endpoint target with error-based (critical) and boolean-based (high) SQLi verified simultaneously. |
| 35 | `test_adversarial_controlled_mission_execute_adapter` | `test_sql_injection_adversarial.py` | ControlledMission Adapter | Executes collector through `ControlledMission(mission)` wrapper. |

---

## 5. Verification Method

### 5.1 Verification Commands
To independently verify the test suite:

```bash
# 1. Run all Sprint 9 SQL Injection tests:
python3 -m pytest tests/collectors/test_sql_injection.py tests/collectors/test_sql_injection_adversarial.py tests/runtime/test_e2e_sql_injection.py -v

# 2. Run full test suite with zero regressions:
python3 -m pytest tests/ --ignore=tests/workspace -q
```

### 5.2 Required Implementation Adjustments (For Implementer Agent)
In `/home/varun/argus/argus/collectors/sql_injection.py`:

1. **Unpack `ControlledMission` in `collect()`**:
```python
# At start of SQLInjectionCollector.collect(self, mission: Any):
raw_mission = getattr(mission, "_mission", mission)
# Pass raw_mission to _extract_candidate_endpoints, _execute_request, and _create_evidence_and_update_state
```

2. **Update `is_false_positive()` for pure reflections without DBMS error**:
```python
# In SQLInjectionAnalyzer.is_false_positive(self, response: HttpResponse, payload: str):
if not has_dbms_sig:
    if clean_payload and clean_payload in body_str:
        return True
    if any(w in body_str.lower() for w in ["error", "syntax", "sql", "database"]):
        return True
```

With these 2 adjustments applied:
- `python3 -m pytest tests/ --ignore=tests/workspace -q` exits `0`.
- 896 passed tests (861 baseline + 35 new Sprint 9 tests), 0 failures, 0 regressions.
