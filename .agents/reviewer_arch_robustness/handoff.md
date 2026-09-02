# Reviewer 1 Handoff Report: Collector Architecture & Robustness

**Reviewer**: Reviewer 1 (Collector Architecture & Robustness Reviewer)  
**Target Milestone**: Sprint 17 (GraphQL Security Detection Module)  
**Date**: 2026-08-31  
**Verdict**: **APPROVE**

---

## 1. Observation

Direct code analysis, static inspection, adversarial stress testing, and test suite execution were conducted across all relevant files:

### A. Codebase Files & Implementations Inspected
1. `argus/collectors/graphql.py` (Lines 1–1798):
   - **Architecture & Interfaces**:
     - `GraphQLSecurityCollector` inherits from `BaseCollector` (`argus/collectors/base.py`) and implements `collect(self, mission) -> List[Evidence]` (Line 1416) and `execute(self, mission) -> List[Evidence]` (Line 1791).
     - Exported alias: `GraphQLCollector = GraphQLSecurityCollector` (Line 1797).
   - **Data Models & Enums**:
     - `GraphQLSeverity` (`critical`, `high`, `medium`, `low`, `info`), `GraphQLTechnique` (10 techniques), `GraphQLMutationStrategy` (7 strategies including `standard`).
     - `GraphQLSecurityResult` dataclass with `technique`, `mutation_strategy`, `severity`, `confidence`, `payload`, `matched_signature`, `evidence_snippet`, `endpoint_url`, `status_code`, `delay_delta`, `template_id`, and `vulnerability_type`.
   - **Polymorphic Execution & Resilience**:
     - `_execute_request()` (Lines 1045–1175): Safely handles custom mock clients (with `client.get`, `client.post`, `client.request`, or callable) supporting both `(mission, url, ...)` and `(url, ...)` call signatures via `TypeError` fallbacks.
     - Production fallback uses `with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:`.
     - All network calls are wrapped in `try...except Exception as e:` returning `None` with debug logging, preventing unhandled socket/connection crashes.
   - **Response Parsing & Normalization**:
     - `_parse_response_body()` (Lines 547–573): Handles `response.body`, `response.text`, and `response.content` (with UTF-8 decode error replacement), followed by `response.json()` or `json.loads(raw_text)` with graceful exception handling.
   - **Candidate Endpoint Discovery**:
     - `_discover_candidate_endpoints()` (Lines 1177–1238): Safely parses `mission.endpoints`, `mission.live_hosts`, and `mission.target`. Checks URL schemes, synthesizes paths against `DEFAULT_GRAPHQL_PATHS`, and deduplicates URLs with a `seen_urls` set.
   - **Quadruple State Updates**:
     - `_create_evidence_and_update_state()` (Lines 1273–1414):
       1. Emits `Evidence(category="graphql_security", status="CONFIRMED", ...)` and updates `mission.evidence.add(ev)` / `append(ev)`.
       2. Appends finding record to `mission.vulnerabilities`.
       3. Expands `attack_surface_graph` with `live_host`, `endpoint`, and `vulnerability` `Node`s, connected via `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
       4. Publishes to `ControlledMission.publish_finding(ev.evidence_id, ev)` when running under wrapper.
   - **False Positive Controls**:
     - Hardened server signatures: `HARDENED_INTROSPECTION_SIGNATURES`, `DEPTH_LIMIT_DEFENSE_SIGNATURES`, `FRAGMENT_CYCLE_DEFENSE_SIGNATURES`, `BATCH_DEFENSE_SIGNATURES`.
     - Baseline subtraction: Benign baseline probe `{ __typename }` is compared against probe responses (Lines 590–593, 700–703, 745–748, 958–961).
     - Echo suppression: Argument injection payloads are stripped from the response body prior to regex matching (Lines 964–966) to prevent false positives from benign input reflection.

2. `argus/collectors/__init__.py` (Lines 56–65, 119–127):
   - Correctly exports `GraphQLSecurityCollector`, `GraphQLCollector`, `GraphQLPayloadGenerator`, `GraphQLSecurityAnalyzer`, `GraphQLSecurityResult`, `GraphQLSeverity`, `GraphQLTechnique`, `GraphQLMutationStrategy`.

3. `argus/runtime/registry.py` (Lines 506–536):
   - Registers tool `graphql_security` with priority 95, tasks, capabilities, and 9 aliases.

4. `argus/runtime/plugins.py` (Lines 68–76):
   - Instantiates `GraphQLSecurityCollector` for `graphql_security`, `graphql_vuln`, `graphql_vulnerability`, `graphql_introspection`, `graphql_collector` before checking fallback `GraphQLPlugin`.

5. `argus/planning/task_generator.py` (Lines 182–194, 474–484):
   - Adds `_RECON_TEMPLATES["graphql_security"]` dependent on `["Discover API Endpoints"]` and maps coverage gap areas.

6. `argus/graph/attack_surface.py` (Lines 817–870):
   - Section 18 builds `endpoint` and `vulnerability` graph nodes and `HAS_VULNERABILITY` edges for GraphQL evidence.

7. `tests/collectors/test_graphql.py` (Lines 1–651):
   - 40 comprehensive unit and integration tests across 7 test suites testing all vulnerability vectors, 6 mutation strategies, false positive suppression, state updates, DAG wiring, and CWE/CVSS resolution.

### B. Test Verification Results
- `python3 -m pytest tests/collectors/test_graphql.py -v`:
  - **40 passed**, 55 warnings in 0.39s.
- `python3 -m pytest tests/ --ignore=tests/workspace -x -q`:
  - **1,392 passed**, 27,060 warnings in 44.45s.
  - Zero failures, zero regressions across the entire platform.

---

## 2. Logic Chain

1. **Adherence to BaseCollector & Collector Architecture**:
   - Observation: `GraphQLSecurityCollector` extends `BaseCollector`, implements `collect(mission)` returning `List[Evidence]`, and provides `execute(mission)` for adapter compatibility.
   - Inference: The collector conforms to the standard ARGUS collector lifecycle and can be seamlessly invoked by both the pipeline task engine and the plugin adapter.

2. **Polymorphic Execution & Robust Error Handling**:
   - Observation: `_execute_request()` handles varying mock signatures, callable mocks, and `AuthenticatedHttpClient` fallback, while catching all network/HTTP exceptions inside `try...except`.
   - Adversarial Test: Verified that passing an `ExplodingClient` raising `ConnectionResetError` or `RuntimeError` terminates cleanly, returning empty evidence without unhandled exceptions.
   - Inference: The transport layer is highly resilient against network timeouts, connection drops, and testing environments.

3. **Robustness Against Malformed/Adversarial Inputs**:
   - Observation: `_parse_response_body()` handles corrupt non-JSON bodies, binary byte sequences, null data, missing fields, and non-dict JSON structures without throwing `TypeError` or `AttributeError`.
   - Adversarial Test: Verified corrupt inputs (`{"data": "string"}`, `{"data": {"__schema": 123}}`, non-HTTP candidate endpoints) execute without exceptions.
   - Inference: The analyzer and collector degrade gracefully when interacting with non-standard, malformed, or hostile endpoints.

4. **False Positive Suppression Integrity**:
   - Observation: The analyzer tests against baseline queries (`{ __typename }`), cleans reflected probe strings before scanning for SQLi/CmdI errors, and matches defensive error responses (`GraphQL introspection is disabled`, `Query depth exceeds maximum`, `Batch requests are not allowed`).
   - Inference: Properly hardened endpoints will not produce false positive alerts.

5. **Absence of Integrity Violations**:
   - Observation: No hardcoded test responses, mock URL short-circuits, fake assertion bypasses, or dummy logic exist in `argus/collectors/graphql.py`. All analysis is performed using live AST/regex signature matching and structural data inspection.
   - Inference: The implementation is genuine, sound, and fully compliant with project standards.

---

## 3. Caveats

- **WebSocket / Subscription Testing**: GraphQL subscriptions over WebSockets (`graphql-ws`) are intentionally out of scope for Sprint 17 and are designated for Sprint 18 (WebSocket Security).
- **Safety Thresholds**: Maximum recursion depth is limited to 15 and alias multiplexing is limited to 20 to prevent service degradation against production targets.

---

## 4. Conclusion

**Verdict: APPROVE**

The Sprint 17 GraphQL Security Detection Module (`GraphQLSecurityCollector`, `GraphQLPayloadGenerator`, `GraphQLSecurityAnalyzer`, and pipeline integrations) is architecturally sound, thoroughly tested, highly robust against malformed or unexpected responses, and enforces rigorous false-positive suppression. All 1,392 workspace tests pass cleanly with zero regressions.

---

## 5. Verification Method

To independently verify this assessment:

1. **Run GraphQL Unit & Integration Suite**:
   ```bash
   python3 -m pytest tests/collectors/test_graphql.py -v
   ```
   *Expected*: `40 passed in < 1.0s`.

2. **Run Full Platform Regression Suite**:
   ```bash
   python3 -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   *Expected*: `1392 passed in ~45s`.

3. **Inspect Implementation & Exports**:
   ```bash
   python3 -c 'from argus.collectors import GraphQLSecurityCollector, GraphQLCollector; print(GraphQLSecurityCollector)'
   ```
   *Expected*: `<class 'argus.collectors.graphql.GraphQLSecurityCollector'>`.
