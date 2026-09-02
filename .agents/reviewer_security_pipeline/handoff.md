# Reviewer 2: GraphQL Security & Pipeline Review Handoff Report

**Reviewer**: Reviewer 2 (GraphQL Security & Pipeline Reviewer)  
**Roles**: reviewer, critic  
**Target Milestone**: Sprint 17 (GraphQL Security Detection Module)  
**Date**: 2026-08-31  
**Verdict**: **APPROVE**

---

## 1. Observation

A comprehensive code, architecture, pipeline, and adversarial review was conducted across all Sprint 17 deliverables:

### Reviewed Artifacts & Codebase State
1. **Collector Architecture (`argus/collectors/graphql.py`)**:
   - `GraphQLSeverity` (`critical`, `high`, `medium`, `low`, `info`), `GraphQLTechnique`, and `GraphQLMutationStrategy` enums strictly typed.
   - `GraphQLSecurityResult` dataclass with full metadata tracking (`technique`, `mutation_strategy`, `severity`, `confidence`, `payload`, `matched_signature`, `evidence_snippet`, `endpoint_url`, `status_code`, `delay_delta`, `baseline_elapsed`, `injected_elapsed`, `is_valid_finding`, `template_id`).
   - Signature Catalogs & Heuristics:
     * `INTROSPECTION_SIGNATURES`: `types_list`, `schema_root`, `query_type`, `mutation_type`, `type_info`.
     * `HARDENED_INTROSPECTION_SIGNATURES`: Detects disabled introspection ("introspection is disabled", "cannot query field '__schema'", "introspection queries are not allowed").
     * `FIELD_SUGGESTION_SIGNATURES`: Regex detecting "Did you mean ...?", "perhaps you meant", "suggestions: [".
     * `DEPTH_LIMIT_DEFENSE_SIGNATURES`: Detects enforced depth and complexity limits ("query depth exceeds", "max query depth exceeded", "complexity score exceeded").
     * `FRAGMENT_CYCLE_DEFENSE_SIGNATURES`: Detects spec-compliant cycle rejections ("cannot spread fragment within itself", "fragment cycle").
     * `BATCH_DEFENSE_SIGNATURES`: Detects disabled batching ("batching is disabled", "batch requests are not allowed").
     * `SQL_ERROR_SIGNATURES`: Engine-specific error matchers for PostgreSQL, MySQL, SQLite, Oracle, MSSQL, Generic SQL.
     * `COMMAND_OUTPUT_SIGNATURES`: `passwd_entry`, `id_command`, `windows_system`, `command_error`.
     * `SENSITIVE_FIELD_NAMES`: 13 high-value authorization probe targets (`admin`, `system`, `debug`, `users`, `passwordHash`, `password`, `token`, `secret`, `apiKey`, `databaseUrl`, `privateKey`, `systemConfig`, `credentials`).

2. **Probe Generation (`GraphQLPayloadGenerator`)**:
   - Benign baseline: `{ __typename }`.
   - Full & root introspection: `__schema { queryType mutationType subscriptionType types { ... } }`.
   - Targeted single-type introspection: `__type(name: "Query") { ... }`.
   - Field suggestions: 6 misspelled field probes (`usr`, `passwrd`, `adm`, `systm`, `accnt`, `tkn`).
   - Query depth: dynamically nested recursive queries across depths 5, 10, 15.
   - Fragment expansion: direct circular fragment recursion (`...F1 ... fragment F1 on Query { ...F1 }`) and 2-step nested fragment cycles (`F1 -> F2 -> F1`).
   - Batching payloads: JSON array batch probes (`[{"query": ...}, {"query": ...}]`).
   - Alias multiplexing: 20 aliased fields (`a1: __typename ... a20: __typename`).
   - Field-level authorization probes: targeted queries on privileged endpoints (`admin`, `users`, `debug`, `tokens`, `systemConfig`).
   - Argument injection probes: SQLi (`' OR '1'='1--`, `' UNION SELECT ...`, `' OR 1=1 #`) and CmdI (`; id ;`, `pdf; whoami`, `127.0.0.1 | cat /etc/passwd`).

3. **Mutation & Evasion Strategies (R3)**:
   - `METHOD_SWAPPING`: Swapping POST to GET query string `?query=...` with JSON variables.
   - `CONTENT_TYPE_MANIPULATION`: Switching to `Content-Type: application/graphql` with raw query body.
   - `QUERY_OBFUSCATION`: Injecting comments (`# argus_guard\n`), commas, and whitespace.
   - `ALIAS_POLLUTION`: Keyword renaming (`_argus_schema: __schema`, `_argus_types: types`, `_argus_qt: queryType`, `_argus_mt: mutationType`, `_argus_type: __type`).
   - `VARIABLE_EXTRACTION`: Dynamic extraction of argument literals into `$variables` and operation parameter headers.
   - `DIRECTIVE_BYPASS`: Injecting `@include(if: true)` and `@skip(if: false)` on schema keywords.

4. **Security Response Analyzer (`GraphQLSecurityAnalyzer`)**:
   - Robust JSON decoding with fallback to raw regex parsing.
   - Baseline subtraction to filter out pre-existing error messages or static server banners.
   - False positive suppression via hardened defense signatures.
   - Reflection echo cancellation for injection probes to prevent false reporting of reflected inputs.
   - Tree depth measurement (`_measure_depth`) verifying recursive nesting of returned data.

5. **Pipeline Connectivity & Graph (`R4`)**:
   - `argus/collectors/__init__.py`: Properly exported collector and supporting classes.
   - `argus/runtime/registry.py`: `graphql_security` registered with priority 95, capability `graphql_security_detector`, required inputs `["endpoints"]`, produced outputs `["vulnerabilities", "observations", "evidence"]`, and 9 aliases.
   - `argus/runtime/plugins.py`: Specialist fallback instantiation mapped in `PluginExecutorAdapter._instantiate_specialist_fallback`.
   - `argus/planning/task_generator.py`: `_RECON_TEMPLATES["graphql_security"]` wired with dependency `["Discover API Endpoints"]`, required inputs `["endpoints"]`, gap resolution logic, and `from_gaps` integration.
   - `argus/graph/attack_surface.py`: Section 18 builds `endpoint` and `vulnerability` nodes with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges linked to `live_host`.
   - `argus/reporting/cvss.py`: CWE database mapped for `graphql_security` (CWE-200), `graphql_dos` (CWE-400), `graphql_depth_dos` (CWE-400), `graphql_batching` (CWE-799), `graphql_batching_bypass` (CWE-799), `graphql_access_control` (CWE-285).

6. **Test Verification Results**:
   - `python3 -m pytest tests/collectors/test_graphql.py -v`: **40 passed** in 0.40s.
   - `python3 -m pytest tests/planning/test_task_generator.py -v`: **18 passed** in 0.43s.
   - `python3 -m pytest tests/graph/test_attack_surface_builder.py -v`: **10 passed** in 0.23s.
   - Full regression suite (`python3 -m pytest tests/ --ignore=tests/workspace -x -q`): **1,392 passed** (1,352 baseline + 40 new, 0 regressions).

---

## 2. Logic Chain

1. **Vulnerability Detection Completeness (R2.1 - R2.4)**:
   - *Introspection / Leakage (R2.1)*: `GraphQLPayloadGenerator.build_introspection_query()` and `GraphQLSecurityAnalyzer.analyze_introspection()` verify both full `__schema` and single `__type` queries. The presence of field suggestions is checked via regex against misspellings.
   - *Query Depth / Fragment Recursion DoS (R2.2)*: `GraphQLSecurityAnalyzer.analyze_query_depth()` computes recursive depth on the parsed JSON response, confirming whether depth limits (5, 10, 15) are enforced. Circular fragments test server resilience against stack overflow / timeout without false positives on spec-compliant errors.
   - *Batching / Alias Multiplexing (R2.3)*: Evaluates both JSON array batch execution and 20-alias batching, confirming bypass of per-request rate-limiting.
   - *Field Access & Injections (R2.4)*: Evaluates non-null data returns on sensitive administrative fields (BOPLA) and validates DB/OS error signatures for SQLi/CmdI while suppressing naive reflection.
   
2. **Mutation Strategies Completeness (R3)**:
   - All 6 mutation strategies (`METHOD_SWAPPING`, `CONTENT_TYPE_MANIPULATION`, `QUERY_OBFUSCATION`, `ALIAS_POLLUTION`, `VARIABLE_EXTRACTION`, `DIRECTIVE_BYPASS`) are implemented in `GraphQLPayloadGenerator.mutate_payload()` and covered by individual unit tests in `TestGraphQLMutationStrategies`.

3. **Pipeline Connectivity & Graph Verification (R4)**:
   - Discovered endpoints flow into `TaskGenerator` after `Discover API Endpoints`.
   - Tool registry maps `graphql_security` and all its aliases with appropriate capabilities.
   - Confirmed evidence creates `endpoint`, `live_host`, and `vulnerability` nodes, interconnected via `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
   - CWE and CVSS scoring properly map to CWE-200, CWE-400, CWE-799, and CWE-285.

4. **Integrity & Quality Assessment**:
   - Zero hardcoded test results in source code.
   - No dummy/facade implementations; full probe execution, parsing, and graph creation logic is present.
   - No shortcuts or external delegators.

---

## 3. Caveats & Adversarial Analysis

- **Assumption 1 (DoS Safety Caps)**:
  - *Challenged*: Depth probing is capped at depth 15 and alias multiplexing is capped at 20 aliases.
  - *Risk / Blast Radius*: Deep recursive queries could crash production targets if unbounded.
  - *Assessment*: Capping at 15 is a deliberate and sound safety control for defensive security tooling while still providing conclusive proof of missing depth limits.
- **Assumption 2 (WebSocket & Subscriptions)**:
  - *Challenged*: WebSocket GraphQL subscriptions (`graphql-ws`) are not probed in this collector.
  - *Assessment*: Intentionally scoped for Sprint 18 (WebSocket Security) per the architectural roadmap.
- **Assumption 3 (WAF & Proxy Behavior)**:
  - *Challenged*: Proxies might reject `application/graphql` or GET parameters with large payloads.
  - *Assessment*: The collector loops through multiple mutation strategies and captures standard POST JSON as baseline fallback.

---

## 4. Conclusion

The GraphQL Security Detection Module in Sprint 17 satisfies all requirements (R1, R2.1–R2.4, R3, R4, R5) and acceptance criteria:
- All 6 mutation strategies are fully implemented and verified.
- Pipeline integration in `registry.py`, `plugins.py`, `task_generator.py`, `attack_surface.py`, and `cvss.py` is sound.
- AttackSurfaceGraph node and edge generation is verified.
- All 40 unit and integration tests pass cleanly.
- Full workspace test suite passes with 1,392 tests and 0 regressions.
- No integrity violations detected.

**Final Verdict**: **APPROVE**

---

## 5. Verification Method

To independently reproduce and verify this review:

1. **Run GraphQL Collector Unit & Integration Tests**:
   ```bash
   python3 -m pytest tests/collectors/test_graphql.py -v
   ```
   Expected result: `40 passed`

2. **Run TaskGenerator DAG Tests**:
   ```bash
   python3 -m pytest tests/planning/test_task_generator.py -v
   ```
   Expected result: `18 passed`

3. **Run Attack Surface Builder Tests**:
   ```bash
   python3 -m pytest tests/graph/test_attack_surface_builder.py -v
   ```
   Expected result: `10 passed`

4. **Run Full Workspace Regression Suite**:
   ```bash
   python3 -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   Expected result: `1392 passed` (or all passing, 0 errors).
