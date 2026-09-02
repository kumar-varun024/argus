# GraphQL Security Specification & Detection Blueprint Report

## 1. Observation

### Codebase & Architectural Baseline
- **Existing Passing Test Baseline**: `1,352 passed, 27003 warnings in 53.20s` (verified via `python3 -m pytest tests/ --ignore=tests/workspace -q`).
- **Collector Architecture**:
  - `BaseCollector` (`argus/collectors/base.py:4-10`): Abstract base class defining `collect(self, mission)`.
  - Modern collectors (`argus/collectors/deserialization.py`, `argus/collectors/xml_parser.py`, `argus/collectors/ssrf.py`):
    - Implement `collect(self, mission)` and `execute(self, mission)`.
    - Accept optional `http_client: Optional[AuthenticatedHttpClient] = None` in constructor for mock injection.
    - Export generator classes (`GraphQLPayloadGenerator`), analyzer classes (`GraphQLAnalyzer`), and result dataclasses (`GraphQLValidationResult`).
    - Emit `Evidence(category="graphql_security", status="CONFIRMED", severity=..., confidence=0.90..0.98)` appended to `mission.evidence` and `mission.vulnerabilities`.
    - Expand `AttackSurfaceGraph` nodes (`live_host`, `endpoint`, `vulnerability`) linked with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
- **Pipeline & DAG Integration**:
  - `argus/planning/task_generator.py:13-182`: `_RECON_TEMPLATES` registers tasks with `tool_id`, `category`, `dependencies: ["Discover API Endpoints"]`, `required_inputs: ["endpoints"]`, and `expected_outputs: ["vulnerabilities", "observations", "evidence"]`.
  - `argus/runtime/plugins.py:65-130`: `PluginExecutorAdapter._instantiate_specialist_fallback` provides dynamic specialist instantiation when `graphql` is invoked.
  - `argus/collectors/__init__.py`: Exports all collectors and supporting data structures.

---

## 2. Logic Chain

1. **GraphQL Attack Surface Definition**:
   GraphQL endpoints consolidate multi-resource querying into single endpoints (e.g. `/graphql`). Security boundaries move from URL routing to schema validation, field resolvers, AST query execution, and query complexity engines.
2. **Detection Categorization**:
   Based on the GraphQL Specification (October 2021), OWASP API Security Top 10 (API4:2023, API1:2023, API3:2023, API8:2023), and GraphQL Threat Matrices, testing requires probing four distinct vulnerability pillars:
   - **Pillar 1: Introspection & Schema Leakage**: Full schema recovery (`__schema`), single-type introspection (`__type`), and field suggestion leakage (`Did you mean ...?` via Levenshtein matching).
   - **Pillar 2: Query Depth & Complexity DoS**: Self-referencing nested queries (depth 5–25) and recursive fragment expansion (`fragment F on User { ...F }` / nested fragment amplification) to identify missing query complexity and depth analyzers.
   - **Pillar 3: Batching / Query Multiplexing**: Array of JSON query objects (`[{"query": "..."}, ...]`) and Alias multiplexing (`query { a1: field, a2: field, ... }`) enabling brute-force amplification and rate limit bypass.
   - **Pillar 4: Field-Level Access Control & Injection**: Probing sensitive/privileged fields (`admin`, `debug`, `users`, `passwordHash`) and testing SQLi/Command injection patterns in GraphQL argument values.
3. **Bypass & Mutation Defense-in-Depth**:
   WAFs and API gateways often apply naive pattern matching against POST JSON payloads. A complete validation engine requires at least 6 mutation strategies:
   - HTTP Method Swapping (POST $\leftrightarrow$ GET $\leftrightarrow$ PUT $\leftrightarrow$ POST urlencoded)
   - Content-Type Manipulation (`application/graphql`, `application/json`, `application/x-www-form-urlencoded`, `text/plain`, `multipart/form-data`)
   - Lexical Obfuscation (Inline comments `# ...\n`, comma delimiters `,`, newline splits, unicode whitespace)
   - Alias Pollution (`query { sec_schema: __schema { ... } }`)
   - Operation Name & Variable Extraction (`operationName: "ValidOp"`, extracting payload into `$variables`)
   - Directive Fuzzing (`@skip(if: false)`, `@include(if: true)`)
4. **False Positive & DoS Safety Controls**:
   - Strictly bound depth tests (depth $\le 15$) and alias counts ($\le 20$) with 3–5s timeouts.
   - Differentiate hardened server responses (e.g. 400 Bad Request with `max depth exceeded` or `introspection disabled`) from vulnerable execution (200 OK with data).
   - Validate JSON envelope (`data` or `errors` structure) and verify specific signature matches.

---

## 3. Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | R1: Discovery | Path & Endpoint Heuristics | Probe common GraphQL endpoint paths and passive URL clues from mission endpoints / JS bundles | URLs (`/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, `/gql`, `/graphql/console`, `/graphiql`, `/playground`) | Detected `GraphQLEndpoint` candidate with method, URL, and confidence | 404 Not Found or non-GraphQL response discarded | Spec Analysis & `argus/plugins/graphql/discovery.py` |
| 2 | R1: Discovery | Universal Injection Channels | Support 4 HTTP transport channels: POST JSON, POST raw `application/graphql`, GET `?query=`, and POST `application/x-www-form-urlencoded` | Query string, Variables dict, Operation Name, Target URL | `HttpResponse` with GraphQL response envelope | Rejection handled gracefully; fallback to alternative transport | RFC GraphQL over HTTP Draft & W3C Specs |
| 3 | R2.1: Introspection | Full Schema Introspection | Probe `__schema` for complete type, field, argument, directive, and mutation catalog | `query IntrospectionQuery { __schema { types { name kind fields { name } } } }` | Full schema dictionary in `data.__schema.types` | Hardened servers return `GraphQL introspection is disabled` | GraphQL October 2021 Spec § 4.1 |
| 4 | R2.1: Introspection | Targeted Root & Type Introspection | Probe specific types (`__schema { queryType { name } }` or `__type(name: "Query")`) when full introspection is blocked | `query { __type(name: "Query") { name fields { name } } }` | Type metadata in `data.__type` | Disabled introspection returns error in `errors` | OWASP GraphQL Cheat Sheet |
| 5 | R2.1: Introspection | Field Suggestion Leakage | Probe non-existent root fields (e.g. `query { usr }`, `query { adm }`) to detect Levenshtein suggestions | `query { passwrd }`, `query { systm }`, `query { usr }` | Error message containing `Did you mean "..."?` revealing hidden fields | Disabled suggestions return generic `Cannot query field` without suggestions | Clairvoyance / GraphQL Spec § 5.3.1 |
| 6 | R2.2: Complexity DoS | Circular Nested Query Probing | Generate calibrated recursive queries (depth 5, 10, 15) across self-referencing entities (e.g., `user -> friends -> user`) | `query { user { friends { friends { friends { id } } } } }` | Vulnerable: 200 OK with deeply nested `data`. Protected: 400 Bad Request with `max depth exceeded` | Depth limit error suppresses vulnerability finding (FP control) | GraphQL DoS Advisory / CWE-400 |
| 7 | R2.2: Complexity DoS | Recursive Fragment Expansion | Probe circular fragment references and nested fragment amplification chains | `query { ...F1 } fragment F1 on Query { ...F1 }` or exponential fragment chain | Clean validation error = Secure. Crash/Hang/500/504 = Vulnerable | Spec validation violation (Spec § 5.5.2.2) | GraphQL Spec § 5.5.2.2 / CWE-674 |
| 8 | R2.3: Batching | HTTP Array Batching | Send JSON array containing multiple queries in a single HTTP request | `[{"query": "query { __typename }"}, {"query": "query { __typename }"}]` | Vulnerable: JSON array of response objects `[{"data": ...}, {"data": ...}]` | Protected: 400 Bad Request or single object response | Apollo Server / GraphQL Yoga Batching Specs |
| 9 | R2.3: Batching | Alias Multiplexing | Send single query containing 10–20 aliased operations to bypass per-request rate limits | `query { a1: __typename a2: __typename ... a20: __typename }` | Vulnerable: `data` object with all aliases resolved (`data.a1`, `data.a2`...) | Protected: Query complexity error / alias count limit | OWASP API4:2023 / GraphQL Batching Attacks |
| 10 | R2.4: Access Control | Privileged Field Discovery | Probe sensitive/administrative fields on Query/Mutation roots (`admin`, `system`, `debug`, `users`, `passwordHash`, `token`, `secret`) | `query { admin { id username } }`, `query { users { id passwordHash } }` | Non-null sensitive data in `data` without admin privileges | 403 Forbidden / `Unauthorized` with null data is marked clean | OWASP API1:2023 (BOLA) & API3:2023 (BOPLA) |
| 11 | R2.4: Injection | GraphQL Argument SQL Injection | Inject classic and time-based SQLi probes into string and integer field arguments | `user(id: "1' OR '1'='1--")`, `search(q: "1' AND SLEEP(3)--")` | SQL error in `errors` array, data leakage, or measurable response delay $\ge 2.5s$ | Proper parameterization returns clean empty or typed validation error | CWE-89 / OWASP Injection |
| 12 | R2.4: Injection | GraphQL Argument Command Injection | Inject OS command injection delimiters into file/system field arguments | `exportReport(format: "pdf; id")`, `ping(host: "127.0.0.1; whoami")` | Command output reflection (`uid=`, `root:`) or syntax error | Strict input validation rejects non-matching characters | CWE-78 / OS Command Injection |
| 13 | R3: Bypass | HTTP Method Swapping | Mutate probe transport from POST to GET (query string), PUT, or POST form urlencoded | `GET /graphql?query=...` or `POST (urlencoded)` | Successful response bypassing POST-only WAF inspection | 405 Method Not Allowed | GraphQL HTTP Spec & WAF Bypass Techniques |
| 14 | R3: Bypass | Content-Type Manipulation | Mutate header to `application/graphql`, `application/x-www-form-urlencoded`, `text/plain`, `multipart/form-data` | Raw query in body with `Content-Type: application/graphql` | Server executes query bypassing JSON-only inspection | 415 Unsupported Media Type | GraphQL Over HTTP RFC |
| 15 | R3: Bypass | Lexical / Comment Obfuscation | Inject `# comments\n`, comma delimiters `,`, and newline splits within query AST | `query#comment\n{\n#__schema\n__schema{\ntypes{\nname}}}` | Query parsed identically to standard query according to lexical spec | Tokenizer error if server parser is non-conformant | GraphQL October 2021 Spec § 2.1 |
| 16 | R3: Bypass | Alias Pollution & Renaming | Wrap sensitive fields in custom alias identifiers to evade static string matches | `query { sec_schema: __schema { type_catalog: types { name } } }` | Response keyed by aliases | WAF string signatures evaded | WAF Evasion Research |
| 17 | R3: Bypass | Operation Name & Variable Extraction | Set benign `operationName` and extract payloads into `$variables` JSON map | `query GetProfile($id: String!) { user(id: $id) { id } }` + `variables: {"id": "1' OR '1'='1"}` | Query body appears benign; payload executes via variables | Payload separated from query text | GraphQL Variables Specification |
| 18 | R3: Bypass | Directive Fuzzing (@skip / @include) | Wrap target fields with standard directives `@include(if: true)` or `@skip(if: false)` | `query { __schema @include(if: true) { types { name } } }` | Directive evaluated dynamically during execution | Static AST matchers miss field name | GraphQL Spec § 3.2.1 |
| 19 | R4: Pipeline | AttackSurfaceGraph Expansion | Generate graph nodes (`live_host`, `endpoint`, `vulnerability`) with `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges | Vulnerability result + target URL | KnowledgeGraph with connected attack surface nodes and edges | Graceful fallback if graph is missing from mission | Argus Graph Architecture |
| 20 | R4: Pipeline | Tool Registry & DAG Scheduling | Register collector in `argus/collectors/__init__.py`, `task_generator.py`, and `plugins.py` | DAG Task execution trigger | Scheduled after `Discover API Endpoints` | Dependency resolved topologically | Argus Planning Engine |

---

## 4. Edge Cases

| # | Feature | Input | Observed / Expected Behavior |
|---|---------|-------|-------------------------------|
| 1 | Introspection | Server returns HTTP 200 with `{"data": {"__schema": null}, "errors": [{"message": "Introspection disabled"}]}` | **Handled as Hardened/Clean**: Parser checks for non-null `types` array with length $> 3$ or valid `queryType`. Does NOT generate false positive evidence. |
| 2 | Field Suggestions | Server returns `Cannot query field "usr" on type "Query"` without `Did you mean ...?` | **Handled as Hardened/Clean**: Field suggestion analyzer requires regex match on `Did you mean` / `Suggestions:`. Normal missing field error is ignored. |
| 3 | Query Depth DoS | Server rejects depth-15 query with HTTP 400 and `{"errors": [{"message": "Query depth of 15 exceeds maximum depth 10"}]}` | **Handled as Secure Defense**: Collector detects depth enforcement and records FP suppression (no vulnerability emitted). |
| 4 | Query Depth DoS | Server executes depth-15 query returning HTTP 200 with deeply nested data objects | **Handled as Vulnerable**: Unbounded query complexity DoS confirmed; emits `Evidence(category="graphql_security", subcategory="depth_dos", severity="medium")`. |
| 5 | Fragment Recursion | Server rejects circular fragment `...F1` with HTTP 400 `Cannot spread fragment within itself` | **Handled as Spec-Compliant**: Complies with GraphQL Spec § 5.5.2.2; no vulnerability emitted. |
| 6 | Fragment Recursion | Server hangs (> 4.0s) or crashes with HTTP 500/502/504 on circular fragment | **Handled as Vulnerable**: Emits DoS evidence due to parser crash / infinite recursion handling failure. |
| 7 | Batch Queries | Server responds to `[{"query": "..."}, {"query": "..."}]` with HTTP 400 `Batch queries are not supported` | **Handled as Secure**: Batching disabled; no evidence emitted. |
| 8 | Batch Queries | Server executes query array returning `[{"data": ...}, {"data": ...}]` | **Handled as Vulnerable**: Query batching multiplexing confirmed; emits `Evidence(category="graphql_security", subcategory="batching", severity="medium")`. |
| 9 | Alias Multiplexing | Server executes query with 20 aliases returning `{"data": {"a1": ..., "a20": ...}}` | **Handled as Vulnerable**: Alias multiplexing confirmed; emits `Evidence(category="graphql_security", subcategory="alias_multiplexing", severity="medium")`. |
| 10 | Field Access Control | Server returns `{"data": {"admin": null}, "errors": [{"message": "Unauthorized"}]}` | **Handled as Secure**: Null field with authorization error is rejected as false positive. Only non-null sensitive data triggers finding. |
| 11 | Injection in Args | Server returns `{"errors": [{"message": "Variable \"$id\" of type \"Int!\" must be provided"}]}` on type violation | **Handled as Type-Safe**: Strong typing validation rejection is marked clean (no SQLi/CmdI finding). |
| 12 | Injection in Args | Server returns SQL syntax error in GraphQL `errors` (e.g. `syntax error at or near "'"`) | **Handled as Vulnerable**: Confirmed SQL injection via GraphQL argument; emits `Evidence(category="graphql_security", subcategory="injection_sqli", severity="high")`. |
| 13 | Transport Handling | Endpoint requires `Content-Type: application/graphql` and rejects `application/json` with 415 | **Handled via Mutation**: Collector automatically retries using Content-Type mutation strategy and records finding with transport provenance. |
| 14 | Obfuscation | WAF blocks `"query { __schema }"` but allows `query#comment\n{\n__schema{\ntypes{\nname}}}` | **Handled via Mutation**: Obfuscation strategy successfully extracts schema, confirming WAF bypass vulnerability. |

---

## 5. Technical Blueprint & Implementation Plan

### A. Module Structure
```
argus/collectors/graphql.py
├── Enums:
│   ├── GraphQLSeverity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
│   ├── GraphQLTechnique (INTROSPECTION, FIELD_SUGGESTIONS, QUERY_DEPTH, FRAGMENT_RECURSION, BATCHING_ARRAY, BATCHING_ALIAS, FIELD_ACCESS_CONTROL, INJECTION_SQLI, INJECTION_CMDI)
│   ├── GraphQLMutationStrategy (STANDARD, METHOD_SWAPPING, CONTENT_TYPE_MANIPULATION, LEXICAL_OBFUSCATION, ALIAS_POLLUTION, VARIABLE_EXTRACTION, DIRECTIVE_BYPASS)
├── Dataclasses:
│   └── GraphQLValidationResult (technique, mutation_strategy, severity, confidence, payload, matched_signature, evidence_snippet, status_code, delay_delta, is_valid_finding, error_message)
├── Signature Catalogs & Heuristics:
│   ├── INTROSPECTION_SIGNATURES & QUERIES
│   ├── FIELD_SUGGESTION_SIGNATURES (Regex patterns for Did you mean / Levenshtein)
│   ├── DEPTH_LIMIT_ERROR_SIGNATURES (Regex patterns for max depth / complexity exceeded)
│   ├── SQL_ERROR_SIGNATURES (PostgreSQL, MySQL, SQLite, Oracle, MSSQL)
│   └── SENSITIVE_FIELD_NAMES (admin, system, debug, private, internal, secret, token, users, passwordHash)
├── Generator:
│   └── GraphQLPayloadGenerator (build_introspection_query, build_depth_query, build_fragment_query, build_batch_array, build_alias_query, build_field_probe, build_injection_query, mutate_payload)
├── Analyzer:
│   └── GraphQLAnalyzer (analyze_introspection, analyze_field_suggestions, analyze_query_depth, analyze_batching, analyze_alias_multiplexing, analyze_field_access, analyze_injection)
├── Collector:
│   └── GraphQLCollector(BaseCollector)
│       ├── Constructor: __init__(self, http_client=None)
│       ├── Entrypoints: collect(self, mission), execute(self, mission)
│       ├── Internal: _discover_candidate_endpoints(mission), _execute_request(...), _run_probe_suite(...)
│       └── Aliases: GraphQLSecurityCollector, GraphQLValidationCollector
```

### B. Severity & Evidence Mapping Matrix
| Vulnerability Technique | Default Severity | CVSS v3.1 Estimate | Confidence | CWE | Evidence Category |
|-------------------------|------------------|-------------------|------------|-----|-------------------|
| Introspection Enabled | MEDIUM | 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) | 0.95 | CWE-200 / CWE-16 | `graphql_security` |
| Field Suggestion Leakage | LOW / MEDIUM | 4.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) | 0.92 | CWE-200 | `graphql_security` |
| Unbounded Query Depth DoS | MEDIUM / HIGH | 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) | 0.90 | CWE-400 / CWE-674 | `graphql_security` |
| Fragment Recursion Crash | MEDIUM / HIGH | 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) | 0.90 | CWE-674 | `graphql_security` |
| HTTP Query Array Batching | MEDIUM | 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) | 0.92 | CWE-799 / CWE-307 | `graphql_security` |
| Alias Multiplexing Abuse | MEDIUM | 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) | 0.92 | CWE-799 | `graphql_security` |
| Broken Field-Level Access (BOPLA) | HIGH / CRITICAL | 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N) | 0.95 | CWE-285 / CWE-200 | `graphql_security` |
| GraphQL Argument SQL Injection | HIGH / CRITICAL | 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) | 0.98 | CWE-89 | `graphql_security` |
| GraphQL Argument OS Command Inj. | CRITICAL | 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) | 0.98 | CWE-78 | `graphql_security` |

### C. 6 Mutation & Bypass Strategies Detail
1. **`METHOD_SWAPPING`**:
   - Converts standard POST to `GET /graphql?query=<URL_ENCODED_QUERY>` or `POST` with `Content-Type: application/x-www-form-urlencoded`.
2. **`CONTENT_TYPE_MANIPULATION`**:
   - Sends query directly as raw string with `Content-Type: application/graphql` or `text/plain`.
3. **`LEXICAL_OBFUSCATION`**:
   - Injects comments `# probe comment\n`, swaps spaces with commas `,`, and introduces multi-line carriage returns.
4. **`ALIAS_POLLUTION`**:
   - Transforms `__schema` to `query { _argus_schema: __schema { _argus_types: types { name } } }`.
5. **`VARIABLE_EXTRACTION`**:
   - Extracts injection literals out of query string into JSON `variables: {"arg": "PAYLOAD"}` with matching `$arg` declaration in query.
6. **`DIRECTIVE_BYPASS`**:
   - Wraps fields in conditional directives: `__schema @include(if: true)` or `types @skip(if: false)`.

---

## 6. Caveats
- **Live DoS Impact Guardrail**: Query depth probes must be calibrated with an upper bound (maximum depth 15, maximum 20 aliases) to prevent accidental denial of service against live authorized target systems.
- **WebSocket / Subscription Testing**: Real-time subscriptions via WebSockets (`graphql-ws`, `subscriptions-transport-ws`) are reserved for Sprint 18 (WebSocket Security) and out of scope for Sprint 17.
- **Mock Server Fidelity**: Unit and integration tests in `tests/collectors/test_graphql.py` must use flexible `MockGraphQLHttpClient` or mock transports rather than binding real OS network sockets to maintain test isolation and speed.

---

## 7. Conclusion
The GraphQL Security technical specification is complete, rigorous, and fully mapped to the ARGUS architecture. Implementation requires:
1. Production collector `argus/collectors/graphql.py` providing `GraphQLCollector`, `GraphQLPayloadGenerator`, and `GraphQLAnalyzer`.
2. DAG scheduling in `argus/planning/task_generator.py` and fallback dispatch in `argus/runtime/plugins.py`.
3. Export from `argus/collectors/__init__.py`.
4. Comprehensive test suite in `tests/collectors/test_graphql.py` with 25+ unit and integration test cases validating introspection, depth DoS, batching, field authorization, injection, all 6 mutation strategies, graph node/edge creation, and false positive controls with zero regressions across the 1,352 passing tests.

---

## 8. Verification Method
- **Baseline Test Command**:
  ```bash
  python3 -m pytest tests/ --ignore=tests/workspace -q
  ```
- **New Unit & Integration Tests Command**:
  ```bash
  python3 -m pytest tests/collectors/test_graphql.py -v
  ```
- **Graph & Registry Verification**:
  - Verify `AttackSurfaceGraph` contains `HAS_VULNERABILITY` edges for confirmed GraphQL findings.
  - Verify `TaskGenerator` creates `ResearchTask` for `graphql_security` following endpoint discovery.
