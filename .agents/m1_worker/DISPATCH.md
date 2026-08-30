## 2026-08-29T16:27:26Z

Scope & Owned Files:
1. Implement `argus/collectors/sql_injection.py` containing:
   - `SQLInjectionPayloadGenerator`: base payloads for error-based, boolean-based (TRUE/FALSE pairs), time-based, and 5 distinct WAF bypass mutation strategies (Case Alternation, Comment Insertion, URL Encoding, Double URL Encoding, Whitespace Substitution).
   - `SQLInjectionAnalyzer`:
     * Error-Based Detection for 5 DBMSs (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) with strict regex matching to avoid false positives. Emits `severity="critical"`.
     * Boolean-Based Blind Differential Analysis: Compares TRUE (`' OR 1=1--`) vs FALSE (`' OR 1=2--`) against baseline, length deltas, content structure, status codes, with dynamic tolerance/noise filtering. Emits `severity="high"`.
     * Time-Based Blind Delay Measurement: Injects time-delay payloads (`SLEEP(5)`, `pg_sleep(5)`, `WAITFOR DELAY '0:0:5'`, `dbms_lock.sleep(5)`), measures latency against baseline, confirming when $T_{injected} - T_{baseline} \ge 4.0\text{s}$. Emits `severity="critical"`.
     * False Positive Rejection & Reflection Discard: Distinguishes genuine database syntax errors from application error text/headings and plain reflection.
   - `SQLInjectionCollector(BaseCollector)`:
     * Extracts target endpoints, base hosts, query parameters, POST form & JSON body fields, path segments, and HTTP headers (`Cookie`, `Referer`, `X-Forwarded-For`).
     * Uses `AuthenticatedHttpClient` with proper session/auth/cookie forwarding and timeout handling.
     * Implements both `collect(self, mission)` and `execute(self, mission)`.
     * Creates `Evidence(category="sql_injection", ...)` stored in `mission.evidence`.
     * Records finding in `mission.vulnerabilities`.
     * Updates `mission.attack_surface_graph` with `live_host`, `endpoint`, `vulnerability` nodes, and connects `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
2. Update `argus/collectors/__init__.py` to export `SQLInjectionCollector`, `SQLInjectionAnalyzer`, `SQLInjectionPayloadGenerator`.
3. Update `argus/planning/task_generator.py`:
   - Add `sql_injection` to `_RECON_TEMPLATES` (title: "Fuzz SQL Injection", category: TaskCategory.EVIDENCE_CORRELATION, dependencies: ["Discover API Endpoints"], priority: 0.81).
   - Add keyword resolution in `_resolve_template_for_gap(gap)` (e.g. "sqli", "sql injection", "sql_injection", "database injection").
   - Update `from_gaps(gaps)` to map inputs from `endpoints`.
4. Update `argus/runtime/registry.py`:
   - Register `sql_injection` in global `registry` as internal tool with safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]}.
5. Update `argus/runtime/plugins.py`:
   - Add fallback instantiation for `sql_injection` in `PluginExecutorAdapter._instantiate_specialist_fallback(plugin_id)`.
6. Update `argus/graph/attack_surface.py`:
   - Handle `category == "sql_injection"` in `AttackSurfaceGraphBuilder.build_from_evidence` to create nodes and `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges.
7. Implement Comprehensive Test Suite:
   - `tests/collectors/test_sql_injection.py`: Unit and component tests for R1-R4 (>15 tests).
   - `tests/collectors/test_sql_injection_adversarial.py`: Boundary, corner cases, false positive rejection, WAF mutations (>10 tests).
   - `tests/runtime/test_e2e_sql_injection.py`: E2E Mission loop integration test proving collector runs during mission loop and constructs graph edges (>3 tests).

Verification & Acceptance Criteria:
- Run `python -m pytest tests/ --ignore=tests/workspace -x -q`
- Must pass with 0 regressions (861+ existing tests pass) and at least 20 new tests (total passing >= 881).
