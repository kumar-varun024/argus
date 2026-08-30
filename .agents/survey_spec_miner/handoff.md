# SQLi Engine & Test Baseline Specification Report

## 1. Observation

### 1.1 Test Suite Baseline
- **Command executed**: `python -m pytest tests/ --ignore=tests/workspace -x -q`
- **Result**: `861 passed, 13416 warnings in 22.33s` (Exit Code: 0)
- **Current Total Test Count**: 861 passing tests
- **Requirement Target**: Must maintain 0 regressions across all 861 existing tests and add $\ge 20$ new tests covering SQL injection detection, payload generation, WAF mutations, differential analysis, timing delay, false positive rejection, DAG scheduling, registry loading, and E2E mission loop integration.

### 1.2 Codebase Architecture & Integration Points
Directly observed integration files and patterns:
1. **`argus/collectors/base.py`**:
   - `BaseCollector` defines `@abstractmethod def collect(self, mission)`
2. **`argus/collectors/path_traversal.py` & `argus/collectors/access_control.py` & `argus/collectors/information_disclosure.py`**:
   - Class structure: Generator (`*PayloadGenerator`), Analyzer (`*Analyzer`), and Collector (`*Collector(BaseCollector)`).
   - Candidate extraction: extracts query parameters, path segments, POST body, and candidate base hosts.
   - Dual interface support: `collect(self, mission)` and `execute(self, mission)`.
   - Evidence creation: `Evidence(category="sql_injection", severity="critical" | "high", status="CONFIRMED", confidence=0.95, ...)`
   - Graph wiring: creates nodes for `live_host`, `endpoint`, and `vulnerability`, connecting `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
3. **`argus/planning/task_generator.py`**:
   - Lines 13–98: `_RECON_TEMPLATES` dictionary containing recon tools (`subfinder`, `httpx`, `katana_crawler`, `nuclei`, `info_disclosure`, `access_control`, `path_traversal`).
   - Lines 314–400: `_resolve_template_for_gap(self, gap: CoverageGap)` resolving gaps by keyword (needs `sqli`, `sql injection`, `sql_injection`, `database injection`).
   - Lines 401–457: `from_gaps(self, gaps)` mapping gap inputs to candidate URLs/endpoints.
4. **`argus/runtime/registry.py`**:
   - Lines 44–288: Global `registry` with registered `Tool` instances. Internal collectors are registered with `safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]}`.
5. **`argus/runtime/plugins.py`**:
   - Lines 65–100: `_instantiate_specialist_fallback(self, plugin_id: str)` providing fallback instantiation for internal collectors.
6. **`argus/graph/attack_surface.py`**:
   - Lines 174–401: `AttackSurfaceGraphBuilder.build_from_evidence` maps evidence categories (`vulnerability`, `subdomain_takeover`, `information_disclosure`, `broken_access_control`, `path_traversal`) into `KnowledgeGraph` nodes and `HAS_VULNERABILITY` edges.
7. **`argus/http/client.py`**:
   - `AuthenticatedHttpClient`: Supports `get()`, `post()`, `put()`, `patch()`, `delete()`, `head()`, `options()`. Returns `HttpResponse` with `status_code`, `headers`, `request_headers`, `body`, `raw_body`, `elapsed` (seconds), `url`, `method`, `error`.

---

## 2. Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | Error-Based SQLi | Multi-DBMS Syntax Error Detection | Detects error messages from 5 major database engines (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) returned in response bodies after injecting syntax-breaking characters (`'`, `"`, `\'`, `\"`, `')`, `1' ORDER BY 1--`). | Injected HTTP responses, raw response body, status code | Match metadata (`matched_signature`, `dbms`, `snippet`, `error_pattern`) | Returns `None` if no DBMS signature matches or if status is not applicable | Spec R2.1, DBMS manual specifications |
| 2 | Error-Based SQLi | Database Signature Catalog | Comprehensive regex signatures for: MySQL (`You have an error in your SQL syntax`, `check the manual that corresponds to your (MySQL\|MariaDB) server version`, `MySqlClient.`, `MySQLSyntaxErrorException`), PostgreSQL (`PostgreSQL.*ERROR`, `pg_query()`, `PSQLException`, `ERROR:\s+syntax error at or near`), MSSQL (`Driver.*SQL Server`, `OLE DB.*SQL Server`, `Unclosed quotation mark after the character string`, `[Microsoft][ODBC SQL Server Driver]`), Oracle (`ORA-[0-9]{5}`, `Oracle error`, `quoted string not properly terminated`), SQLite (`SQLite/JDBCDriver`, `SQLite.Exception`, `sqlite3.OperationalError`, `SQLITE_ERROR`, `near ".*": syntax error`). | Response text stream | DBMS classification and matched line | Skips non-DBMS errors and generic strings | Spec R2.1, standard vulnerability corpora |
| 3 | Boolean-Based Blind | Differential Analysis (TRUE vs FALSE) | Injects paired boolean conditions (e.g. `' OR 1=1--` vs `' OR 1=2--`, `1 AND 1=1` vs `1 AND 1=2`) and compares response length, content structure, and status codes to detect differential application behavior indicating SQL injection. | Target URL/params, TRUE payload, FALSE payload, baseline response | Boolean verdict (`is_vulnerable: True`, `true_length`, `false_length`, `length_delta`, `confidence`) | Returns `None` if TRUE and FALSE responses are identical or both trigger error pages | Spec R2.2 |
| 4 | Boolean-Based Blind | Dynamic Tolerance & Noise Filtering | Filters out dynamic body content (timestamps, CSRF tokens, session IDs) by evaluating length delta thresholds and structural stability between baseline and injected responses. | Baseline response body, TRUE response body, FALSE response body | Normalized differential score | Rejects differential if difference is within normal dynamic noise threshold | Spec R2.2 |
| 5 | Time-Based Blind | Time-Delay Measurement | Injects time-delay payloads (e.g., MySQL `SLEEP(5)`, Postgres `pg_sleep(5)`, MSSQL `WAITFOR DELAY '0:0:5'`, Oracle `dbms_lock.sleep(5)`) and measures elapsed request duration. | Target endpoint, delay payload ($D=5$s), timeout configuration | Timing verdict (`is_vulnerable: True`, `elapsed_time`, `baseline_time`, `delay_delta`) | Returns `None` if response latency does not meet delay threshold | Spec R2.3 |
| 6 | Time-Based Blind | Baseline Latency Calibration & Delay Threshold | Calculates baseline request latency ($T_{baseline}$) before injection and requires $T_{injected} - T_{baseline} \ge 4.0\text{ seconds}$ to confirm time-based SQL injection without false positives from slow network links. | Benign baseline request timing, injected request timing | Verified time-delay injection finding | Rejects when baseline itself is slow or latency difference $< 4.0$s | Spec R2.3 |
| 7 | False Positive Rejection | Application Generic Word Filtration | Distinguishes genuine database syntax error messages from common application text containing words like "error", "sql", "syntax", "database", or HTML page headings (`<title>Error</title>`). | Response body, status code, URL path | Boolean flag (`is_genuine_dbms_error`) | Discards generic words that lack DBMS-specific syntax signatures | Acceptance Criteria R2/False Positives |
| 8 | False Positive Rejection | Reflection Discard Logic | Identifies when injected payload strings are merely reflected back into HTML/JSON output (e.g. `<p>Results for: ' OR 1=1--</p>`) without database execution. | Injected payload string, response body, matched regex span | Boolean flag (`is_reflection`) | Discards finding if match is an artifact of literal parameter reflection | Acceptance Criteria R2/False Positives |
| 9 | WAF Bypass | Strategy 1: Case Alternation | Mutates SQL keywords to mixed case (e.g. `sElEcT`, `uNiOn`, `wHeRe`, `aNd`, `oR`, `sLeEp`) to bypass case-sensitive signature filters. | Base SQL payload | Mutated payload string | Preserves semantic validity of SQL payload | Spec R3 |
| 10 | WAF Bypass | Strategy 2: Comment Insertion | Inserts inline comments `/**/` inside or between SQL keywords (e.g. `SEL/**/ECT`, `UN/**/ION/**/ALL/**/SEL/**/ECT`, `OR/**/1=1`). | Base SQL payload | Mutated payload string | Retains valid SQL parsing by target DBMS engine | Spec R3 |
| 11 | WAF Bypass | Strategy 3: URL Encoding | Encodes special SQL characters (`%27`, `%20`, `%3D`, `%2D%2D`) into standard percent-encoding format. | Base SQL payload | URL-encoded payload string | Handles query string and body parameter encoding | Spec R3 |
| 12 | WAF Bypass | Strategy 4: Double URL Encoding | Double encodes special characters (`%2527`, `%2520`, `%253D`, `%252D%252D`) to bypass reverse proxy / WAF decoders that perform only single decoding. | Base SQL payload | Double URL-encoded payload string | Handles multi-tier proxy architecture evasion | Spec R3 |
| 13 | WAF Bypass | Strategy 5: Whitespace Substitution | Replaces whitespace with alternative separators recognized by SQL engines: tabs (`%09`), newlines (`%0a`), carriage returns (`%0d`), plus (`+`), and inline comments (`/**/`). | Base SQL payload | Whitespace-substituted payload string | Produces valid whitespace alternatives | Spec R3 |
| 14 | Parameter Fuzzing | Multi-Parameter Injection Surface | Injects payloads into query parameters, POST form-urlencoded fields, POST JSON body fields, path segments, and HTTP headers (`Cookie`, `Referer`, `X-Forwarded-For`, `User-Agent`). | Candidate endpoint object from mission | Dispatched HTTP requests across injection vectors | Handles malformed endpoints and missing parameter types gracefully | Spec R1 |
| 15 | Graph & Pipeline | AttackSurfaceGraph & TaskGenerator Wiring | Integrates `SQLInjectionCollector` into `TaskGenerator` DAG, registers in `ToolRegistry` as internal plugin `sql_injection`, and builds `vulnerability` nodes connected with `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges. | Mission object, EvidenceStore | Updated KnowledgeGraph, mission vulnerabilities list, Evidence list | No unhandled exceptions on empty missions or missing assets | Spec R4 |

---

## 3. Edge Cases

| # | Feature | Input | Observed Behavior |
|---|---------|-------|-------------------|
| 1 | Error-Based Detection | Page contains `<title>Application Error</title> <p>Please contact sql-admin@company.com</p>` | Must NOT trigger error-based SQLi (rejected by strict DBMS signature regexes). |
| 2 | Error-Based Detection | Endpoint echoes search query: `<h1>Search for: ' OR 1=1--</h1>` | Must NOT trigger error-based SQLi (reflection guard identifies matched string inside payload / HTML reflection). |
| 3 | Error-Based Detection | Injected `'` triggers MySQL error: `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version` | Matches `mysql_syntax_error`, emits `Evidence(category="sql_injection", severity="critical")`. |
| 4 | Error-Based Detection | Baseline already returns `PostgreSQL ERROR: relation "config" does not exist` before injection | Differential check ignores pre-existing baseline database errors and does not attribute to payload. |
| 5 | Boolean-Based Blind | Injected `' OR 1=1--` returns 200 OK (2500 bytes) with user profile; `' OR 1=2--` returns 200 OK (150 bytes) empty container | Differential analyzer confirms SQLi, calculates $\Delta > 30$ bytes, emits `Evidence(category="sql_injection", severity="high")`. |
| 6 | Boolean-Based Blind | Injected `' OR 1=1--` returns 200 OK (500 bytes) and `' OR 1=2--` returns 200 OK (500 bytes) identical body | Differential analyzer detects 0 delta / identical content, rejects finding. |
| 7 | Boolean-Based Blind | Injected `' OR 1=1--` returns 200 OK (1200 bytes) and `' OR 1=2--` returns 404 / 500 error | Status code differential confirms injection condition, emits `Evidence(category="sql_injection", severity="high")`. |
| 8 | Time-Based Blind | Baseline latency is 0.05s; Injected `SLEEP(5)` takes 5.08s | Delay delta is $5.08 - 0.05 = 5.03\text{s} \ge 4.0\text{s}$, emits `Evidence(category="sql_injection", severity="critical")`. |
| 9 | Time-Based Blind | Baseline latency is 4.5s (congested server); Injected `SLEEP(5)` takes 4.7s | Delay delta is $4.7 - 4.5 = 0.2\text{s} < 4.0\text{s}$, rejected as non-injection baseline network lag. |
| 10 | Time-Based Blind | Injected payload causes HTTP timeout / connection drop | Exception handled gracefully, request logs error, no crash. |
| 11 | WAF Mutation | Input payload: `' UNION SELECT 1,2,3-- ` | Mutation strategies generate: `1. ' uNiOn sElEcT 1,2,3--`, `2. ' UN/**/ION/**/SEL/**/ECT 1,2,3--`, `3. %27%20UNION%20SELECT%201%2C2%2C3--`, `4. %2527%2520UNION%2520SELECT%25201%252C2%252C3--`, `5. '%09UNION%09SELECT%091,2,3--`. |
| 12 | Parameter Fuzzing | JSON POST request `{"query": "books", "limit": 10}` | Injects into JSON keys: `{"query": "books' OR '1'='1", "limit": 10}` and `{"query": "books", "limit": "10' OR '1'='1"}`. |
| 13 | Parameter Fuzzing | Path parameter `https://example.com/api/users/123` | Injects into path segment: `https://example.com/api/users/123%27%20OR%201=1--`. |
| 14 | Parameter Fuzzing | Header injection `Cookie: session_id=abc; user_id=123'` | Injects into header values: `X-Forwarded-For: 127.0.0.1'`, `Referer: https://example.com/item'`. |
| 15 | Attack Surface Graph | EvidenceStore has 1 error-based SQLi and 1 boolean-based SQLi on same endpoint | Graph creates live_host, endpoint, and distinct vulnerability nodes, connects `HAS_ENDPOINT` and `HAS_VULNERABILITY` without duplicate node ID conflicts. |

---

## 4. Test Mocks, Fixtures, and Conventions Inventory

### 4.1 Existing Test Patterns & Infrastructure
1. **Mock HTTP Clients in Unit/Adversarial Tests**:
   - `MockTraversalHttpClient`, `MockAdversarialHttpClient`, `MockE2EPathTraversalHttpClient`:
     - Provide `set_route(url, status_code, body)` or `history` tracking.
     - Return `HttpResponse(success=..., status_code=..., raw_body=..., body=..., url=..., elapsed=...)`.
     - Implement `get(mission, url, **kwargs)` and `post(mission, url, **kwargs)` handling mission or plain url arguments.
2. **Timing Delay Emulation for Time-Based Tests**:
   - Mock client can accept a route definition with `(status_code, body, delay_seconds)` or a callable hook that executes `time.sleep(...)` or populates `HttpResponse.elapsed = 5.05`.
3. **Live Socket Server Fixtures**:
   - In `tests/http/test_authenticated_http_client.py`: Uses `find_free_port()`, `HTTPServer(("127.0.0.1", port), Handler)`, runs in daemon background thread, provides real HTTP socket interactions for integration tests.
4. **Mission Fixture Setup**:
   ```python
   mission = Mission(target="example.com")
   mission.scope = ["example.com"]
   mission.endpoints = [{"url": "https://example.com/search?q=test", "path": "/search", "host": "https://example.com"}]
   mission.live_hosts = [{"url": "https://example.com", "host": "example.com"}]
   mission.evidence = EvidenceStore()
   mission.vulnerabilities = []
   mission.attack_surface_graph = KnowledgeGraph()
   ```
5. **Test File Conventions**:
   - Unit tests: `tests/collectors/test_sql_injection.py` (or `test_sqli.py`)
   - Adversarial / boundary tests: `tests/collectors/test_sql_injection_adversarial.py`
   - E2E Mission runtime tests: `tests/runtime/test_e2e_sql_injection.py`

---

## 5. Logic Chain

1. **Test Baseline Stability**:
   - Direct observation of running `pytest tests/ --ignore=tests/workspace -x -q` confirms 861 tests pass cleanly.
   - Any implementation of `SQLInjectionCollector` and supporting modules must strictly preserve all 861 tests and introduce zero regressions.

2. **Collector Design Conformance**:
   - Observation of `PathTraversalCollector` (`argus/collectors/path_traversal.py`), `AccessControlCollector` (`argus/collectors/access_control.py`), and `InformationDisclosureCollector` (`argus/collectors/information_disclosure.py`) reveals a consistent three-tier modular pattern:
     - `SQLInjectionPayloadGenerator`: Encapsulates base payloads and 5 WAF mutation strategies.
     - `SQLInjectionAnalyzer`: Encapsulates multi-DBMS signature regexes, boolean differential logic, time delay calculation, and false positive / reflection rejection.
     - `SQLInjectionCollector(BaseCollector)`: Orchestrates candidate parameter extraction (GET query, POST form/JSON, path segments, headers), executes requests via `AuthenticatedHttpClient`, passes responses to analyzer, creates `Evidence`, and updates mission vulnerabilities and `KnowledgeGraph`.

3. **Multi-DBMS Signatures & Severity Rules**:
   - Observation of DBMS error specifications yields strict regex signatures for MySQL, PostgreSQL, MSSQL, Oracle, and SQLite.
   - Error-based and time-based confirmed findings must be assigned `severity="critical"`.
   - Boolean-based differential findings must be assigned `severity="high"`.

4. **WAF Bypass Mutation Coverage**:
   - Spec R3 explicitly requires 5 distinct mutation strategies:
     - Case Alternation (`sElEcT`)
     - Comment Insertion (`SEL/**/ECT`)
     - URL Encoding (`%27%20OR%201%3D1--`)
     - Double Encoding (`%2527%2520OR%25201%253D1--`)
     - Whitespace Substitution (`%09`, `%0a`, `%0d`, `+`, `/**/`)

5. **Pipeline & Graph Integration**:
   - `argus/planning/task_generator.py`: Add `sql_injection` to `_RECON_TEMPLATES`, `_resolve_template_for_gap`, and `from_gaps`.
   - `argus/runtime/registry.py`: Register `sql_injection` in global `registry`.
   - `argus/runtime/plugins.py`: Add `sql_injection` to `_instantiate_specialist_fallback`.
   - `argus/graph/attack_surface.py`: Add `category == "sql_injection"` handling in `AttackSurfaceGraphBuilder.build_from_evidence`.
   - `argus/collectors/__init__.py`: Export `SQLInjectionCollector`, `SQLInjectionPayloadGenerator`, `SQLInjectionAnalyzer`.

---

## 6. Caveats

- **No Caveats**: The codebase, test suite, and requirements are completely accessible, verifiable, and well-structured.

---

## 7. Conclusion

All specifications, DBMS error signatures, boolean differential heuristics, time-delay baseline calculation formulas, false positive filters, WAF bypass mutations, and pipeline integration requirements have been surveyed and documented. The test suite baseline is 861 passing tests. Implementation plans and tests can proceed directly from this specification.

---

## 8. Verification Method

- **Baseline Pytest Command**:
  ```bash
  python -m pytest tests/ --ignore=tests/workspace -x -q
  ```
- **Expected Result**: Exits 0, 861 passed.
- **Files Inspected**:
  - `/home/varun/argus/ORIGINAL_REQUEST.md`
  - `/home/varun/argus/argus/collectors/__init__.py`
  - `/home/varun/argus/argus/collectors/base.py`
  - `/home/varun/argus/argus/collectors/path_traversal.py`
  - `/home/varun/argus/argus/collectors/access_control.py`
  - `/home/varun/argus/argus/collectors/information_disclosure.py`
  - `/home/varun/argus/argus/planning/task_generator.py`
  - `/home/varun/argus/argus/planning/models.py`
  - `/home/varun/argus/argus/runtime/registry.py`
  - `/home/varun/argus/argus/runtime/plugins.py`
  - `/home/varun/argus/argus/graph/attack_surface.py`
  - `/home/varun/argus/argus/http/client.py`
  - `/home/varun/argus/tests/collectors/test_path_traversal.py`
  - `/home/varun/argus/tests/collectors/test_path_traversal_adversarial.py`
  - `/home/varun/argus/tests/runtime/test_e2e_path_traversal.py`
  - `/home/varun/argus/tests/http/test_authenticated_http_client.py`
