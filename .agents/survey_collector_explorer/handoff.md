# Handoff Report: XSS Detection Collector (R1) Survey & Architecture Specification

## 1. Observation

A comprehensive audit was performed across the ARGUS codebase to survey collector patterns, HTTP client interactions, evidence models, graph representations, runtime registries, and task planning DAGs.

### A. Existing Collector Implementations
1. **`argus/collectors/base.py` (Lines 1-10)**:
   ```python
   class BaseCollector(ABC):
       @abstractmethod
       def collect(self, mission):
           pass
   ```
   All collectors implement `collect(self, mission) -> List[Evidence]` and provide an `execute(self, mission)` method for plugin compatibility.

2. **`argus/collectors/path_traversal.py` (Lines 1-591)** & **`argus/collectors/sql_injection.py` (Lines 1-1184)**:
   - Structure follows a 3-class paradigm:
     - `PayloadGenerator`: generates base probe inputs, mutated payloads, and technique-specific test cases.
     - `Analyzer`: parses HTTP responses, matches signatures/deltas, eliminates false positives, and returns structured match metadata (`template_id`, `severity`, `confidence`, `snippet`, etc.).
     - `Collector(BaseCollector)`: extracts candidate endpoints from `mission.endpoints` and `mission.live_hosts`, iterates through parameters (GET query, POST form/JSON, headers, path segments), executes requests via `AuthenticatedHttpClient`, passes responses to `Analyzer`, creates `Evidence`, appends to `mission.vulnerabilities`, and expands `mission.attack_surface_graph` with `Node` and `Edge` objects (`HAS_ENDPOINT`, `HAS_VULNERABILITY`).

3. **`argus/collectors/javascript.py` (Lines 1-163)**:
   - Uses `bs4.BeautifulSoup` to parse HTML (`soup.find_all("script")`) and locate JavaScript sources.

4. **`argus/http/client.py` (Lines 300-587)**:
   - `AuthenticatedHttpClient` inherits from `AuthorizedHttpClient`.
   - Methods: `get(mission, url, params=None, headers=None, cookies=None, timeout=None)`, `post(mission, url, data=None, json=None, headers=None, cookies=None, timeout=None)`, `request(mission, method, url, ...)`.
   - Returns `HttpResponse` dataclass with fields: `success` (bool), `status_code` (Optional[int]), `headers` (Dict[str, str]), `request_headers` (Dict[str, str]), `body` (Optional[str]), `raw_body` (Optional[str]), `url` (str), `method` (str), `elapsed` (float), `error` (Optional[str]), `scope_decision`, `authorization_decision`.
   - Enforces strict scope gating via `ScopeResolver` before any network activity.

5. **`argus/evidence/model.py` (Lines 26-56)**:
   - `Evidence` dataclass fields: `evidence_id`, `mission_id`, `source_type="LOG"`, `created_by="SYSTEM_GENERATED"`, `title`, `description`, `category`, `value`, `source`, `status="CONFIRMED"`, `confidence` (float e.g. 0.95), `severity` ("critical" / "high" / "medium" / "info"), `provenance` (`ProvenanceData(step_id=...)`), `tags` (List[str]), `metadata` (Dict[str, Any]).

6. **`argus/graph/attack_surface.py` (Lines 1-638)**:
   - Graph builder maps structured evidence to `KnowledgeGraph` nodes and edges:
     - `live_host`: `id=f"live_host:{base_url}"`
     - `endpoint`: `id=f"endpoint:{target_url}"`
     - `vulnerability`: `id=f"vulnerability:{template_id}:{target_url}:{param}"`
     - Edges: `HAS_ENDPOINT` from `live_host` -> `endpoint`, `HAS_VULNERABILITY` from `live_host` -> `vulnerability`, and `HAS_VULNERABILITY` from `endpoint` -> `vulnerability`.

7. **`argus/planning/task_generator.py` (Lines 13-110, 326-474)**:
   - `_RECON_TEMPLATES` registers tasks with `tool_id`, `dependencies`, `required_inputs=["endpoints"]`, `expected_outputs=["vulnerabilities", "observations", "evidence"]`.
   - `_resolve_template_for_gap` maps coverage gap keywords to task templates.

8. **`argus/runtime/registry.py` (Lines 44-305)** & **`argus/runtime/plugins.py` (Lines 65-104)**:
   - `ToolRegistry` registers executable tools (`Tool(id="xss", name="XSS Collector", ...)`).
   - `PluginExecutorAdapter._instantiate_specialist_fallback` dynamically instantiates collector classes when executed as plugins.

9. **Test Suite Baseline**:
   - `python3 -m pytest tests/ --ignore=tests/workspace -x -q` passed cleanly with **896 passed** tests.

---

## 2. Logic Chain

From these direct observations, the design for `argus/collectors/xss.py` and its pipeline integrations is derived step-by-step:

### Step 1: XSS Requirements Decomposition
To fulfill OWASP WSTG-INPV-01/02 and the Sprint 10 specification, the engine must support three core detection vectors:
1. **Reflected XSS**:
   - Canary token generation: Uniquely randomized, alphanumeric/tokenized strings (e.g. `argus_xss_<uuid8>`) to avoid colliding with normal application keywords.
   - Target vectors: GET query parameters, POST form fields (`application/x-www-form-urlencoded`), POST JSON body fields (`application/json`), and HTTP headers (`User-Agent`, `Referer`, `X-Forwarded-For`, `Cookie`).
   - HTML context parsing and unescaped reflection verification.
   - Strict false positive rejection when special characters (`<`, `>`, `"`, `'`, `&`) are properly entity-encoded (`&lt;`, `&gt;`, `&quot;`, `&#39;`, `&amp;`).
2. **Stored XSS**:
   - Multi-step stateful validation: POST payload submission followed immediately by a GET request to the same endpoint or related rendering view (e.g., `/view`, `/profile`, `/posts`, `/comments`).
   - Detection of persisted, unescaped canary payloads in the subsequent GET response.
   - Critical severity assignment (`severity="critical"`).
3. **Context-Aware Payload Generation**:
   - Reflection in different syntactic locations in an HTML document requires distinct escape sequences:
     - **HTML Body Context** (`<tag>...CANARY...</tag>`): Breakout tags `<script>/*CANARY*/</script>`, `<img src=x onerror=alert('CANARY')>`, `<svg onload=alert(CANARY)>`, `<b>CANARY</b>`.
     - **HTML Attribute (Double Quote)** (`<tag attr="...CANARY...">`): Breakout sequences `">`, `" onfocus="`, `" autofocus onfocus="`.
     - **HTML Attribute (Single Quote)** (`<tag attr='...CANARY...'>`): Breakout sequences `'>`, `' onfocus='`, `' onmouseover='`.
     - **HTML Attribute (Unquoted)** (`<tag attr=...CANARY...>`): Breakout sequences ` onfocus=`, ` autofocus onfocus=`.
     - **JavaScript String Context** (`<script>var x = "...CANARY...";</script>`): Breakout sequences `";alert('CANARY');//`, `';alert('CANARY');//`, `</script><script>alert('CANARY')</script>`.
     - **URL Context** (`<a href="...CANARY...">`): `javascript:alert('CANARY')`, `javascript:void('CANARY')`.

### Step 2: Component Architecture for `argus/collectors/xss.py`

#### Component 1: `XSSContext` (Enum)
Defines HTML syntactic reflection contexts:
- `HTML_BODY = "html_body"`
- `ATTRIBUTE_DOUBLE = "attribute_double"`
- `ATTRIBUTE_SINGLE = "attribute_single"`
- `ATTRIBUTE_UNQUOTED = "attribute_unquoted"`
- `SCRIPT_STRING_DOUBLE = "script_string_double"`
- `SCRIPT_STRING_SINGLE = "script_string_single"`
- `SCRIPT_BLOCK = "script_block"`
- `URL_ATTRIBUTE = "url_attribute"`
- `COMMENT = "comment"`
- `UNKNOWN = "unknown"`

#### Component 2: `XSSPayloadGenerator`
- `generate_canary(prefix: str = "argusxss") -> str`: Generates `f"{prefix}_{uuid.uuid4().hex[:8]}"`.
- `get_canary_probe(canary: str) -> str`: Returns benign canary string for initial echo & context discovery.
- `get_context_payloads(context: XSSContext, canary: str) -> List[Dict[str, str]]`: Returns targeted payload sets and expected breakout tokens.
- `get_default_payload_suite(canary: str) -> List[Tuple[str, XSSContext, str]]`: Returns a multi-context payload suite covering Body, Attribute, and Script contexts.
- `get_stored_payload(canary: str) -> str`: Generates high-confidence stored test payload (e.g. `<b id="argus_stored_{canary}">stored_xss</b>` or `<img src=x onerror=alert('{canary}')>`).

#### Component 3: `XSSAnalyzer`
- `HTMLContextDetector`: An internal `html.parser.HTMLParser` state machine that parses responses, tracks tag stack, current tag attributes, script/style blocks, comments, and identifies the exact `XSSContext` of canary occurrences.
- `is_properly_escaped(raw_body: str, canary: str) -> bool`: Verifies whether special characters associated with the canary are entity-encoded (`&lt;`, `&gt;`, `&quot;`, `&#39;`, `&#x27;`, `&amp;`). If all occurrences are escaped, flags as safe (false positive suppression).
- `analyze_reflected(resp: HttpResponse, canary: str, payload: str, context: Optional[XSSContext]) -> Optional[Dict[str, Any]]`:
  - Validates `resp.status_code` and response content.
  - Checks if canary and breakout tokens appear unescaped in an executable context.
  - Returns match dictionary:
    `{"xss_type": "reflected", "context": context.value, "template_id": f"xss-reflected-{context.value.replace('_', '-')}", "severity": "high", "confidence": 0.95, "snippet": snippet}`
- `analyze_stored(resp: HttpResponse, canary: str, payload: str) -> Optional[Dict[str, Any]]`:
  - Analyzes re-fetched GET response for presence of persisted unescaped payload.
  - Returns match dictionary:
    `{"xss_type": "stored", "context": "html_body", "template_id": "xss-stored", "severity": "critical", "confidence": 0.95, "snippet": snippet}`

#### Component 4: `XSSCollector(BaseCollector)`
- `__init__(self, http_client=None, payload_generator=None, analyzer=None, timeout=10.0)`
- `_extract_candidate_endpoints(mission) -> List[Dict[str, Any]]`: Ingests `mission.endpoints`, `mission.live_hosts`, and fallback probe paths (`/search`, `/view`, `/feedback`, `/profile`, `/contact`, `/comments`, `/login`).
- `_execute_request(mission, method, url, params, data, json_data, headers, cookies) -> Optional[HttpResponse]`
- `_test_reflected_xss(mission, candidate, detected_evidence, confirmed_vuln_keys)`:
  - Vector 1: GET Query parameters.
  - Vector 2: POST form bodies (`data=...`).
  - Vector 3: POST JSON bodies (`json=...`).
  - Vector 4: HTTP Headers (`User-Agent`, `Referer`, `X-Forwarded-For`, `Cookie`).
- `_test_stored_xss(mission, candidate, detected_evidence, confirmed_vuln_keys)`:
  - Submits stored payload via POST.
  - Re-fetches endpoint via GET.
  - Verifies persistence with `XSSAnalyzer.analyze_stored`.
- `_create_evidence_and_update_state(...) -> Evidence`:
  - Instantiates `Evidence(category="xss", severity="critical" if stored else "high", ...)`
  - Adds to `mission.evidence`, `mission.vulnerabilities`.
  - Adds `live_host`, `endpoint`, and `vulnerability` nodes and connects with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
  - Calls `mission.publish_finding`.

### Step 3: Pipeline Integration Wiring
1. **`argus/collectors/__init__.py`**:
   - Export `XSSCollector`, `XSSAnalyzer`, `XSSPayloadGenerator`, `XSSContext`.
2. **`argus/planning/task_generator.py`**:
   - Add `"xss"` to `_RECON_TEMPLATES` with dependencies `["Discover API Endpoints"]`.
   - Update `_resolve_template_for_gap` to map `"xss"`, `"cross-site scripting"`, `"reflected xss"`, `"stored xss"` to the XSS template.
3. **`argus/runtime/registry.py`**:
   - Register `Tool(id="xss", name="XSS Collector", capability="xss_detector", ...)` in `registry`.
4. **`argus/runtime/plugins.py`**:
   - Add `elif "xss" in plugin_id:` fallback instantiation to `PluginExecutorAdapter`.
5. **`argus/graph/attack_surface.py`**:
   - Add Section 12 in `AttackSurfaceGraphBuilder.build_from_evidence` for `getattr(ev, "category", None) == "xss"`.

---

## 3. Caveats

1. **DOM-Based XSS**: Pure client-side DOM manipulation without server reflection requires JavaScript AST/DOM execution (e.g. headless browser or static JS sink analysis). The XSS collector focuses on Reflected and Stored XSS over HTTP; static JS sink correlations are provided via `JavaScriptCollector` / `JavaScriptAnalyzer`.
2. **WAF Obfuscation Variations**: Complex character set encodings (e.g. UTF-7, non-standard HTML entities) may exist; standard entity decodings (`&lt;`, `&gt;`, `&quot;`, `&#39;`, `&#x27;`, `&amp;`, decimal and hex HTML entities) are handled.
3. **Stored XSS Propagation Routes**: In some web apps, a POST to `/api/comments` is rendered on a different route like `/posts/123`. The collector tests persistence on the target endpoint and standard view routes associated with the host.

---

## 4. Conclusion

The architecture for the XSS Detection Collector is fully mapped and aligns seamlessly with existing ARGUS collectors (`SQLInjectionCollector`, `PathTraversalCollector`, `AccessControlCollector`).

### Key Design Highlights:
| Aspect | Specification |
|---|---|
| **Module File** | `argus/collectors/xss.py` |
| **Collector Class** | `XSSCollector(BaseCollector)` |
| **Payload Generator** | `XSSPayloadGenerator` (Canary generator, Context-aware payload sets, Stored payload sets) |
| **Response Analyzer** | `XSSAnalyzer` (HTML context detection via `html.parser`, breakout verification, entity-encoding false positive rejection) |
| **Evidence Category** | `category="xss"` |
| **Severity Mapping** | Stored XSS: `critical` (0.95 confidence), Reflected XSS: `high` (0.95 confidence), DOM/Contextual: `medium` |
| **Graph Edges** | `HAS_ENDPOINT` (live_host -> endpoint), `HAS_VULNERABILITY` (live_host -> vuln & endpoint -> vuln) |
| **Pipeline Wiring** | `registry.py` (tool ID `xss`), `task_generator.py` (DAG template `xss`), `plugins.py` (fallback adapter), `attack_surface.py` (category `xss`) |

---

## 5. Verification Method

To independently verify the survey and prepare for implementation validation:

1. **Verify Baseline Tests**:
   ```bash
   python3 -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   Must exit with code 0 (896 passed).

2. **Inspect Existing Reference Implementations**:
   - `argus/collectors/sql_injection.py` (56KB complete reference collector)
   - `argus/collectors/path_traversal.py` (24KB complete reference collector)
   - `argus/http/client.py` (AuthenticatedHttpClient and HttpResponse model)
   - `argus/planning/task_generator.py` (DAG task templates)
   - `argus/runtime/registry.py` (Tool registration)

3. **Future Verification Criteria for XSS Implementation**:
   - Unit tests covering `XSSPayloadGenerator` (canary uniqueness, context payload sets).
   - Unit tests covering `XSSAnalyzer` (HTML body unescaped reflection, attribute breakout, JS string breakout, false positive entity-encoding suppression).
   - Unit tests covering `XSSCollector` (GET query parameter fuzzing, POST form/JSON body fuzzing, header fuzzing, stored POST-then-GET persistence).
   - Integration tests covering TaskGenerator DAG generation, ToolRegistry lookup, AttackSurfaceGraph edge creation, and E2E mission execution.
