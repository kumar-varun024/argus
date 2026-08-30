# Milestone 2 Handoff Report: Cross-Site Scripting (XSS) Detection Engine

## 1. Observation

The ARGUS XSS Detection Engine (Sprint 10 Milestone 2) has been fully implemented and verified in accordance with `ORIGINAL_REQUEST.md` and `PROJECT.md`.

### Files Modified & Created:
- `argus/collectors/xss.py`: Complete implementation of `XSSContext`, `XSSPayloadGenerator`, `XSSAnalyzer`, and `XSSCollector(BaseCollector)`.
- `argus/collectors/__init__.py`: Exported `XSSCollector`, `XSSAnalyzer`, `XSSPayloadGenerator`, and `XSSContext`.
- `tests/collectors/test_xss.py`: 13 comprehensive unit and integration tests covering canary token generation, context payload suites, HTML context detection, entity escaping verification, Reflected XSS (GET query, POST form, POST JSON, HTTP headers), Stored XSS persistence (POST-then-GET), plugin execute adapter, and attack surface graph node/edge creation.
- `tests/collectors/test_xss_adversarial.py`: 12 adversarial and false-positive suppression tests covering entity-encoded tag rejection (`&lt;`, `&gt;`), entity-encoded quote rejection (`&quot;`, `&#39;`, `&#x27;`), decimal/hex HTML entity rejection, non-HTML content-type rejection (`application/json`, `text/plain`, binary/PDF), malformed HTML handling, null bytes in responses, massive payload bodies, network error/timeout resilience, malformed endpoint inputs, and ControlledMission wrapper finding publishing.

### Test Execution Results:
1. Dedicated XSS test suites:
   `python -m pytest tests/collectors/test_xss.py tests/collectors/test_xss_adversarial.py -v` -> **25 passed in 0.67s**.
2. Full repository regression suite:
   `python -m pytest tests/ --ignore=tests/workspace -x -q` -> **950 passed in 32.46s (0 regressions)**.

---

## 2. Logic Chain

The implementation follows standard OWASP WSTG-INPV-01/02 methodology and integrates seamlessly with ARGUS architecture:

1. **`XSSContext` Enum**:
   Defines HTML syntactic reflection contexts: `HTML_BODY`, `ATTRIBUTE_DOUBLE`, `ATTRIBUTE_SINGLE`, `ATTRIBUTE_UNQUOTED`, `SCRIPT_STRING_DOUBLE`, `SCRIPT_STRING_SINGLE`, `SCRIPT_BLOCK`, `URL_ATTRIBUTE`, `COMMENT`, and `UNKNOWN`.

2. **`XSSPayloadGenerator`**:
   - `generate_canary(prefix="argusxss") -> str`: Generates unique alphanumeric canary strings with UUID suffixes (e.g. `argusxss4a7f29c1`).
   - `get_canary_probe(canary: str) -> str`: Returns benign canary token for initial reflection discovery.
   - `get_context_payloads(context: XSSContext, canary: str) -> List[Dict[str, str]]`: Generates specialized breakout payloads tailored to the syntactic reflection context.
   - `get_default_payload_suite(canary: str) -> List[Tuple[str, XSSContext, str]]`: Returns multi-context payload suite covering Body, Attribute quotes/unquoted, Script strings, and URL attributes.
   - `get_stored_payload(canary: str) -> str`: Generates high-confidence stored test payload.

3. **`XSSAnalyzer`**:
   - Implements `_HTMLContextDetectorParser` using `html.parser.HTMLParser` state machine combined with attribute regex inspection to accurately identify syntactic reflection contexts.
   - `is_properly_escaped(raw_body: str, canary: str) -> bool`: Strictly checks whether HTML special characters around the canary are entity-encoded (`&lt;`, `&gt;`, `&quot;`, `&#39;`, `&#x27;`, `&#60;`, `&#62;`, `&#34;`, `&#x22;`, `&#x3c;`, `&#x3e;`), suppressing false positives when properly escaped while confirming raw unescaped breakouts.
   - `analyze_reflected(resp: HttpResponse, canary: str, payload: str, context: Optional[XSSContext]) -> Optional[Dict[str, Any]]`: Validates unescaped reflection and breakout, filtering non-HTML content-types (`application/json`, `text/plain`, `application/octet-stream`) and assigning severity `"high"` (or `"medium"` for comments/headers).
   - `analyze_stored(resp: HttpResponse, canary: str, payload: str) -> Optional[Dict[str, Any]]`: Validates persisted unescaped payloads in re-fetched pages, assigning severity `"critical"`.

4. **`XSSCollector(BaseCollector)`**:
   - Ingests candidates from `mission.endpoints`, `mission.live_hosts`, and fallback discovery routes.
   - Executes multi-vector active fuzzing:
     - Vector 1: GET Query Parameters (canary probe context discovery + targeted breakout fuzzing + default suite fallback).
     - Vector 2: POST Form Bodies (`data=...`).
     - Vector 3: POST JSON Bodies (`json=...`).
     - Vector 4: HTTP Headers (`User-Agent`, `Referer`, `X-Forwarded-For`).
     - Vector 5: Stateful Stored XSS via POST payload submission followed by immediate GET verification for persistence.
   - Constructs `Evidence(category="xss", severity=severity, ...)` and updates `mission.evidence`, `mission.vulnerabilities`.
   - Expands `mission.attack_surface_graph` with `live_host`, `endpoint`, and `vulnerability` nodes and connects with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
   - Exposes `execute(self, mission)` adapter for plugin execution.

---

## 3. Caveats

- **DOM-Based XSS**: Pure client-side DOM manipulation without server reflection requires browser JavaScript engine execution (which is evaluated via AST analysis in `JavaScriptCollector`). `XSSCollector` focuses on Reflected and Stored XSS vectors over HTTP.
- **WAF Obfuscation / Charsets**: The analyzer supports standard entity encodings, numeric entity encodings, and hex entity encodings. Custom non-standard character sets (e.g. UTF-7) are mapped to fallback parsing.

---

## 4. Conclusion

Milestone 2 is complete and all requirements have been met with high test coverage and zero regressions.

| Component | Status | Verification |
|---|---|---|
| `XSSContext` & Generator | Complete | 100% test pass rate in `test_xss.py` |
| `XSSAnalyzer` & Escaping | Complete | FP suppression verified in `test_xss_adversarial.py` |
| `XSSCollector` Multi-vector | Complete | GET, POST form/JSON, Header, Stored XSS verified |
| Attack Surface Graph | Complete | `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges verified |
| Regressions | 0 | Full test suite passed (950 passed) |

---

## 5. Verification Method

To independently verify this milestone:

```bash
# 1. Run XSS Unit and Adversarial Test Suites
python -m pytest tests/collectors/test_xss.py tests/collectors/test_xss_adversarial.py -v

# 2. Run Full Regression Audit
python -m pytest tests/ --ignore=tests/workspace -x -q
```
All commands exit code 0.
