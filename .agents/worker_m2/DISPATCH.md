## 2026-08-30T07:28:37Z

You are Worker 2 (XSS Specialist) for Sprint 10 Milestone 2.
Your working directory is /home/varun/argus/.agents/worker_m2

You MUST read /home/varun/argus/.agents/ORIGINAL_REQUEST.md and /home/varun/argus/PROJECT.md before doing anything else.
You should also read the architectural design at /home/varun/argus/.agents/survey_collector_explorer/handoff.md and reference collectors (`argus/collectors/sql_injection.py`, `argus/collectors/path_traversal.py`, `argus/collectors/base.py`, `argus/http/client.py`).

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your Exclusive File Ownership:
- `argus/collectors/xss.py`
- `argus/collectors/__init__.py`
- `tests/collectors/test_xss.py`
- `tests/collectors/test_xss_adversarial.py`

Your Mission:
1. Implement `argus/collectors/xss.py`:
   - `XSSContext` Enum: `HTML_BODY`, `ATTRIBUTE_DOUBLE`, `ATTRIBUTE_SINGLE`, `ATTRIBUTE_UNQUOTED`, `SCRIPT_STRING_DOUBLE`, `SCRIPT_STRING_SINGLE`, `SCRIPT_BLOCK`, `URL_ATTRIBUTE`, `COMMENT`, `UNKNOWN`.
   - `XSSPayloadGenerator`:
     - `generate_canary(prefix="argusxss") -> str`: unique alphanumeric string with UUID suffix.
     - `get_canary_probe(canary: str) -> str`: returns probe canary for initial reflection discovery.
     - `get_context_payloads(context: XSSContext, canary: str) -> List[Dict[str, str]]`: returns targeted payloads and expected breakout markers for HTML body, attribute quotes/unquoted, script strings, and URL attributes.
     - `get_default_payload_suite(canary: str) -> List[Tuple[str, XSSContext, str]]`: multi-context suite.
     - `get_stored_payload(canary: str) -> str`: stored XSS test payload.
   - `XSSAnalyzer`:
     - Robust HTML context parsing via `html.parser.HTMLParser` or `BeautifulSoup`.
     - `is_properly_escaped(raw_body: str, canary: str) -> bool`: strictly checks whether special characters associated with the canary are HTML entity-encoded (`&lt;`, `&gt;`, `&quot;`, `&#39;`, `&#x27;`, `&amp;`), suppressing false positives when properly escaped.
     - `analyze_reflected(resp: HttpResponse, canary: str, payload: str, context: Optional[XSSContext]) -> Optional[Dict[str, Any]]`: verifies unescaped reflection and breakout in HTML body, attribute, script, or header context, returning finding dict with `severity="high"` (or `"medium"` for headers).
     - `analyze_stored(resp: HttpResponse, canary: str, payload: str) -> Optional[Dict[str, Any]]`: verifies persistence of unescaped payload in re-fetched page, returning finding dict with `severity="critical"`.
   - `XSSCollector(BaseCollector)`:
     - `__init__(self, http_client=None, payload_generator=None, analyzer=None, timeout=10.0)`
     - `collect(self, mission) -> List[Evidence]`: extracts candidates from `mission.endpoints`, `mission.live_hosts`, tests GET query parameters, POST form bodies (`data=`), POST JSON bodies (`json=`), HTTP headers (`User-Agent`, `Referer`, `X-Forwarded-For`), and Stored XSS via stateful POST-then-GET.
     - Creates `Evidence(category="xss", severity="critical" if stored else ("high" if reflected else "medium"), ...)` and appends to `mission.evidence`, `mission.vulnerabilities`.
     - Updates `mission.attack_surface_graph` with `live_host`, `endpoint`, `vulnerability` nodes and `HAS_ENDPOINT`, `HAS_VULNERABILITY` edges.
     - `execute(self, mission) -> Dict[str, Any]`: plugin adapter method.
2. In `argus/collectors/__init__.py`:
   - Export `XSSCollector`, `XSSAnalyzer`, `XSSPayloadGenerator`, `XSSContext`.
3. Create comprehensive tests:
   - `tests/collectors/test_xss.py`: unit tests for `XSSPayloadGenerator`, `XSSAnalyzer` (reflected body, attribute, script string, stored post-then-get), `XSSCollector` (GET query param fuzzing, POST form/JSON fuzzing, header fuzzing, stored XSS), and graph node/edge creation.
   - `tests/collectors/test_xss_adversarial.py`: adversarial & false positive tests (entity-encoded `<` / `>` rejection, quote entity escaping, JSON content-type rejection, plain text content-type rejection, malformed HTML, network timeouts, invalid endpoints).
4. Run tests and verify zero regressions:
   - `python -m pytest tests/collectors/test_xss.py tests/collectors/test_xss_adversarial.py -v`
   - `python -m pytest tests/ --ignore=tests/workspace -x -q`
5. Write your handoff report to `/home/varun/argus/.agents/worker_m2/handoff.md`.
6. When complete, send a final message to the orchestrator referencing your handoff report.
