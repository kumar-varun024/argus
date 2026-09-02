# Specification Mining & Test Suite Exploration Report: CORS & HTTP Security Header Audit Module

**Author**: Explorer 3 (Spec Miner & Test Suite Explorer)  
**Date**: 2026-09-01T17:15:00Z  
**Target Repository**: `/home/varun/argus`  
**Working Directory**: `/home/varun/argus/.agents/explorer_survey_3`  
**Reference Request**: `/home/varun/argus/.agents/orchestrator/ORIGINAL_REQUEST.md`

---

## Executive Summary
This specification mining and test suite exploration report provides the authoritative specification, edge-case analysis, test suite architecture, mock HTTP client patterns, and pipeline integration models for the **CORS Misconfiguration & HTTP Security Header Audit Module** (`CORSSecurityCollector` in `argus/collectors/cors_headers.py`).

### Key Validation Outcomes:
1. **Test Execution Baseline Verified**:
   Command: `python -m pytest tests/ --ignore=tests/workspace -x -q`
   Result: **1,740 passed, 30,682 warnings in 70.48s (exit code 0)**.
   Zero test failures across all 119 test modules.
2. **Authoritative Specification Extracted**:
   - Requirements R1–R6 thoroughly mined across `ORIGINAL_REQUEST.md`, `PROJECT.md`, `argus/collectors/`, `argus/http/client.py`, `argus/graph/attack_surface.py`, `argus/runtime/registry.py`, and `argus/reporting/cvss.py`.
   - 6 CORS detection modes mapped with exact trigger conditions, severity ratings, and false positive boundaries.
   - 8 HTTP security header audits mapped with exact directive parsing, RFC specifications, and compliance rules.
   - 5 mutation and evasion strategies mapped with generation algorithms and header manipulations.
   - Exact CVSS v3.1 and CWE mappings specified (CWE-942 for CORS, CWE-693 for general security headers, CWE-1021 for XFO/frame-ancestors, CWE-525 for cache-control).
3. **Test Infrastructure & Mock Patterns Established**:
   - Standard mock HTTP client class (`MockCORSHttpClient`) modeled after `MockCacheHttpClient` and `MockSSTIHttpClient`.
   - Support for synchronous and async execution flows, simulating custom `Origin`, `Access-Control-*`, and response headers.
   - Zero-external-dependency requirement compliant (standard library only + internal Argus abstractions).

---

## Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | R1: Collector Core | `CORSSecurityCollector` (BaseCollector) | Active collector discovering candidate endpoints and executing CORS probing + Security Header auditing. | `mission` object (`endpoints`, `live_hosts`, `target`, `evidence`) | `List[Evidence]`, mutates `mission.vulnerabilities`, `mission.evidence`, `mission.attack_surface_graph`, calls `publish_finding` | Catches network/timeout exceptions, logs warnings, continues probing subsequent endpoints | `argus/collectors/base.py`, `argus/collectors/cache_security.py:1324-1518` |
| 2 | R1: HTTP Dispatch | `CORSProber` / `AuthenticatedHttpClient` | HTTP client wrapper sending crafted `Origin` and `Access-Control-*` headers with scope checks and authentication injection. | Target URL, HTTP Method (`GET`, `OPTIONS`), Headers (`Origin`, `Access-Control-Request-*`), optional cookies | `HttpResponse` (status_code, headers, body, elapsed, error) | Returns `HttpResponse(success=False, error=...)` on timeout/network error; blocks out-of-scope targets | `argus/http/client.py:300-508` |
| 3 | R2: CORS Mode 1 | Arbitrary Origin Reflection | Detects backend echoing untrusted attacker `Origin` in `Access-Control-Allow-Origin` (ACAO) with credentials enabled. | `Origin: https://evil.com` or `https://attacker.com` | `CORSProbeResult` (reflected=True, credentials=True, severity="high") | Ignores if origin is not echoed or credentials not allowed | `ORIGINAL_REQUEST.md` § R2.1 |
| 4 | R2: CORS Mode 2 | Null Origin Acceptance | Detects backend accepting `Origin: null` with credentials enabled (`ACAC: true`). | `Origin: null` | `CORSProbeResult` (null_allowed=True, credentials=True, severity="high") | Ignores if `null` is rejected or credentials false (unless sensitive endpoint) | `ORIGINAL_REQUEST.md` § R2.2 |
| 5 | R2: CORS Mode 3 | Wildcard with Credentials | Detects invalid/dangerous combination of `ACAO: *` and `ACAC: true`. | `Origin: https://evil.com` | `CORSProbeResult` (wildcard_creds=True, severity="critical") | Ignores standard wildcard without credentials on public resources | `ORIGINAL_REQUEST.md` § R2.3 |
| 6 | R2: CORS Mode 4 | Subdomain Trust Abuse | Detects overly broad trust of arbitrary subdomains (e.g. `*.target.com` trusting `attacker.target.com`). | `Origin: https://attacker.example.com` | `CORSProbeResult` (subdomain_abuse=True, severity="high" if creds else "medium") | Ignores if only legitimate configured subdomains are whitelisted | `ORIGINAL_REQUEST.md` § R2.4 |
| 7 | R2: CORS Mode 5 | Pre-flight Bypass & Misconfiguration | Probes `OPTIONS` responses for overly permissive methods (`*`, `DELETE`, `PUT`) or headers (`*`, arbitrary echo). | `OPTIONS` with `Access-Control-Request-Method/Headers` | `CORSProbeResult` (preflight_misconfig=True, severity="medium"/"high") | Ignores standard restricted method/header lists | `ORIGINAL_REQUEST.md` § R2.5 |
| 8 | R2: CORS Mode 6 | Origin Parser Differential | Detects parser flaws via prefix/suffix injection (`target.com.evil.com`, `evil-target.com`, URL encoding, protocol confusion). | `Origin: https://example.com.evil.com`, `http://example.com`, etc. | `CORSProbeResult` (parser_differential=True, severity="high") | Ignores if backend correctly enforces strict domain anchor parsing | `ORIGINAL_REQUEST.md` § R2.6 |
| 9 | R3: Header Audit 1 | Content-Security-Policy (CSP) | Detects missing CSP, `unsafe-inline`, `unsafe-eval`, wildcard sources (`*`, `http:`, `data:`), and missing `frame-ancestors`. | Response headers (`Content-Security-Policy`) | `HeaderAuditResult` (header="Content-Security-Policy", severity="medium") | No finding if strong CSP policy is present | `ORIGINAL_REQUEST.md` § R3 |
| 10 | R3: Header Audit 2 | Strict-Transport-Security (HSTS) | Detects missing HSTS on HTTPS, low `max-age < 31536000`, missing `includeSubDomains`, and missing `preload`. | Response headers (`Strict-Transport-Security`), URL scheme | `HeaderAuditResult` (header="Strict-Transport-Security", severity="low") | No finding if `max-age >= 31536000` and `includeSubDomains` present; suppressed on HTTP | `ORIGINAL_REQUEST.md` § R3 |
| 11 | R3: Header Audit 3 | X-Frame-Options (XFO) | Detects missing XFO (when CSP frame-ancestors absent) or misconfigured `ALLOW-FROM` without valid URI. | Response headers (`X-Frame-Options`, `Content-Security-Policy`) | `HeaderAuditResult` (header="X-Frame-Options", severity="medium") | No finding if `DENY`, `SAMEORIGIN`, or CSP `frame-ancestors` present | `ORIGINAL_REQUEST.md` § R3 |
| 12 | R3: Header Audit 4 | X-Content-Type-Options (XCTO) | Detects missing or invalid `nosniff` header preventing MIME-confusion attacks. | Response headers (`X-Content-Type-Options`) | `HeaderAuditResult` (header="X-Content-Type-Options", severity="low") | No finding if `nosniff` present | `ORIGINAL_REQUEST.md` § R3 |
| 13 | R3: Header Audit 5 | Referrer-Policy | Detects missing or dangerous policies (`unsafe-url`, `no-referrer-when-downgrade`). | Response headers (`Referrer-Policy`) | `HeaderAuditResult` (header="Referrer-Policy", severity="low"/"medium") | No finding if `strict-origin-when-cross-origin`, `no-referrer`, `same-origin` present | `ORIGINAL_REQUEST.md` § R3 |
| 14 | R3: Header Audit 6 | Permissions-Policy | Detects missing or overly permissive permissions policies allowing unconstrained camera/microphone/geolocation. | Response headers (`Permissions-Policy`, `Feature-Policy`) | `HeaderAuditResult` (header="Permissions-Policy", severity="low") | No finding if features are properly constrained or disabled | `ORIGINAL_REQUEST.md` § R3 |
| 15 | R3: Header Audit 7 | X-XSS-Protection | Detects explicitly disabled `0` or missing protection on legacy endpoints. | Response headers (`X-XSS-Protection`) | `HeaderAuditResult` (header="X-XSS-Protection", severity="info"/"low") | Flagged only when appropriate; suppressed if strong CSP exists | `ORIGINAL_REQUEST.md` § R3 |
| 16 | R3: Header Audit 8 | Cache-Control on Sensitive Endpoints | Detects missing `no-store` or `no-cache` on authenticated/PII responses. | Response headers (`Cache-Control`, `Pragma`), status 200, endpoint path / auth context | `HeaderAuditResult` (header="Cache-Control", severity="medium"/"low") | Suppressed on public static assets (.css, .js, .png) or unauthenticated public endpoints | `ORIGINAL_REQUEST.md` § R3 |
| 17 | R4: Mutation 1 | Origin Casing Variations | Generates mixed-case scheme/host variations (e.g. `hTtPs://ExAmPlE.cOm`, header key `oRiGiN`). | Base Target URL | List of mutated `Origin` strings | Fallback to canonical origin | `ORIGINAL_REQUEST.md` § R4 |
| 18 | R4: Mutation 2 | Protocol Smuggling | Generates requests with mismatched/insecure protocols (`http://` for HTTPS targets, `file://`, `data:`, `null`). | Base Target URL | List of mutated protocol origins | Fallback to standard HTTP/HTTPS | `ORIGINAL_REQUEST.md` § R4 |
| 19 | R4: Mutation 3 | Subdomain Injection | Generates prefix/suffix/subdomain variations (`attacker.target.com`, `target.com.attacker.com`, `attacker-target.com`). | Base Target Host | List of crafted origins | Handles dotless TLDs and arbitrary nesting | `ORIGINAL_REQUEST.md` § R4 |
| 20 | R4: Mutation 4 | Header Duplication & Folding | Generates multiple `Origin` headers or comma-separated folded headers. | Target URL, headers dict | Multi-header / folded header request specifications | Gracefully handled by HTTP client / parser | `ORIGINAL_REQUEST.md` § R4 |
| 21 | R4: Mutation 5 | Pre-flight Enumeration | Generates systematic matrix of `OPTIONS` probes with standard, non-standard, and dangerous methods/headers. | Target URL | List of `OPTIONS` probe requests | Safe non-destructive HTTP verbs | `ORIGINAL_REQUEST.md` § R4 |
| 22 | R5: Pipeline Connectivity | Tool Registry Registration | Registers `Tool(id="cors_headers", ...)` with full capability aliases in `registry.py` and `PluginExecutorAdapter`. | Tool registry initialization | Tool object retrievable via `registry.get("cors_headers")` and aliases | Graceful fallback instantiation | `argus/runtime/registry.py:821`, `argus/runtime/plugins.py:170` |
| 23 | R5: DAG Task Scheduling | TaskGenerator DAG Wiring | Maps `cors_headers` task in `_TOOL_TEMPLATES` with dependency on `Discover API Endpoints`. | Discovered endpoints gap | Generates DAG Task for CORS & Security Headers | Falls back to generic evidence correlation | `argus/planning/task_generator.py:254` |
| 24 | R5: Attack Surface Graph | Graph Node & Edge Ingestion | Connects `live_host`, `endpoint`, and `vulnerability` nodes with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges. | `Evidence(category="cors" | "security_headers")` | Populated `KnowledgeGraph` with `HAS_VULNERABILITY` edges | Deduplicates existing nodes/edges | `argus/graph/attack_surface.py:1208` |
| 25 | R5: CVSS / CWE Mapping | CWE-942, CWE-693, CWE-1021 | Maps CORS to CWE-942, Security Headers to CWE-693, Clickjacking to CWE-1021, and calibrates CVSS 3.1 base scores. | Category string + severity | `CVSSData` (score, vector, rating), `CWEInfo` (id, name) | Defaults to CWE-699 for unrecognized categories | `argus/reporting/cvss.py:33-180` |

---

## Edge Cases

| # | Feature | Input | Observed / Specified Behavior |
|---|---------|-------|-------------------------------|
| 1 | CORS False Positive Rejection | `ACAO: https://example.com` on `https://example.com` (Same-Origin reflection) | Suppressed (NO finding emitted). Same-origin reflection is standard and safe. |
| 2 | CORS False Positive Rejection | `ACAO: *` and `ACAC: false` (or omitted) on public unauthenticated API | Suppressed (NO finding emitted). Wildcard without credentials on public API is valid open CORS per spec. |
| 3 | CORS Origin Reflection | `Origin: https://evil.com` -> `ACAO: https://evil.com` + `ACAC: true` | Generated finding with severity **High**, title "CORS Misconfiguration: Arbitrary Origin Reflection with Credentials", CWE-942. |
| 4 | CORS Null Origin | `Origin: null` -> `ACAO: null` + `ACAC: true` | Generated finding with severity **High**, title "CORS Misconfiguration: Insecure Null Origin Allowed with Credentials", CWE-942. |
| 5 | CORS Wildcard + Creds | `ACAO: *` + `ACAC: true` | Generated finding with severity **Critical** (CVSS score 9.8), title "CORS Misconfiguration: Wildcard Origin Allowed with Credentials", CWE-942. |
| 6 | CORS Subdomain Abuse | `Origin: https://attacker.example.com` -> `ACAO: https://attacker.example.com` + `ACAC: true` | Generated finding with severity **High**, title "CORS Misconfiguration: Overly Broad Subdomain Trust Abuse", CWE-942. |
| 7 | CORS Parser Differential | `Origin: https://example.com.evil.com` -> `ACAO: https://example.com.evil.com` + `ACAC: true` | Generated finding with severity **High**, title "CORS Misconfiguration: Origin Parser Differential / Suffix Injection", CWE-942. |
| 8 | CORS Case Sensitivity | Header in response: `access-control-allow-origin: https://evil.com` (lowercase) | Normalized via case-insensitive dictionary lookup; correctly detected as finding. |
| 9 | CSP Analysis | `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'` | Generated finding with severity **Medium**, title "Weak Content-Security-Policy: Unsafe Inline Script Execution Allowed", CWE-693. |
| 10 | CSP Wildcard | `Content-Security-Policy: default-src *` | Generated finding with severity **Medium**, title "Weak Content-Security-Policy: Wildcard Source Allowed", CWE-693. |
| 11 | CSP Multi-Header | Multiple `Content-Security-Policy` headers returned (comma-separated or multiple entries) | Parsed cumulatively according to CSP specification (each policy must be satisfied). |
| 12 | HSTS Compliance | `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` | Valid compliance: NO finding emitted. |
| 13 | HSTS Low Max-Age | `Strict-Transport-Security: max-age=86400` (< 31536000 seconds) | Generated finding with severity **Low**, title "Weak Strict-Transport-Security: Low Max-Age", CWE-693. |
| 14 | HSTS on Plain HTTP | Plain `http://example.com` endpoint without HSTS | HSTS audit suppressed or flagged only as Info (HSTS is strictly an HTTPS header). |
| 15 | XFO vs CSP frame-ancestors | `X-Frame-Options` missing, but `Content-Security-Policy: frame-ancestors 'self'` present | Suppressed or downgraded to Info because CSP `frame-ancestors` supersedes X-Frame-Options in modern browsers. |
| 16 | XFO Misconfigured | `X-Frame-Options: ALLOW-FROM` (no URI specified) | Generated finding with severity **Medium**, title "Misconfigured X-Frame-Options Header", CWE-1021. |
| 17 | XCTO Missing | Missing `X-Content-Type-Options: nosniff` on HTML/JSON response | Generated finding with severity **Low**, title "Missing X-Content-Type-Options Header", CWE-693. |
| 18 | Referrer-Policy Safe | `Referrer-Policy: strict-origin-when-cross-origin` | Valid compliance: NO finding emitted. |
| 19 | Referrer-Policy Unsafe | `Referrer-Policy: unsafe-url` | Generated finding with severity **Medium**, title "Weak Referrer-Policy: Unsafe URL Leaking Full Path and Query Parameters", CWE-693. |
| 20 | Cache-Control Public Asset | Missing `no-store` on `https://example.com/static/style.css` (status 200, static file) | Suppressed: static assets are intentionally cacheable. |
| 21 | Cache-Control Sensitive API | Missing `no-store` on `https://example.com/api/v1/user/profile` (authenticated JSON response with user data) | Generated finding with severity **Medium**, title "Sensitive Endpoint Cacheable: Missing Cache-Control no-store", CWE-525 / CWE-693. |
| 22 | HTTP Client Network Error | Endpoint connection times out or resets during CORS probe | Prober catches `httpx.TimeoutException` / `ConnectionError`, returns `HttpResponse(success=False, error=...)`, logs warning, and does NOT crash scan. |
| 23 | Scope Enforcement | Target URL is outside authorized mission scope | `AuthenticatedHttpClient` blocks request before transmission, returns `HttpResponse(success=False, error="Blocked by scope")`, 0 packets sent. |

---

## Detailed Requirements Mapping & Architectural Analysis

### 1. Test Suite Layout & Fixture Architecture

#### Existing Layout (`tests/` directory):
- `tests/collectors/`: Houses all 20+ collector test suites and adversarial suites (e.g., `test_cache_security.py`, `test_ssti.py`, `test_race_conditions.py`, `test_graphql.py`).
- `tests/http/`: Tests for `AuthenticatedHttpClient`, `AuthorizedHttpClient`, scope gating, and session cookie lifecycle (`test_authenticated_http_client.py`).
- `tests/planning/`: Tests for `TaskGenerator`, DAG task resolution, coverage gap mapping (`test_task_generator.py`).
- `tests/runtime/`: Tests for `ToolRegistry`, `PluginExecutorAdapter`, `Mission`, `ControlledMission` (`test_registry.py`, `test_plugins.py`).
- `tests/reporting/`: Tests for `CVSSCalculator`, `EvidenceProcessor`, CWE resolution (`test_cvss.py`).
- `tests/graph/`: Tests for `KnowledgeGraph`, `AttackSurfaceGraphBuilder`, `Node`, `Edge` (`test_graph.py`, `test_attack_surface.py`).

#### Mock HTTP Client Pattern:
All modern ARGUS collector test suites use in-memory mock HTTP clients that conform to the `AuthenticatedHttpClient` interface:
```python
class MockCORSHttpClient:
    """Mock HTTP client simulating CORS pre-flight, origin responses, and security headers."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, Dict[str, str], str]]] = None):
        # Key format: f"{method}:{url}:{origin_header}" or f"{method}:{url}"
        self.routes: Dict[str, Tuple[int, Dict[str, str], str]] = dict(routes or {})
        self.request_log: List[Dict[str, Any]] = []

    def set_route(self, method: str, url: str, origin: str, status_code: int, headers: Dict[str, str], body: str = ""):
        key = f"{method.upper()}:{url}:{origin}"
        self.routes[key] = (status_code, headers, body)

    def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> HttpResponse:
        req_headers = {k.lower(): str(v) for k, v in (headers or {}).items()}
        origin = req_headers.get("origin", "")
        self.request_log.append({"method": method, "url": url, "headers": req_headers})

        # 1. Exact match with method + url + origin
        exact_key = f"{method.upper()}:{url}:{origin}"
        if exact_key in self.routes:
            sc, rh, body = self.routes[exact_key]
            return HttpResponse(success=(200 <= sc < 400), status_code=sc, headers=rh, body=body, raw_body=body, url=url)

        # 2. Match with method + url
        method_url_key = f"{method.upper()}:{url}"
        if method_url_key in self.routes:
            sc, rh, body = self.routes[method_url_key]
            return HttpResponse(success=(200 <= sc < 400), status_code=sc, headers=rh, body=body, raw_body=body, url=url)

        # 3. Default fallback response
        return HttpResponse(success=True, status_code=200, headers={}, body="OK", raw_body="OK", url=url)

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> HttpResponse:
        return self.request("GET", url, headers=headers, **kwargs)

    def options(self, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> HttpResponse:
        return self.request("OPTIONS", url, headers=headers, **kwargs)
```

---

### 2. Exact Header Specifications & Parsing Logic

#### A. Case-Insensitive Header Normalization
All HTTP header parsing must operate on case-insensitive dictionaries. When checking response headers:
```python
def normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {k.lower().strip(): v.strip() for k, v in headers.items()}
```

#### B. CORS Response Header Specifications (RFC 6454 / Fetch Spec):
1. `access-control-allow-origin`:
   - Value is either `*`, `null`, or a single specific origin: `<scheme>://<host>[:<port>]`.
   - Cannot contain multiple origins separated by spaces or commas according to Fetch specification.
2. `access-control-allow-credentials`:
   - Value must be literally `"true"` (case-sensitive string according to spec, but checked case-insensitively for robustness).
   - If missing or `"false"`, credentials are not allowed.
3. `access-control-allow-methods`:
   - Comma-separated list of permitted HTTP methods: `GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH`.
4. `access-control-allow-headers`:
   - Comma-separated list of permitted request headers: `*`, `Content-Type, Authorization, X-Requested-With, X-Custom-Header`.
5. `access-control-max-age`:
   - Integer number of seconds pre-flight results can be cached (e.g. `86400`).
6. `vary`:
   - Must contain `Origin` if the server dynamically reflects or selectively allows origins based on the request `Origin` header.

#### C. HTTP Security Header Specifications:
1. `Content-Security-Policy`:
   - Directives separated by semicolons `;`.
   - Directive name followed by space-separated source list: `<directive-name> <source-expression> ...`
   - Key directives to parse:
     - `default-src`, `script-src`, `script-src-elem`, `style-src`, `connect-src`, `object-src`, `frame-ancestors`, `base-uri`.
   - Weakness checks:
     - `'unsafe-inline'` in `script-src` / `default-src`
     - `'unsafe-eval'` in `script-src` / `default-src`
     - `*` or `http:` or `data:` in `script-src` / `default-src` / `connect-src`
     - Absence of `frame-ancestors`
     - Absence of `object-src 'none'`
2. `Strict-Transport-Security`:
   - Directives: `max-age=<seconds>`, `includeSubDomains`, `preload`.
   - Threshold: `max-age >= 31536000` (1 year).
   - Evaluated only for HTTPS endpoints (ignored or marked info for plain HTTP).
3. `X-Frame-Options`:
   - Valid values: `DENY`, `SAMEORIGIN`.
   - Invalid / Deprecated: `ALLOW-FROM <uri>` or missing.
   - Superseded when CSP `frame-ancestors` is present.
4. `X-Content-Type-Options`:
   - Must be `nosniff`. Any other value or missing header is flagged.
5. `Referrer-Policy`:
   - Safe values: `no-referrer`, `same-origin`, `strict-origin`, `strict-origin-when-cross-origin`.
   - Permissive / Unsafe: `unsafe-url`, `no-referrer-when-downgrade`.
6. `Permissions-Policy`:
   - Directives: `<feature>=(<allowlist>)` (e.g. `camera=(), microphone=(), geolocation=(self)`).
   - Flagged if missing or if dangerous features (`camera`, `microphone`, `geolocation`, `payment`) are set to `*`.
7. `X-XSS-Protection`:
   - Flagged if explicitly `0` (disabled) or missing on legacy endpoints without CSP.
8. `Cache-Control` on Sensitive Endpoints:
   - Sensitive endpoints determined by: authenticated request, path keywords (`/api/`, `/user`, `/account`, `/auth`, `/profile`, `/token`, `/admin`, `/checkout`, `/cart`), or `Set-Cookie` / JSON response containing sensitive keys.
   - Must contain `no-store` or `no-cache, private`. Flagged if `public`, missing, or cacheable with `max-age > 0` without `no-store`.

---

## 5-Component Handoff Report

### 1. Observation
- **Test Baseline Execution**:
  Command: `python -m pytest tests/ --ignore=tests/workspace -x -q`
  Output: `1740 passed, 30682 warnings in 70.48s (0:01:10)` (Exit code: 0).
  Confirmed 1,740 passing tests with zero test regressions.
- **Base Collector Architecture**:
  Inspected `/home/varun/argus/argus/collectors/base.py:1-10`. `BaseCollector` defines `@abstractmethod def collect(self, mission)`.
  Inspected `/home/varun/argus/argus/collectors/cache_security.py:1324-1523` and `ssti.py:500-670`. Collectors implement `collect(mission)` and alias `execute(mission)`, performing discovery, prober orchestration, and Quadruple State Publishing.
- **HTTP Client Architecture**:
  Inspected `/home/varun/argus/argus/http/client.py:72-85` (`HttpResponse`), lines `300-508` (`AuthenticatedHttpClient`). Supports `request()`, `get()`, `post()`, `options()`, session cookie tracking, `ScopeResolver` boundary enforcement, and credentials injection.
- **Tool Registry Architecture**:
  Inspected `/home/varun/argus/argus/runtime/registry.py:821-855`. Tools registered with `Tool(id=..., name=..., capability=..., capabilities=[...], supported_tasks=[...], required_inputs=["endpoints"], produced_outputs=["vulnerabilities", "observations", "evidence"])`.
- **Plugin Fallback Architecture**:
  Inspected `/home/varun/argus/argus/runtime/plugins.py:170-214`. `PluginExecutorAdapter._instantiate_specialist_fallback()` instantiates specialist collectors based on plugin key matching.
- **TaskGenerator DAG Architecture**:
  Inspected `/home/varun/argus/argus/planning/task_generator.py:80-265`. Task templates registered in `_TOOL_TEMPLATES` with dependencies on `["Discover API Endpoints"]`.
- **Attack Surface Graph Architecture**:
  Inspected `/home/varun/argus/argus/graph/attack_surface.py:1208-1276`. Ingests evidence records, builds `Node(type="live_host")`, `Node(type="endpoint")`, `Node(type="vulnerability")`, and creates `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
- **CVSS & CWE Database**:
  Inspected `/home/varun/argus/argus/reporting/cvss.py:33-180` and lines `372-440`. Maps `cors` to `CWE-942`. Currently missing explicit `CWE-693` ("Protection Mechanism Failure") and `CWE-1021` ("Clickjacking / UI Redressing") in `CWE_DATABASE`.

### 2. Logic Chain
1. **Collector Architecture Compliance**: Since all 20+ collectors in ARGUS follow the tripartite pattern (`CORSSecurityCollector`, `CORSProber`/`HeaderAuditor`, `CORSAnalyzer`/`CORSMutationGenerator`), implementing the CORS and HTTP security header module as a monolithic cohesive file `argus/collectors/cors_headers.py` inheriting from `BaseCollector` guarantees full compliance with the Argus execution engine.
2. **Mockability & Isolation**: Implementing `CORSProber` and `HeaderAuditor` with an optional `http_client` argument allows unit and adversarial test suites (`tests/collectors/test_cors_headers.py`) to inject fast, deterministic `MockCORSHttpClient` instances without needing live network access or spinning up background daemon servers during benchmark mode.
3. **Multi-Vector Precision**: By structuring CORS detection into 6 explicit vector types (`ORIGIN_REFLECTION`, `NULL_ORIGIN_ALLOWED`, `WILDCARD_WITH_CREDENTIALS`, `SUBDOMAIN_TRUST_ABUSE`, `PREFLIGHT_BYPASS`, `ORIGIN_PARSER_DIFFERENTIAL`) and verifying both the `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` headers simultaneously, false positives (such as legitimate same-origin reflection or public wildcard APIs) are eliminated while critical misconfigurations are reliably captured.
4. **Security Header Thoroughness**: By auditing 8 distinct HTTP security headers with granular directive parsers (e.g., distinguishing weak CSP `'unsafe-inline'` from missing CSP, and evaluating HSTS `max-age` against the 31,536,000 second threshold with `includeSubDomains`), findings are accurately classified by severity (Medium for missing CSP / clickjacking, Low for missing XCTO / Referrer-Policy / HSTS).
5. **Mutation Strategy Execution**: By generating at least 5 distinct mutation strategies (`ORIGIN_CASING`, `PROTOCOL_SMUGGLING`, `SUBDOMAIN_INJECTION`, `HEADER_DUPLICATION`, `PREFLIGHT_ENUMERATION`), the prober can uncover edge-case WAF bypasses and parser differentials across complex proxy topologies.
6. **Pipeline & Graph Integrity**: Wiring `cors_headers` into `registry.py`, `plugins.py`, `task_generator.py`, `engine.py`, `attack_surface.py`, and `cvss.py` ensures that findings properly transition into `HAS_VULNERABILITY` edges in the `KnowledgeGraph` and receive standardized CVSS 3.1 scoring with CWE-942, CWE-693, and CWE-1021.

### 3. Caveats
- **Plain HTTP vs HTTPS Context**: HSTS checks must only trigger for HTTPS endpoints; auditing an unencrypted `http://` endpoint for missing HSTS without flagging it as an HTTPS-specific requirement would introduce false positives.
- **CSP vs X-Frame-Options Precedence**: Modern user agents prioritize CSP `frame-ancestors` over `X-Frame-Options`. If a response has a strong `Content-Security-Policy: frame-ancestors 'self'` directive but omits `X-Frame-Options`, the missing XFO finding should be suppressed or categorized as informational.
- **Dynamic Port Binding**: Any integration test utilizing real HTTP servers must bind to port 0 (`find_free_port()`) to prevent port collision failures during concurrent test execution.

### 4. Conclusion
The specification and architecture for the CORS Misconfiguration & HTTP Security Header Audit Module are fully mapped and ready for implementation.
- All 1,740 baseline tests pass cleanly.
- Implementing `argus/collectors/cors_headers.py` and wiring it into the 6 integration points (`__init__.py`, `registry.py`, `plugins.py`, `task_generator.py`, `engine.py`, `attack_surface.py`, `cvss.py`) with 25+ comprehensive unit and integration tests in `tests/collectors/test_cors_headers.py` will satisfy all requirements R1–R6 with zero regressions.

### 5. Verification Method
1. **Verify Baseline & New Tests**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   *Expected*: 1,765+ passed (1,740 baseline + 25+ new tests), 0 failures, exit code 0.
2. **Verify Module-Specific Unit Tests**:
   ```bash
   python -m pytest tests/collectors/test_cors_headers.py -v
   ```
   *Expected*: All CORS detection modes, header audit rules, mutation strategies, and pipeline connectivity tests pass.
3. **Verify Pipeline Registration**:
   ```bash
   python -c "from argus.runtime.registry import registry; assert registry.get('cors_headers') is not None"
   python -c "from argus.collectors import CORSSecurityCollector; assert CORSSecurityCollector is not None"
   ```
4. **Verify Graph Integration**:
   ```bash
   python -c "from argus.graph.attack_surface import AttackSurfaceGraphBuilder; from argus.evidence.model import Evidence; g = AttackSurfaceGraphBuilder().build_from_evidence([Evidence(category='cors', value='https://example.com', title='CORS Reflection')]); assert len(g.edges_by_type('HAS_VULNERABILITY')) > 0"
   ```
