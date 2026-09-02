# Specification & Architecture Report: Web Cache Poisoning & Web Cache Deception Detection Module

**Sprint:** 23 — Web Cache Security (Poisoning & Deception)  
**Agent:** survey_spec_miner (teamwork_preview_spec_miner)  
**Target Workspace:** `/home/varun/argus`  
**Date:** 2026-09-01  
**Baseline Test Suite:** 1,648 passed, 0 failed  

---

## 1. Observation

Direct inspection of the ARGUS codebase (`/home/varun/argus`) and architectural contracts reveals the following foundational components and integration points:

1. **Collector Architecture Pattern (`BaseCollector` & Tripartite Separation):**
   - Existing collectors (e.g. `argus/collectors/ssti.py`, `argus/collectors/race_conditions.py`, `argus/collectors/request_smuggling.py`, `argus/collectors/business_logic.py`) inherit from `BaseCollector` (`argus/collectors/base.py`) and implement `collect(mission) -> List[Evidence]`.
   - Production collectors follow a modular tripartite design:
     - **Payload Generator (`CacheSecurityPayloadGenerator`):** Constructs parameter matrices, unkeyed headers, path manipulation vectors, delimiter variations, FAT GET bodies, and randomized cache busters.
     - **Prober (`CacheSecurityProber`):** Wraps `AuthenticatedHttpClient` (`argus/http/client.py`) to execute structured differential multi-stage HTTP request sequences (baseline $\to$ perturbed $\to$ replay $\to$ control) with millisecond-precision timing and header inspection.
     - **Security Analyzer (`CacheSecurityAnalyzer`):** Evaluates cache status transitions, detects reflected canary tokens in cached responses, detects sensitive PII leakage in static file caches, fingerprints CDN/cache proxies, and applies strict false-positive rejection filters.

2. **HTTP Client Capabilities (`AuthenticatedHttpClient` & `HttpResponse`):**
   - `AuthenticatedHttpClient` provides authorization gating (`AuthDecision`), scope resolution (`ScopeDecision`), request/response header sanitization, cookie handling, custom header injection, and proxy/SSL handling.
   - `HttpResponse` provides `.status_code`, `.headers` (case-insensitive dictionary), `.body`, `.raw_body`, `.elapsed`, `.url`, `.method`, and `.success`.

3. **Attack Surface Graph & Evidence Pipeline:**
   - Evidence model (`argus/evidence/model.py`) uses `Evidence(category="cache_security", value=..., source="cache_security", status="CONFIRMED", confidence=1.0, severity="high"|"critical", provenance=ProvenanceData(...), metadata={...})`.
   - Graph expansion (`argus/graph/attack_surface.py` and `argus/graph/node.py`) creates nodes `live_host`, `endpoint`, and `vulnerability`, connecting them with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
   - Task DAG generation (`argus/planning/task_generator.py`) defines tasks in `_RECON_TEMPLATES` with category `TaskCategory.EVIDENCE_CORRELATION`, dependencies `["Discover API Endpoints"]`, required inputs `["endpoints"]`, and produced outputs `["vulnerabilities", "observations", "evidence"]`.
   - Tool registry (`argus/runtime/registry.py`) and plugin adapter (`argus/runtime/plugins.py`) dynamically register and instantiate collectors based on tool IDs and aliases.
   - CVSS reporting (`argus/reporting/cvss.py`) calculates standardized CVSS v3.1 scores and maps CWE identifiers (`CWE-444`, `CWE-524`, `CWE-525`, `CWE-79`, `CWE-200`).

---

## 2. Logic Chain

### 2.1 Threat Model & Vulnerability Mechanics

Web caching layers (CDNs, reverse proxies, load balancers, Varnish, Nginx, Apache Traffic Server) optimize bandwidth and latency by serving stored HTTP responses for requests matching a computed **Cache Key**. 

A standard cache key is typically constructed as:
$$\text{CacheKey} = (\text{HTTP Method}, \text{Host Header}, \text{Request URI Path})$$

Vulnerabilities arise when there is an **asymmetry or parser differential** between the caching layer and the backend application server:

```
+-----------------------------------------------------------------------------------------------+
|                                      WEB CACHE POISONING                                      |
|                                                                                               |
|  Attacker Request (with Cache Buster C_1):                                                    |
|  GET /page?cb=C_1 HTTP/1.1                                                                    |
|  Host: target.com                                                                             |
|  X-Forwarded-Host: evil-canary.argus-security.com --------------------+                       |
|                                                                       |                       |
|         |                                                             |                       |
|         v                                                             v                       |
|  +-------------------+  Key = GET target.com /page?cb=C_1       +--------------------------+  |
|  | CDN / Cache Proxy | ---------------------------------------> | Application Backend      |  |
|  | (Ignores X-F-H in |                                          | (Reflects X-F-H into     |  |
|  |  Cache Key)       | <--------------------------------------- |  <script src="...">)     |  |
|  +-------------------+   200 OK (Cache-Control: public, s-maxage) +--------------------------+  |
|         |                Body: <script src="//evil-canary.../a.js">                           |
|         | Stores in Cache                                                                     |
|         v                                                                                     |
|  Victim / Verification Request (with SAME Cache Buster C_1, NO Headers):                      |
|  GET /page?cb=C_1 HTTP/1.1                                                                    |
|  Host: target.com (NO X-Forwarded-Host header!)                                               |
|         |                                                                                     |
|         v                                                                                     |
|  +-------------------+                                                                        |
|  | CDN / Cache Proxy | ===> Returns CACHED POISONED RESPONSE (X-Cache: HIT, Age > 0)           |
|  +-------------------+      Body: <script src="//evil-canary.../a.js"> (EXPLOITATION VERIFIED) |
+-----------------------------------------------------------------------------------------------+

+-----------------------------------------------------------------------------------------------+
|                                      WEB CACHE DECEPTION                                      |
|                                                                                               |
|  Authenticated User / Attacker Probing Request:                                               |
|  GET /account/settings/nonexistent.css?cb=C_1 HTTP/1.1                                        |
|  Cookie: session=xyz (Authenticated Session)                                                  |
|                                                                                               |
|         |                                                                                     |
|         v                                                                                     |
|  +-------------------+  Static Asset Rule (*.css => CACHE)     +--------------------------+  |
|  | CDN / Cache Proxy | ---------------------------------------> | Application Backend      |  |
|  | (Caches *.css)    |                                          | (Origin ignores trailing |  |
|  |                   | <--------------------------------------- |  /nonexistent.css and    |  |
|  +-------------------+   200 OK (Returns sensitive user JSON)   |  returns PII/Secrets)    |  |
|         |                Body: {"email":"user@victim.com",...}  +--------------------------+  |
|         | Publicly Stores Sensitive Body in Cache Key (*.css)                                 |
|         v                                                                                     |
|  Unauthenticated Attacker Request:                                                            |
|  GET /account/settings/nonexistent.css?cb=C_1 HTTP/1.1                                        |
|  (NO Cookies, NO Authorization Header)                                                        |
|         |                                                                                     |
|         v                                                                                     |
|  +-------------------+                                                                        |
|  | CDN / Cache Proxy | ===> Returns CACHED AUTHENTICATED PII (X-Cache: HIT, 200 OK)           |
|  +-------------------+      Body: {"email":"user@victim.com", "token":"..."} (PII LEAKED)     |
+-----------------------------------------------------------------------------------------------+
```

---

## 3. Detailed Requirements & Technical Specifications

### 3.1 R1: Cache Security Collector & Prober Architecture

#### 3.1.1 Class Hierarchy & Component Interaction
The module must be implemented under `argus/collectors/cache_security.py` adhering to the following class structure:

1. **`CacheSecurityCollector(BaseCollector)`:**
   - Orchestrates endpoint discovery from mission data.
   - Instantiates `CacheSecurityPayloadGenerator`, `CacheSecurityProber`, and `CacheSecurityAnalyzer`.
   - Iterates through candidate endpoints, executes active multi-vector probes, verifies findings via multi-step confirmation, suppresses false positives, and executes Quadruple State Publishing.

2. **`CacheSecurityPayloadGenerator`:**
   - Generates payloads across all 5 detection vectors and 5 mutation strategies.
   - Provides methods:
     - `generate_unkeyed_header_probes(base_url, canary)`
     - `generate_unkeyed_param_probes(base_url, canary)`
     - `generate_cache_deception_probes(base_url, authenticated_endpoints)`
     - `generate_normalization_flaw_probes(base_url, canary)`
     - `generate_fingerprint_probes(base_url)`
     - `apply_mutation_strategy(probe, strategy)`

3. **`CacheSecurityProber`:**
   - Wraps `AuthenticatedHttpClient` (or injected mock HTTP client for testing).
   - Manages cache buster nonce generation (`uuid.uuid4().hex[:12]`, millisecond timestamps).
   - Implements sequential request execution with microsecond latency recording.
   - Implements the 4-Step Sequential Differential Confirmation Pipeline:
     - `measure_baseline(url, cache_buster)`
     - `execute_perturbation_probe(probe, cache_buster)`
     - `execute_replay_verification(url, cache_buster)`
     - `execute_isolation_control(url, fresh_cache_buster)`

4. **`CacheSecurityAnalyzer`:**
   - Parses HTTP status codes, headers, and bodies across the 4-step sequence.
   - Evaluates cache lifecycle status (`HIT`, `MISS`, `Age` progression, `Cache-Control`).
   - Identifies reflection points (HTML tags, script URLs, redirect `Location`, JSON values).
   - Inspects response bodies for sensitive PII and authentication credentials during Web Cache Deception analysis.
   - Computes CVSS v3.1 scores and assigns CWE classifications (`CWE-444`, `CWE-524`, `CWE-525`, `CWE-79`, `CWE-200`).

---

### 3.2 R2: Multi-Vector Detection Modes

```
+----------------------------------------------------------------------------------------------------+
|                                    MULTI-VECTOR DETECTION MODES                                    |
+------------------------------------+---------------------------------------------------------------+
| Mode 1: Unkeyed Header Poisoning   | Injects unkeyed reverse proxy/host headers to reflect canary  |
|                                    | or alter response logic, cached under public request key.     |
+------------------------------------+---------------------------------------------------------------+
| Mode 2: Unkeyed Parameter &        | Probes unkeyed query parameters (UTM, JSONP) and parser       |
|         Parameter Cloaking         | discrepancies (?, ;, %26, %23) ignored by cache keys.         |
+------------------------------------+---------------------------------------------------------------+
| Mode 3: Web Cache Deception (WCD)  | Manipulates path extensions and delimiters on sensitive auth  |
|                                    | endpoints to force public CDN caching of authenticated PII.   |
+------------------------------------+---------------------------------------------------------------+
| Mode 4: Normalization Flaws        | Tests FAT GET request bodies, method overrides (X-HTTP-Method)|
|                                    | and duplicate header folding ignored by cache key generation. |
+------------------------------------+---------------------------------------------------------------+
| Mode 5: Cache Lifecycle & CDN      | Detects cache status headers (X-Cache, CF-Cache-Status, Age)   |
|         Fingerprinting             | and fingerprints CDN/proxy engines (Cloudflare, Varnish, ATS).|
+------------------------------------+---------------------------------------------------------------+
```

#### 3.2.1 Mode 1: Unkeyed Header Poisoning Matrix

| # | Header Name | Probe Value Format | Target Impact / Observable Behavior | Severity |
|---|-------------|--------------------|--------------------------------------|----------|
| 1 | `X-Forwarded-Host` | `<canary>.argus-security.com` | Reflected in `<script src="...">`, `<link href="...">`, OpenGraph `og:url`, or 301/302 `Location` header cached for all users. | Critical |
| 2 | `X-Forwarded-Scheme` | `http` (when targeting HTTPS) | Triggers 301/302 redirect loop `Location: https://target.com/` cached on origin URL, causing Denial of Service or insecure resource loading. | High |
| 3 | `X-Forwarded-Proto` | `http` | Same as `X-Forwarded-Scheme`; forces redirect or mixed-content script inclusion. | High |
| 4 | `X-Original-URL` | `/admin` or `/<canary_path>` | Overrides origin path while reverse proxy caches response under requested public URL, serving unauthorized backend routes. | Critical |
| 5 | `X-Rewrite-URL` | `/admin` or `/<canary_path>` | Overrides origin route in IIS/ASP.NET/Nginx environments while front-end caches under benign URL. | Critical |
| 6 | `X-Host` | `<canary>.argus-security.com` | Alternative host header evaluated by legacy frameworks, poisoning link generation. | High |
| 7 | `Forwarded` | `host=<canary>.argus-security.com;proto=http` | RFC 7239 standard forwarding header parsed by modern backends but unkeyed by legacy cache proxies. | High |
| 8 | `X-Forwarded-Prefix` | `//<canary>.argus-security.com` | Prepends canary domain to generated asset paths (`<link href="//canary/static/app.css">`). | Critical |
| 9 | `X-Forwarded-Port` | `1337` | Injected into generated redirects or canonical URLs (`https://target.com:1337/`). | Medium |
| 10 | `X-HTTP-Host-Override` | `<canary>.argus-security.com` | Evaluated by certain PHP and Java frameworks to construct absolute URLs. | High |
| 11 | `Base-Url` | `https://<canary>.argus-security.com/` | Framework base URL override reflected in `<base href="...">`. | Critical |
| 12 | `X-ProxyUser-Ip` / `X-Real-IP` | `<canary_ip>` | Reflected in debug headers or access control error responses cached publicly. | Medium |

#### 3.2.2 Mode 2: Unkeyed Query Parameter Poisoning & Parameter Cloaking Matrix

| # | Technique | Syntax / Payload Structure | Parser Mechanism & Detection Logic | Severity |
|---|-----------|----------------------------|-----------------------------------|----------|
| 1 | **Unkeyed Analytics Parameter** | `?utm_source=<canary>`, `?utm_content=<canary>`, `?fbclid=<canary>`, `?gclid=<canary>`, `?_ga=<canary>` | CDN strips tracking params from cache key ($K = \text{Path}$), but backend reflects parameter into page body or JSON response. | High |
| 2 | **Unkeyed JSONP / Callback** | `?callback=<canary>`, `?cb=<canary>`, `?jsonp=<canary>` | Endpoint serves JSONP; cache ignores `callback` parameter in key, caching attacker's function name or XSS vector for all users. | Critical |
| 3 | **Parameter Cloaking (Double Question Mark)** | `?keyed_param=1?unkeyed_param=<canary>` | Cache treats `?keyed_param=1?unkeyed_param=...` as a single parameter name, while backend query parser splits at second `?`, processing `unkeyed_param`. | High |
| 4 | **Parameter Cloaking (Semicolon Delimiter)** | `?keyed_param=1;unkeyed_param=<canary>` | Java (Spring/Tomcat) and Ruby/Python treat `;` as query delimiter (`&`), while CDN/cache ignores content after `;` or treats as part of value. | High |
| 5 | **Parameter Cloaking (URL-Encoded Delimiters)** | `?keyed_param=1%26unkeyed_param=<canary>` | Reverse proxy parses `%26` as literal character in cache key, while backend decodes URL before parsing query parameters. | High |
| 6 | **Hash Delimiter Cloaking** | `?unkeyed=<canary>%23keyed=1` | Cache engine keys on full string; backend or downstream proxy truncates query string at `#` (`%23`), creating cache key mismatch. | High |
| 7 | **HTTP Parameter Pollution (HPP)** | `?param=clean&param=<canary>` | Cache keys on first occurrence (`clean`), backend processes second occurrence (`canary`) and reflects it in response. | High |

#### 3.2.3 Mode 3: Web Cache Deception (WCD) Matrix

| # | Probe Path Pattern | Delimiter / Extension | Target Endpoint Type | Detection Oracle & Verification Criteria | Severity |
|---|--------------------|-----------------------|----------------------|-----------------------------------------|----------|
| 1 | `/account/settings/nonexistent.css` | Trailing path + `.css` | Authenticated Profile / Settings | Origin returns 200 OK with User PII (`email`, `api_key`); CDN caches response under static `.css` rule (`X-Cache: HIT`). Unauthenticated replay retrieves PII. | High |
| 2 | `/api/user;test.js` | Semicolon matrix param + `.js` | User Profile JSON API | Spring/Java backend ignores matrix param `;test.js` and returns user data; CDN caches under `.js` script rule. | High |
| 3 | `/api/v1/me/avatar.png` | Fake subpath + `.png` | Authenticated User Info | Backend handles `/api/v1/me` route ignoring subpath; CDN caches under image rule. | High |
| 4 | `/dashboard/data.json/fake.svg` | Appended `.svg` | Dashboard Data | Reverse proxy caches `.svg` publicly; authenticated metrics/PII exposed. | High |
| 5 | `/profile%0A.css` | Encoded newline `%0A` + `.css` | Profile Page | Nginx/Apache path discrepancy: backend strips `%0A`, CDN regex matches `\.css$`. | High |
| 6 | `/api/user%00.js` | Encoded null byte `%00` + `.js` | Identity API | C-based reverse proxy truncates at null byte; CDN caches under `.js`. | Critical |
| 7 | `/api/user%23.css` | Encoded hash `%23` (`#`) + `.css` | Sensitive JSON API | Origin routing ignores fragment; CDN caches under `.css`. | High |
| 8 | `/api/user/..;/static/style.css` | Path traversal confusion `..;/` | API Endpoint | Reverse proxy normalizes path to `/static/style.css` (cached), backend routes to `/api/user`. | High |

#### 3.2.4 Mode 4: Cache Key Normalization Flaws Matrix

| # | Technique | Request Structure | Backend vs Cache Behavior | Severity |
|---|-----------|-------------------|---------------------------|----------|
| 1 | **FAT GET Request** | `GET /path?cb=<nonce> HTTP/1.1`<br>`Content-Type: application/x-www-form-urlencoded`<br>`Content-Length: 28`<br><br>`utm_content=<canary>&x=1` | Cache engine computes key strictly from GET URL line (ignoring body). Backend parses body parameters and reflects `utm_content` into response, which is then cached for standard GET requests. | High |
| 2 | **Method Override Header** | `GET /path?cb=<nonce> HTTP/1.1`<br>`X-HTTP-Method-Override: POST`<br>`Content-Type: application/json`<br><br>`{"canary": "injected"}` | Cache engine treats request as cacheable GET; backend framework (Spring, Express, Rails) processes as POST/PUT state modification or alternative view. | High |
| 3 | **Alternative Method Override Headers** | `X-Method-Override: POST`, `_method=POST`, `X-HTTP-Method: POST` | Same as above; evaluated by frameworks to simulate RESTful methods. | High |
| 4 | **Duplicate Header Folding** | Multiple `Host: target.com` and `Host: <canary>` or folded CRLF headers | Proxy concatenates headers with commas or forwards first; backend parses second, poisoning virtual host routing. | High |

#### 3.2.5 Mode 5: Cache Header & Lifecycle Fingerprinting

##### Cache Status Header Signatures
The scanner must extract and evaluate the following headers to determine cache state:

| Header Name | Values / Patterns | Meaning & Lifecycle Interpretation |
|-------------|-------------------|-----------------------------------|
| `CF-Cache-Status` | `HIT`, `STALE`, `REVALIDATED`, `UPDATING` | **Cache HIT**: Response served directly from Cloudflare cache storage. |
| `CF-Cache-Status` | `MISS`, `EXPIRED`, `BYPASS`, `DYNAMIC` | **Cache MISS / Bypass**: Response fetched from origin or marked uncacheable. |
| `X-Cache` | `HIT`, `TCP_HIT`, `TCP_REFRESH_HIT`, `HIT from cloudfront`, `HIT from ATS` | **Cache HIT**: Response served from reverse proxy / CDN cache. |
| `X-Cache` | `MISS`, `TCP_MISS`, `MISS from cloudfront`, `MISS from ATS` | **Cache MISS**: Response retrieved from origin. |
| `X-Cache-Hits` | Integer string (e.g. `"1"`, `"42"`) | Count of hits on this cache object; value $\ge 1$ confirms active caching. |
| `X-Varnish` | Multiple integers (e.g. `"12345678 87654321"`) | **Varnish Cache HIT**: Presence of 2 transaction IDs indicates cache hit. Single ID indicates miss. |
| `X-Served-By` | `cache-iad-kiad7000020-IAD` | Indicates Fastly / Varnish cache node handling. |
| `X-Timer` | `S1700000000.123456,VS0,VE1` | Fastly timing header; `VS0` (Varnish Socket 0) indicates cache hit. |
| `Age` | Integer string (e.g. `"12"`, `"120"`) | **Monotonic Age Progression**: Seconds response has resided in cache. If $Age_{t_2} > Age_{t_1}$, caching is verified even if status headers are stripped! |
| `Cache-Control` | `public`, `max-age=N`, `s-maxage=N` | Directives instructing downstream proxies to cache the response. |

##### CDN & Reverse Proxy Signatures Matrix

| Technology | Distinctive Response Headers | Engine Type | Default Key Behavior |
|------------|------------------------------|-------------|----------------------|
| **Cloudflare** | `Server: cloudflare`, `CF-Ray: ...`, `CF-Cache-Status: HIT/MISS`, `cf-bgj: ...` | CDN / Edge Proxy | Keys on Scheme + Host + Path + Query. Ignores standard unkeyed headers by default unless Page Rules configured. |
| **AWS CloudFront** | `Via: ... CloudFront`, `X-Amz-Cf-Id: ...`, `X-Amz-Cf-Pop: ...`, `X-Cache: HIT from cloudfront` | CDN | Keys on Host + Path + Query (unless configured to forward query strings or specific headers). |
| **Akamai** | `Server: AkamaiGHost`, `X-Akamai-Request-ID: ...`, `X-Check-Cacheable: YES`, `Akamai-Cache-Status: ...` | CDN | Sophisticated edge rule caching; susceptible to unkeyed headers if forward-headers not part of cache key. |
| **Fastly** | `Server: Varnish`, `X-Served-By: cache-...`, `Fastly-Debug-Digest: ...`, `X-Timer: ...` | VCL-driven CDN | Highly customizable VCL caching rules; keys on URL path, susceptible to matrix parameter discrepancies. |
| **Varnish Cache** | `Via: ... varnish`, `X-Varnish: ...`, `Server: Varnish` | Reverse Proxy Cache | Default VCL keys on `req.url` and `req.http.host`. Standard unkeyed headers (`X-Forwarded-*`) bypass key. |
| **Nginx** | `Server: nginx`, `X-Cache-Status: HIT/MISS`, `X-Cache: HIT` | Reverse Proxy Cache | `proxy_cache_key` defaults to `$scheme$proxy_host$request_uri`. Ignores request body in GET requests (FAT GET vulnerable). |
| **Apache Traffic Server (ATS)** | `Server: ATS`, `Via: ... ApacheTrafficServer`, `X-Cache: HIT from ATS` | Reverse Proxy Cache | Keys on URI. Susceptible to unkeyed query parameter pollution and delimiter confusion. |

---

### 3.3 R3: Mutation & Evasion Strategies (5 Distinct Strategies)

```
+----------------------------------------------------------------------------------------------------+
|                                  MUTATION & EVASION STRATEGIES                                     |
+------------------------------------+---------------------------------------------------------------+
| Strategy 1: Dynamic Cache Buster   | Generates isolated nonces across query params, headers, and   |
|             Insertion              | cookies to prevent testing cross-talk and verify isolation.   |
+------------------------------------+---------------------------------------------------------------+
| Strategy 2: Path Delimiter         | Applies delimiters (;, .., %00, %0A, #, ..;/) to confuse      |
|             Variations             | path parsers and bypass static extension cache rules.         |
+------------------------------------+---------------------------------------------------------------+
| Strategy 3: Normalization          | Inverts casing and applies selective percent-encoding to test |
|             Inversion              | case-sensitivity and URL decoding discrepancies.              |
+------------------------------------+---------------------------------------------------------------+
| Strategy 4: Header Parameterization| Injects duplicate headers, comma-separated lists, and tabs to |
|             & Cloaking             | exploit header parsing discrepancies.                         |
+------------------------------------+---------------------------------------------------------------+
| Strategy 5: Cache Rule Probe       | Rotates Accept headers and iterates static extension matrices |
|             Variations             | (.css, .js, .png, .svg, .json) across candidate endpoints.    |
+------------------------------------+---------------------------------------------------------------+
```

#### Strategy 1: Dynamic Cache Buster Insertion
- **Mechanism:** To prevent tests from polluting live user cache keys or interfering with concurrent tests, every test sequence utilizes cryptographically random nonces:
  - Query String Nonces: `?cb=<uuid_12>`, `?__argus_cb=<timestamp_ms>`, `?nonce=<hex_8>`.
  - Unkeyed Header Nonces: `X-Argus-Buster: <nonce>`, `Origin: https://<nonce>.argus.local`.
  - Cache Isolation Protocol: Step 1 (Baseline) uses $B_0$; Steps 2 & 3 (Poison + Replay) use $B_1$; Step 4 (Control) uses $B_2$.

#### Strategy 2: Path Delimiter Variations
- **Mechanism:** Exploits matrix parameters and parser truncations across web servers (Tomcat, Spring, IIS, Nginx, Apache):
  - Matrix Semicolons: `/endpoint;argus=1.css`, `/endpoint;jsessionid=123.js`.
  - Directory Traversal Confusions: `/endpoint/..;/style.css`, `/endpoint/%2e%2e%2fstyle.css`.
  - Encoded Delimiters: `%0A` (newline), `%0D` (carriage return), `%00` (null byte), `%23` (hash `#`), `%3F` (question mark `?`).
  - Dot Segment Normalization: `/endpoint/.css`, `/endpoint/test..css`.

#### Strategy 3: Request Normalization Inversion
- **Mechanism:** Tests whether cache keys normalize casing or percent-encoding differently from backend routing:
  - Path Case Inversion: `/ACCOUNT/SETTINGS.CSS` vs `/account/settings.css`.
  - Header Name Casing: `x-forwarded-host` vs `X-Forwarded-Host` vs `X-FORWARDED-HOST`.
  - Selective Percent Encoding: `%61%63%63%6f%75%6e%74/%73%65%74%74%69%6e%67%73.css`.
  - Double URL Encoding: `%252e%252e%252f` (`../`), `%2523` (`#`).

#### Strategy 4: Header Parameterization & Cloaking
- **Mechanism:** Bypasses WAFs and exploits multi-header folding in reverse proxies:
  - Duplicate Headers: Multiple `Host` or `X-Forwarded-Host` headers in the same HTTP payload.
  - Comma-Separated Values: `X-Forwarded-Host: legitimate.com, <canary>.argus-security.com`.
  - Whitespace & Tab Insertion: `X-Forwarded-Host:\t<canary>.argus-security.com`, `X-Forwarded-Host:  <canary>`.
  - Attribute Semicolon Cloaking: `X-Forwarded-Host: <canary>;version=1`.

#### Strategy 5: Cache Rule Probe Variations
- **Mechanism:** Maps caching boundaries by manipulating content negotiation and extension rules:
  - Content-Type / Accept Header Manipulation: `Accept: text/css,*/*;q=0.1`, `Accept: application/javascript`, `Accept: image/webp,*/*`.
  - Static Extension Matrix Expansion: Evaluates comprehensive matrix: `[.css, .js, .png, .jpg, .jpeg, .svg, .ico, .woff, .woff2, .json, .xml, .map, .avif, .webp, .pdf, .txt, .html]`.

---

### 3.4 R4: Pipeline & AttackSurfaceGraph Connectivity

#### 3.4.1 TaskGenerator DAG Integration (`argus/planning/task_generator.py`)
Add task template definition in `_RECON_TEMPLATES`:

```python
_RECON_TEMPLATES["cache_security"] = {
    "title": "Validate Web Cache Poisoning & Cache Deception",
    "goal": "Actively probe discovered endpoints for unkeyed headers, unkeyed query parameters, web cache deception (WCD), cache key normalization flaws, and CDN caching misconfigurations using AuthenticatedHttpClient and differential cache confirmation probers.",
    "category": TaskCategory.EVIDENCE_CORRELATION,
    "required_inputs": ["endpoints"],
    "expected_outputs": ["vulnerabilities", "observations", "evidence"],
    "dependencies": ["Discover API Endpoints"],
    "required_specialists": [],
    "metadata": {"tool_id": "cache_security"},
    "estimated_duration_minutes": 10,
    "priority": 0.82,
}
```

Wire DAG resolver logic in `generate_recon_dag`:
```python
elif tool_id in (
    "katana_crawler", "nuclei", "info_disclosure", "access_control",
    "path_traversal", "sql_injection", "xss", "command_injection",
    "ssrf", "oauth", "xml_parser_validation", "deserialization",
    "graphql_security", "websocket_security", "request_smuggling",
    "race_conditions", "business_logic", "ssti", "cache_security"
):
```

#### 3.4.2 Registry Integration (`argus/runtime/registry.py`)
Add alias mapping:
```python
"cache_security": "cache_security",
"web_cache_poisoning": "cache_security",
"cache_poisoning": "cache_security",
"cache_deception": "cache_security",
"web_cache_deception": "cache_security",
"wcd": "cache_security",
"unkeyed_headers": "cache_security",
"unkeyed_params": "cache_security",
"cache_security_collector": "cache_security",
"cache_security_detector": "cache_security",
```

Register tool definition:
```python
registry.register(
    Tool(
        id="cache_security",
        name="Web Cache Poisoning & Cache Deception Detection Collector",
        capability="cache_security_detector",
        description="Actively discovers and validates Web Cache Poisoning, Web Cache Deception, unkeyed header/parameter injection, FAT GET desynchronization, and CDN cache lifecycle flaws across reverse proxies and CDNs using AuthenticatedHttpClient.",
        supported_tasks=[
            "Cache Security Validation",
            "Web Cache Poisoning Detection",
            "Web Cache Deception Detection",
            "Unkeyed Header Analysis",
            "Unkeyed Parameter Analysis",
            "CDN Lifecycle Fingerprinting",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "cache_security_detector",
            "cache_security_collector",
            "cache_poisoning_detector",
            "cache_deception_detector",
            "unkeyed_header_detector",
            "wcd_detector",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)
```

#### 3.4.3 Plugin Executor Adapter (`argus/runtime/plugins.py`)
```python
elif (
    "cache_security" in plugin_id
    or "cache_poisoning" in plugin_id
    or "cache_deception" in plugin_id
    or "wcd" in plugin_id
    or "unkeyed" in plugin_id
):
    from argus.collectors.cache_security import CacheSecurityCollector
    return CacheSecurityCollector()
```

#### 3.4.4 CVSS & CWE Mappings (`argus/reporting/cvss.py`)
```python
"cache_security": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
"web_cache_poisoning": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
"cache_poisoning": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
"unkeyed_header_poisoning": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
"unkeyed_param_poisoning": CWEInfo("CWE-444", "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling / Cache Poisoning')"),
"web_cache_deception": CWEInfo("CWE-524", "Information Exposure Through Caching"),
"cache_deception": CWEInfo("CWE-524", "Information Exposure Through Caching"),
"wcd": CWEInfo("CWE-524", "Information Exposure Through Caching"),
```

#### 3.4.5 AttackSurfaceGraph Node & Edge Expansion
When a vulnerability is confirmed:
- Create `live_host` node: `Node(id="live_host:<host>", type="live_host", value="<host>", metadata={"url": "<host>"})`
- Create `endpoint` node: `Node(id="endpoint:<url>", type="endpoint", value="<url>", metadata={"url": "<url>", "status_code": 200})`
- Create `vulnerability` node: `Node(id="vulnerability:<template_id>:<url>:<vector>", type="vulnerability", value="<title>", metadata=ev.metadata)`
- Connect edges:
  - `graph.connect("live_host:<host>", "endpoint:<url>", edge_type="HAS_ENDPOINT")`
  - `graph.connect("live_host:<host>", "vulnerability:...", edge_type="HAS_VULNERABILITY")`
  - `graph.connect("endpoint:<url>", "vulnerability:...", edge_type="HAS_VULNERABILITY")`

---

### 3.5 R5: False Positive Rejection Rules & Verification Oracle Matrix

#### 3.5.1 The 4-Step Sequential Differential Confirmation Oracle

```
+----------------------------------------------------------------------------------------------------+
|                         4-STEP DIFFERENTIAL CONFIRMATION ORACLE                                    |
+----------------------------------------------------------------------------------------------------+
|  Step 1: Baseline Measurement (Nonce B_0)                                                          |
|  - Request: GET /endpoint?cb=B_0 (clean, no injection)                                             |
|  - Check: Record pristine status, body hash, length, cache headers (Age=0, MISS).                  |
+----------------------------------------------------------------------------------------------------+
|  Step 2: Perturbed Poisoning Probe (Nonce B_1)                                                     |
|  - Request: GET /endpoint?cb=B_1 (with X-Forwarded-Host: canary.argus.local OR appended .css)       |
|  - Check: Verify canary reflection, redirect to canary, or sensitive PII returned.                |
|  - Rejection Filter: If canary is NOT reflected / status is 4xx/5xx error => REJECT EARLY.        |
+----------------------------------------------------------------------------------------------------+
|  Step 3: Replay / Cache Validation Probe (Nonce B_1)                                               |
|  - Request: GET /endpoint?cb=B_1 (CLEAN request - NO poisoning headers, NO cookies for WCD)        |
|  - Check:                                                                                          |
|    1. Cache HIT verified: X-Cache: HIT OR CF-Cache-Status: HIT OR Age > 0                          |
|    2. Poisoned state persisted: canary string in body/headers OR sensitive PII in WCD.            |
|  - Rejection Filter: If response is MISS or clean (no canary/PII) => REJECT (Uncached Reflection).|
+----------------------------------------------------------------------------------------------------+
|  Step 4: Isolation Control Probe (Nonce B_2)                                                       |
|  - Request: GET /endpoint?cb=B_2 (clean request with NEW cache buster B_2)                         |
|  - Check: Response must be CLEAN and unpolluted (canary NOT present).                              |
|  - Rejection Filter: If canary appears in B_2 => REJECT (Global Dynamic Echo / Broken Backend).    |
+----------------------------------------------------------------------------------------------------+
```

#### 3.5.2 False Positive Rejection Decision Matrix

| Scenario / Observed State | Step 1 (B_0) | Step 2 (B_1 Perturbed) | Step 3 (B_1 Replay) | Step 4 (B_2 Control) | Decision | Reason / Classification |
|---|---|---|---|---|---|---|
| **True Web Cache Poisoning** | Clean, MISS | Canary Reflected | **HIT**, Canary Present | Clean, MISS | **CONFIRM (Critical)** | Genuine cache poisoning verified via unkeyed input persistence. |
| **True Web Cache Deception** | Clean 200 (Auth) | Sensitive PII (Auth) | **HIT**, PII Present (Unauth) | Clean 200 (Unauth) | **CONFIRM (High)** | Sensitive authenticated content publicly cached under static rule. |
| **Uncached Dynamic Reflection** | Clean | Canary Reflected | **MISS / Clean** (No Canary) | Clean | **REJECT** | Header reflects dynamically on direct request but response is NOT stored in cache. |
| **Unreflected Header Injection** | Clean | No Change (Clean) | Clean | Clean | **REJECT** | Injected header was ignored by backend; no exploitable reflection or redirection. |
| **Public Static Asset (WCD Probe)** | Static CSS | Static CSS | **HIT**, Static CSS (No PII) | Static CSS | **REJECT** | Target is legitimately a public static asset with no sensitive PII/tokens. |
| **Global Dynamic Reflection** | Clean | Canary Reflected | Canary Present | **Canary Present** | **REJECT** | Backend dynamically echoes parameter application-wide across all requests (not a cache flaw). |
| **WAF / Rate-Limit Block** | Clean | 429 / 403 WAF Block | 429 / 403 Block | Clean | **REJECT** | Request blocked by rate-limiting or security filter; no vulnerability state. |
| **Volatile Timestamp / Jitter** | Hash $H_1$ | Hash $H_2$ | **MISS**, Hash $H_3$ | Hash $H_4$ | **REJECT** | Body changes due to dynamic server clock or CSRF tokens; not cache poisoning. |

---

## 4. Discovered Features & Edge Cases

### 4.1 Features Discovered
| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | R1: Collector | `CacheSecurityCollector` | Active collector inheriting from `BaseCollector` | `mission` object | `List[Evidence]` | Catches HTTP timeouts, logs debug errors, continues | Codebase architecture probe |
| 2 | R1: Prober | `CacheSecurityProber` | Differential multi-step cache verification prober | `url`, `probe`, `cache_buster` | `CacheProbeResponse` | Graceful fallback on connection resets | Codebase & RFC 7234 |
| 3 | R1: Generator | `CacheSecurityPayloadGenerator` | Multi-vector payload generator | `base_url`, `canary` | `List[CacheProbe]` | Validates URL format | RFC 7239, PortSwigger WCP spec |
| 4 | R1: Analyzer | `CacheSecurityAnalyzer` | Verification oracle and PII extractor | `ProbeResult` | `CacheValidationResult` | Suppresses false positive reflections | Defensive scanner spec |
| 5 | R2: Mode 1 | Unkeyed Host/Forwarded Headers | Probes `X-Forwarded-Host`, `Forwarded`, `X-Host`, etc. | Host headers with canary domain | Reflected script tag / redirect `Location` | Rejects uncached reflections | RFC 7239, reverse proxy research |
| 6 | R2: Mode 1 | Unkeyed Scheme/Proto Headers | Probes `X-Forwarded-Scheme`, `X-Forwarded-Proto` | `http` vs `https` | Redirect loops / insecure resource includes | Rejects standard unreflected redirects | CDN forwarding standards |
| 7 | R2: Mode 1 | Unkeyed Path Overrides | Probes `X-Original-URL`, `X-Rewrite-URL` | Injected internal paths | Overridden origin page cached under public path | Rejects 404 unhandled paths | IIS/Nginx rewrite specs |
| 8 | R2: Mode 2 | Unkeyed Query Parameters | Probes `utm_*`, `fbclid`, `gclid`, `_ga` | Analytics params with canary | Reflected parameter in cached HTML/JSON | Rejects keyed query parameters | CDN cache key configurations |
| 9 | R2: Mode 2 | Unkeyed JSONP Callbacks | Probes `callback`, `cb`, `jsonp` | Canary function name | Cached JSONP response with injected canary | Rejects non-JSONP responses | Web API security standards |
| 10 | R2: Mode 2 | Parameter Cloaking Discrepancies | Probes `?k=1?u=2`, `?k=1;u=2`, `%26`, `%23` | Delimiter-separated params | Backend executes cloaked param; cache ignores | Rejects unified key parsers | Parser differential research |
| 11 | R2: Mode 3 | Web Cache Deception (Static Path) | Probes `/account/settings/test.css` | Appended static extensions | Authenticated PII cached and served to unauth | Rejects public static files | BlackHat WCD research |
| 12 | R2: Mode 3 | WCD Delimiter Matrix | Probes `/api/user;test.js`, `%0A`, `%00`, `..;/` | Semicolon/encoded delimiters | Origin strips delimiter; CDN caches under extension | Rejects normalized paths | Java/Spring matrix specs |
| 13 | R2: Mode 4 | FAT GET Requests | Sends GET request with body parameters | URL-encoded or JSON body in GET | Backend parses body and reflects in cached GET | Rejects rejected GET bodies | HTTP/1.1 RFC 7230 |
| 14 | R2: Mode 4 | Method Override Headers | Probes `X-HTTP-Method-Override: POST` | Method override in GET | Backend processes POST action; cached as GET | Rejects unhandled method overrides | REST framework specs |
| 15 | R2: Mode 5 | Cache Status Fingerprinting | Detects `CF-Cache-Status`, `X-Cache`, `Age` | Response headers | Identified cache lifecycle state (`HIT`/`MISS`) | Handles missing cache headers | RFC 7234 & CDN specs |
| 16 | R2: Mode 5 | CDN Engine Fingerprinting | Identifies Cloudflare, CloudFront, Varnish, ATS, Nginx | Server/Via/Timer headers | Fingerprinted CDN/Proxy engine family | Defaults to `generic` cache engine | Cloud CDN response profiles |
| 17 | R3: Strategy 1 | Dynamic Cache Buster Insertion | Query/header nonces per step | Timestamp/UUID nonces | Isolated cache partition per test sequence | Generates collision-free IDs | Defensive scanner safety |
| 18 | R3: Strategy 2 | Path Delimiter Variations | Tests `;`, `..;/`, `%2e%2e%2f`, `#`, `%00` | Mutated URL paths | Delimiter confusion payloads | Escapes invalid URI characters | URI RFC 3986 |
| 19 | R3: Strategy 3 | Normalization Inversion | Tests casing and percent-encoding | Uppercase / encoded characters | Normalization bypass payloads | Handles malformed encoding | URL normalization rules |
| 20 | R3: Strategy 4 | Header Parameterization & Cloaking | Injects duplicate headers and comma lists | Multi-header payloads | Folded/cloaked header variations | Prevents HTTP/2 framing errors | HTTP/1.1 & HTTP/2 standards |
| 21 | R3: Strategy 5 | Cache Rule Probing | Manipulates `Accept` and static extension matrix | 15+ static file extensions | Comprehensive static rule boundary map | Filters unsupported MIME types | MIME/HTTP content negotiation |
| 22 | R4: Pipeline | DAG Task Scheduling | Schedules `cache_security` in `TaskGenerator` | Endpoint graph node | Generated DAG task with priority 0.82 | Fallback to default recon task | Argus DAG TaskGenerator |
| 23 | R4: Registry | Tool & Alias Registration | Registers `cache_security` with aliases | Registry lookup | Instantiated collector | Dynamic fallback instantiation | Argus ToolRegistry |
| 24 | R4: Graph | AttackSurfaceGraph Expansion | Emits `live_host`, `endpoint`, `vulnerability` | Confirmed `Evidence` | KnowledgeGraph nodes and edges | Prevents duplicate node IDs | Argus AttackSurfaceGraph |
| 25 | R4: CVSS | Automated CVSS & CWE Mapping | Maps `CWE-444`, `CWE-524`, `CWE-525` | Finding metadata | CVSS v3.1 score (7.5 - 8.8) | Fallback to default CWE | Argus CVSSCalculator |

### 4.2 Edge Cases
| # | Feature | Input / Condition | Observed & Expected Behavior |
|---|---------|-------------------|-----------------------------|
| 1 | WCD on Non-Authenticated Endpoint | Public blog endpoint `/blog/post/1/test.css` | Origin returns public content; analyzer checks for sensitive PII (emails, tokens) $\to$ No PII detected $\to$ REJECT false positive. |
| 2 | Cache Status Header Stripped | Reverse proxy caches responses but strips `X-Cache` / `CF-Cache-Status` headers | Analyzer evaluates monotonic increase of `Age` header across requests ($Age_2 > Age_1$) to verify caching. |
| 3 | Upstream Origin 304 Not Modified | Replay request returns `304 Not Modified` | Prober evaluates entity headers from original cache response; confirms cache validation mechanism. |
| 4 | Origin Rate Limiting / 429 Too Many Requests | Rapid probe bursts trigger origin 429 / 503 | Analyzer catches rate-limit status; marks probe as inconclusive without raising false positive vulnerability. |
| 5 | CDN Caching Error Responses (404/500 Caching) | Host header injection induces 400 Bad Request which is cached by CDN | Analyzer flags Error-Based Cache Poisoning (`status=400`, `severity=Medium/High`) if error response is cached and served to clean requests. |
| 6 | URL Fragment Truncation | Delimiter payload with `#` (`%23`) | Prober ensures proper URL percent-encoding during transport so `#` is sent to proxy rather than stripped by HTTP client library. |
| 7 | Duplicate Header Handling in HTTP/2 | Multiple `Host` headers over HTTP/2 connection | Prober uses HTTP/1.1 transport or HTTP/2 pseudo-header formatting to avoid illegal HTTP/2 frame construction. |
| 8 | Dynamic CSRF Token Jitter | Baseline and Replay response bodies differ due to per-request CSRF tokens | Analyzer performs substring canary search and DOM structural diffing rather than strict whole-body hashing. |

---

## 5. Caveats

1. **Safety & Non-Destructive Testing:** Probing live caches with global URLs without cache busters can poison responses for actual users. **ARGUS must strictly enforce unique cache buster nonces on all poisoning probes** so that poisoned entries are isolated strictly to test keys.
2. **CDN Cache Purge Inability:** Blackbox security tools cannot force a CDN to purge a cache key. Test keys should have short TTLs or use randomized cache buster nonces that naturally expire.
3. **Session Cookie Isolation for WCD:** Web Cache Deception detection requires valid authenticated credentials to verify if sensitive user data is cached. The module must coordinate with `AuthenticatedHttpClient` and `MultiIdentityCoordinator` to test multi-user privilege boundaries safely.

---

## 6. Conclusion

The specification formalizes all technical requirements (R1 through R5) for the Web Cache Poisoning & Web Cache Deception Detection Module in ARGUS. It provides comprehensive payload matrices, CDN fingerprinting signatures, 5 distinct evasion strategies, the 4-step differential verification oracle, full DAG/Registry/Graph pipeline wiring, and strict false-positive rejection filters.

---

## 7. Verification Method

To independently verify the implementation against this specification:
1. Run the test suite:
   ```bash
   python -m pytest tests/collectors/test_cache_security.py -v
   ```
2. Run full regression test suite:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
3. Inspect `handoff.md` at `/home/varun/argus/.agents/survey_spec_miner/handoff.md`.
