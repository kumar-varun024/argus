## 2026-09-01T17:41:00Z

You are Worker 1 (CORS & Security Headers Implementer).
Your working directory is: `/home/varun/argus/.agents/worker_cors_module`

Scope and Tasks:
1. Implement `/home/varun/argus/argus/collectors/cors_headers.py`:
   - `CORSSecurityCollector` (inherits `BaseCollector`):
     - `collect(self, mission)` and `execute(self, mission)` -> `List[Evidence]`
     - Endpoint discovery from `mission.endpoints`, `mission.live_hosts`, `mission.target`, `mission.evidence`
     - Uses `CORSProber` and `HeaderAuditor`
     - Emits quadruple state updates: `mission.evidence.add()`, `mission.vulnerabilities.append()`, `mission.attack_surface_graph` (creating `live_host`, `endpoint`, `vulnerability` nodes linked by `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges), and `mission.publish_finding(...)`
   - `CORSProber`:
     - Dispatches HTTP requests using `AuthenticatedHttpClient` (or injected custom/mock client)
     - Catches connection and timeout exceptions gracefully, returning `HttpResponse(success=False, error=...)`
   - `CORSMutationGenerator`:
     - Generates 5 evasion strategies:
       a. `ORIGIN_CASING`: Casing variations (`hTtPs://ExAmPlE.cOm`)
       b. `PROTOCOL_SMUGGLING`: Protocol variations (`http://`, `file://`, `data://`, `null`)
       c. `SUBDOMAIN_INJECTION`: Prefix/suffix/subdomain variations
       d. `HEADER_DUPLICATION`: Header duplication / folding
       e. `PREFLIGHT_ENUMERATION`: Pre-flight method/header matrix
   - `CORSAnalyzer`:
     - Analyzes response headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, `Vary`)
     - 6 CORS detection modes:
       1. Origin reflection (`ACAO: <arbitrary-origin>`, `ACAC: true`)
       2. Null origin acceptance (`Origin: null` -> `ACAO: null`, `ACAC: true`)
       3. Wildcard with credentials (`ACAO: *` and `ACAC: true`)
       4. Subdomain trust abuse (`Origin: https://attacker.target.com` -> `ACAO: ...`)
       5. Pre-flight bypass (OPTIONS responses with overly permissive methods/headers, missing/broken preflight)
       6. Origin parser differential (`target.com.attacker.com`, `attacker-target.com`, URL encoding, protocol confusion)
     - Rejects false positives (same-origin reflection is safe, wildcard on public endpoint without credentials is safe).
   - `HeaderAuditor`:
     - 8 HTTP security header compliance audits:
       1. CSP (missing, unsafe-inline, unsafe-eval, wildcard sources `*` / `http:` / `data:`, missing frame-ancestors)
       2. HSTS (evaluated on HTTPS: missing, max-age < 31536000, missing includeSubDomains, missing preload)
       3. X-Frame-Options (missing when CSP frame-ancestors absent, misconfigured ALLOW-FROM)
       4. X-Content-Type-Options (missing nosniff)
       5. Referrer-Policy (missing, unsafe-url, no-referrer-when-downgrade)
       6. Permissions-Policy (missing, unconstrained wildcards * on camera/microphone/geolocation)
       7. X-XSS-Protection (explicitly 0 / missing without CSP)
       8. Cache-Control on sensitive endpoints (missing no-store/no-cache on authenticated/sensitive routes)

2. Export `CORSSecurityCollector` in `argus/collectors/__init__.py`.

3. Wire pipeline connectivity:
   - `argus/planning/task_generator.py`: Register `cors_headers` in `_TOOL_TEMPLATES` / `_RECON_TEMPLATES` dependent on `"Discover API Endpoints"`.
   - `argus/runtime/registry.py`: Register `cors_headers` tool with capability aliases (`cors`, `cors_headers`, `security_headers`, `http_headers`).
   - `argus/runtime/plugins.py`: Register specialist fallback for `cors_headers`.
   - `argus/graph/attack_surface.py`: Ensure `AttackSurfaceGraphBuilder` generates `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges for evidence categories `cors` and `security_headers`.
   - `argus/reporting/cvss.py`: Add `CWE-942`, `CWE-693`, `CWE-1021`, `CWE-525` to `CWE_DATABASE` and CVSS calculation mappings.

4. Write comprehensive tests in `tests/collectors/test_cors_headers.py`:
   - Provide `MockCORSHttpClient`
   - Include >= 25 tests covering all 6 CORS modes, 8 header audits, 5 mutation strategies, false positive rejection, error handling, mock client, graph integration, and pipeline connectivity.

5. Verify:
   - Run `python -m pytest tests/collectors/test_cors_headers.py -v`
   - Run `python -m pytest tests/ --ignore=tests/workspace -x -q` (ensure all 1,740+ tests pass with zero regressions).
