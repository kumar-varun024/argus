## 2026-09-01T17:21:37Z
You are the Lead Implementation Worker for the CORS Misconfiguration & HTTP Security Header Audit Module in ARGUS.
Your working directory is: `/home/varun/argus/.agents/worker_cors_headers`

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A forensic auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Read:
- `/home/varun/argus/.agents/orchestrator/ORIGINAL_REQUEST.md`
- `/home/varun/argus/PROJECT.md`
- `/home/varun/argus/.agents/explorer_survey_1/handoff.md`
- `/home/varun/argus/.agents/explorer_survey_3/handoff.md`

Your tasks:
1. Implement `argus/collectors/cors_headers.py`:
   - `CORSSecurityCollector` inheriting from `BaseCollector` (with `collect(mission)` and `execute(mission)`).
   - Candidate endpoint discovery with fallback synthesis when endpoints list is empty.
   - Probing engine using `AuthenticatedHttpClient` (with support for mock/custom clients and graceful timeout/exception handling).
   - 6 CORS detection modes:
     1. Origin reflection (`ACAO: <arbitrary-origin>`, `ACAC: true`)
     2. Null origin acceptance (`Origin: null` -> `ACAO: null`, `ACAC: true`)
     3. Wildcard with credentials (`ACAO: *` and `ACAC: true`)
     4. Subdomain trust abuse (`Origin: https://attacker.target.com` -> `ACAO: ...`)
     5. Pre-flight bypass (OPTIONS responses with overly permissive methods/headers, missing/broken pre-flight)
     6. Origin parser differentials (`target.com.attacker.com`, `attacker-target.com`, URL encoding, protocol confusion)
   - 5 Mutation & evasion strategies:
     1. Origin casing variations (`hTtPs://ExAmPlE.cOm`)
     2. Protocol smuggling (`http://`, `file://`, `data://`, `null`)
     3. Subdomain injection patterns (prefix, suffix, delimiter variations)
     4. Header duplication & folding (multiple Origin headers, comma-separated)
     5. Pre-flight method/header enumeration
   - 8 HTTP security header audits:
     1. CSP (missing, unsafe-inline, unsafe-eval, wildcard sources, missing frame-ancestors)
     2. HSTS (missing on HTTPS, low max-age < 31536000, missing includeSubDomains, missing preload)
     3. X-Frame-Options (missing without CSP frame-ancestors, misconfigured ALLOW-FROM)
     4. X-Content-Type-Options (missing nosniff)
     5. Referrer-Policy (missing, unsafe-url, no-referrer-when-downgrade)
     6. Permissions-Policy (missing, unconstrained camera/microphone/geolocation wildcards)
     7. X-XSS-Protection (0 / missing without CSP)
     8. Cache-Control on sensitive endpoints (missing no-store / no-cache on auth/PII/sensitive routes)
   - Quadruple state publishing (`mission.evidence`, `mission.vulnerabilities`, `mission.attack_surface_graph`, `mission.publish_finding`).
2. Export `CORSSecurityCollector` in `argus/collectors/__init__.py`.
3. Pipeline Connectivity:
   - `argus/planning/task_generator.py`: Add `cors_headers` to `_TOOL_TEMPLATES` / `_RECON_TEMPLATES` with dependency on endpoint discovery (`"Discover API Endpoints"`).
   - `argus/runtime/registry.py`: Register tool `cors_headers` with capability aliases (`cors`, `cors_headers`, `security_headers`, `http_headers`).
   - `argus/runtime/plugins.py`: Register specialist fallback for `cors_headers`.
   - `argus/graph/attack_surface.py`: Ensure `AttackSurfaceGraphBuilder` creates `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges for `cors` and `security_headers` evidence.
   - `argus/reporting/cvss.py`: Add `CWE-942`, `CWE-693`, `CWE-1021`, `CWE-525` to `CWE_DATABASE` and CVSS calculation mappings.
4. Comprehensive Test Suite in `tests/collectors/test_cors_headers.py`:
   - Write >= 25 exhaustive tests covering all 6 CORS modes, 8 header audits, 5 mutation strategies, false positive rejection rules, error handling, mock client, and pipeline integration tests.
5. Verification:
   - Run `python -m pytest tests/collectors/test_cors_headers.py -v`
   - Run `python -m pytest tests/ --ignore=tests/workspace -x -q` (all 1,740+ baseline tests + new tests must pass).

Write a comprehensive handoff report to:
`/home/varun/argus/.agents/worker_cors_headers/handoff.md`

Update `/home/varun/argus/.agents/worker_cors_headers/progress.md` with your status.
When finished, send a message to parent with summary and file path.
