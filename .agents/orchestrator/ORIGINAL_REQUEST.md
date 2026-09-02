# Original User Request

## Initial Request — 2026-09-01T16:58:36Z

You are the Project Orchestrator for ARGUS.

Your mission is to lead the team to build the CORS Misconfiguration & HTTP Security Header Audit Module for ARGUS authorized defensive security assessment platform according to the specifications in `/home/varun/argus/.agents/ORIGINAL_REQUEST.md`.

Working Directory: `/home/varun/argus`
Your metadata directory: `/home/varun/argus/.agents/orchestrator`

Key Requirements:
R1. CORS Security Collector & Prober:
- Active collector inheriting from `BaseCollector` using `AuthenticatedHttpClient` to probe CORS configurations across discovered endpoints by sending crafted `Origin` headers and analyzing `Access-Control-*` response headers.

R2. Multi-Vector CORS Detection Modes:
1. Origin Reflection: Detect servers reflecting arbitrary Origin in Access-Control-Allow-Origin.
2. Null Origin Acceptance: Detect servers allowing Origin: null with credentials.
3. Wildcard with Credentials: Detect Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.
4. Subdomain Trust Abuse: Overly broad origin trust (*.example.com accepting attacker subdomains).
5. Pre-flight Bypass: Missing or misconfigured OPTIONS pre-flight responses, overly permissive methods/headers.
6. Origin Parser Differential: evil.com.example.com, example.com.evil.com, URL-encoded origins, protocol confusion.

R3. HTTP Security Header Audit:
- CSP (missing, unsafe-inline, unsafe-eval, wildcard sources, missing frame-ancestors)
- HSTS (missing, low max-age < 31536000, missing includeSubDomains, missing preload)
- X-Frame-Options (missing, misconfigured)
- X-Content-Type-Options (missing nosniff)
- Referrer-Policy (missing, overly permissive)
- Permissions-Policy (missing, overly permissive)
- X-XSS-Protection (0 / missing)
- Cache-Control on sensitive endpoints (missing no-store / no-cache)

R4. Mutation & Evasion Strategies (at least 5 distinct strategies):
- Origin Casing Variations
- Protocol Smuggling
- Subdomain Injection Patterns
- Header Duplication & Folding
- Pre-flight Method/Header Enumeration

R5. Pipeline Connectivity:
- Wire collector into TaskGenerator DAG after endpoint discovery.
- Register as internal plugin in tool registry.
- Confirmed findings create HAS_VULNERABILITY edges on attack surface graph.
- Map CWE-942 for CORS findings, CWE-693 / CWE-1021 for header findings in cvss.py.

R6. Zero Regression & E2E Validation:
- All 1,740+ passing tests must continue to pass (`python -m pytest tests/ --ignore=tests/workspace -x -q`).
- Write at least 25 new tests covering all modes, header audit, false positive rejection, mutation strategies, and pipeline connectivity.
- Write handoff report to `.agents/sprint25_cors_headers/handoff.md`.
