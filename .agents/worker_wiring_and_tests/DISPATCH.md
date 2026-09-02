## 2026-09-01T17:21:48Z

You are the Worker subagent for the ARGUS project.
Your working directory is `/home/varun/argus/.agents/worker_wiring_and_tests`.
Please read `/home/varun/argus/.agents/ORIGINAL_REQUEST.md` and `/home/varun/argus/PROJECT.md`.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Context:
`argus/collectors/cors_headers.py` has been implemented with `CORSSecurityCollector`, `CORSProber`, `CORSAnalyzer`, `HTTPHeaderAuditor`, `CORSPayloadGenerator`, enums, and models.

Your task:
1. Inspect `argus/collectors/cors_headers.py` and ensure `CORSHeadersCollector` alias is exported.
2. Update `argus/collectors/__init__.py` to import and export:
   `CORSSecurityCollector`, `CORSHeadersCollector`, `CORSProber`, `HeaderAuditor`, `HTTPHeaderAuditor`, `CORSMutationGenerator`, `CORSPayloadGenerator`, `CORSAnalyzer`.
3. Update `argus/runtime/registry.py`:
   Register `Tool(id="cors_headers", name="CORS & HTTP Security Header Auditor", version="1.0.0", capability="cors_headers", description="...", supported_tasks=["Validate CORS Security", "Audit HTTP Security Headers", "cors", "security_headers"], required_inputs=["endpoints"], produced_outputs=["vulnerabilities", "observations", "evidence"], capabilities=["cors", "cors_security", "cors_misconfiguration", "security_headers", "http_headers", "header_audit", "csp", "hsts"], safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]}, timeout=300.0, priority=95)`.
   Add alias mappings in `ToolRegistry.get()` for `"cors"`, `"cors_security"`, `"cors_collector"`, `"cors_headers"`, `"cors_headers_collector"`, `"cors_misconfiguration"`, `"security_headers"`, `"http_headers"`, `"header_audit"`, `"header_auditor"`, `"security_header_collector"`.
4. Update `argus/runtime/plugins.py`:
   In `PluginExecutorAdapter._instantiate_specialist_fallback(plugin_id)`, add branch for `"cors"` / `"security_header"` returning `CORSSecurityCollector()`.
5. Update `argus/planning/task_generator.py`:
   Add `"cors_headers"` in `_RECON_TEMPLATES` (dependencies: `["Discover API Endpoints"]`, required_inputs: `["endpoints"]`, priority: 0.81, produces: `["vulnerabilities", "observations", "evidence"]`).
   Add keyword routing in `_resolve_template_for_gap` matching `"cors"`, `"cors security"`, `"cors misconfiguration"`, `"security headers"`, `"http security headers"`, `"csp"`, `"hsts"`.
   Add `"cors_headers"` in `from_gaps` endpoint input resolution tuple.
6. Update `argus/scanning/engine.py`:
   Add `"cors_headers"`, `"cors"`, `"cors_security"`, `"security_headers"` to `collector_class_map` mapping to `"CORSSecurityCollector"`.
7. Update `argus/graph/attack_surface.py`:
   Ensure evidence categories `"cors"`, `"cors_misconfiguration"`, `"security_headers"`, `"missing_security_headers"` create `vulnerability` nodes with `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges.
8. Update `argus/reporting/cvss.py`:
   Add `CWE-693` ("Protection Mechanism Failure") and `CWE-1021` ("Improper Restriction of Rendered UI Layers or Frames ('Clickjacking')") to `CWE_DATABASE`.
   Ensure CORS maps to `CWE-942`.
   Ensure preset vectors calibrate severities: Critical (wildcard+credentials), High (reflected origin+credentials), Medium (missing CSP), Low (missing nosniff / referrer-policy).
9. Create `tests/collectors/test_cors_headers.py`:
   Write at least 25 new comprehensive, deterministic, fast unit tests covering:
   - Data models, enums, dataclasses, and serialization
   - Mutation Generator (5+ mutation strategies: casing, protocol smuggling, subdomain injection, header folding, preflight enumeration)
   - CORS Analyzer: all 6 detection modes (origin reflection, null origin, wildcard+credentials, subdomain trust abuse, preflight bypass, parser differential)
   - False positive rejection: same-origin reflection suppressed, unauthenticated wildcard CORS on public endpoints suppressed, HSTS on plain HTTP suppressed, static file cache-control suppressed, XFO suppressed when CSP frame-ancestors present
   - HTTP Security Header Auditor: CSP missing & weak directives (unsafe-inline, unsafe-eval, wildcard, missing frame-ancestors), HSTS missing & low max-age (< 31536000), X-Frame-Options missing & misconfigured, X-Content-Type-Options nosniff check, Referrer-Policy checks, Permissions-Policy checks, X-XSS-Protection checks, Cache-Control on sensitive endpoints
   - Collector execution: `collect(mission)` and `execute(mission)`, endpoint harvesting, mock HTTP client probing, Quadruple State Mutation (`mission.evidence`, `mission.vulnerabilities`, `mission.attack_surface_graph` with `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges, `publish_finding`)
   - Tool registry lookup and alias resolution
   - TaskGenerator DAG integration and topological sort order
   - CVSS and CWE database mappings
10. Run tests:
    - Run `python -m pytest tests/collectors/test_cors_headers.py -v`
    - Run full test suite: `python -m pytest tests/ --ignore=tests/workspace -x -q` (ensure all 1,740+ tests pass with 0 failures).

Write a comprehensive handoff report to `/home/varun/argus/.agents/worker_wiring_and_tests/handoff.md` and notify via `send_message`.
