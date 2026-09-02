# DISPATCH — 2026-09-01T23:00:39Z

## Assignment
Pipeline & Graph Integration for CORS & HTTP Security Header Audit Module:
1. `argus/collectors/__init__.py`:
   Export `CORSSecurityCollector`, `CORSHeadersCollector`, `CORSProber`, `HeaderAuditor`, `HTTPHeaderAuditor`, `CORSMutationGenerator`, `CORSPayloadGenerator`, `CORSAnalyzer`.
2. `argus/runtime/registry.py`:
   Register `Tool(id="cors_headers", name="CORS & HTTP Security Header Auditor", version="1.0.0", capability="cors_headers", description="Actively audits CORS misconfigurations and HTTP security response headers across discovered endpoints and live hosts.", supported_tasks=["Validate CORS Security", "Audit HTTP Security Headers", "cors", "security_headers"], required_inputs=["endpoints"], produced_outputs=["vulnerabilities", "observations", "evidence"], capabilities=["cors", "cors_security", "cors_misconfiguration", "security_headers", "http_headers", "header_audit", "csp", "hsts"], safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]}, timeout=300.0, priority=95)`.
   In `ToolRegistry.get()`, add alias mappings for `"cors"`, `"cors_security"`, `"cors_collector"`, `"cors_headers"`, `"cors_headers_collector"`, `"cors_misconfiguration"`, `"security_headers"`, `"http_headers"`, `"header_audit"`, `"header_auditor"`, `"security_header_collector"`.
3. `argus/runtime/plugins.py`:
   In `PluginExecutorAdapter._instantiate_specialist_fallback(plugin_id)`, add branch for `"cors"` / `"security_header"` returning `CORSSecurityCollector()`.
4. `argus/planning/task_generator.py`:
   In `_RECON_TEMPLATES`, add `"cors_headers"` task definition:
   - title: `"Audit CORS & HTTP Security Headers"`
   - category: `TaskCategory.EVIDENCE_CORRELATION` (or appropriate enum)
   - dependencies: `["Discover API Endpoints"]`
   - required_inputs: `["endpoints"]`
   - produced_outputs: `["vulnerabilities", "observations", "evidence"]`
   - priority: `0.81`
   - metadata: `{"tool_id": "cors_headers"}`
   In `_resolve_template_for_gap()`, map keywords (`"cors"`, `"cors security"`, `"cors misconfiguration"`, `"security headers"`, `"http security headers"`, `"csp"`, `"hsts"`) to `_RECON_TEMPLATES["cors_headers"]`.
   In `from_gaps()`, include `"cors_headers"` in the tool_id tuple checking for endpoint inputs.
5. `argus/scanning/engine.py`:
   Add `"cors_headers"`, `"cors"`, `"cors_security"`, `"security_headers"` to `collector_class_map` mapping to `"CORSSecurityCollector"`.
6. `argus/graph/attack_surface.py`:
   In `AttackSurfaceGraphBuilder`, ensure evidence categories `"cors"`, `"cors_misconfiguration"`, `"security_headers"`, `"missing_security_headers"` create `vulnerability` nodes and connect `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges.
7. `argus/reporting/cvss.py`:
   In `CWE_DATABASE`, add:
   - `"CWE-693": CWEInfo("CWE-693", "Protection Mechanism Failure")`
   - `"CWE-1021": CWEInfo("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames ('Clickjacking')")`
   Ensure category `"cors"` maps to `CWE-942`, `"security_headers"` / `"csp"` / `"hsts"` map to `CWE-693`, `"clickjacking"` / `"xfo"` map to `CWE-1021`.
   In `_get_preset_vector`, add presets for CORS (High/Critical) and Security Headers (Medium/Low).
8. Run python import checks to verify all modified modules load cleanly without syntax or import errors.
