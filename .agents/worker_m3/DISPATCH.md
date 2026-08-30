## 2026-08-30T07:51:00Z
You are Worker 3 (Pipeline & Graph Integration Specialist) for Sprint 10 Milestone 3.
Your working directory is /home/varun/argus/.agents/worker_m3

You MUST read /home/varun/argus/.agents/ORIGINAL_REQUEST.md and /home/varun/argus/PROJECT.md before doing anything else.
You should also read the architectural specification at /home/varun/argus/.agents/survey_pipeline_explorer/handoff.md.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your Exclusive File Ownership:
- `argus/runtime/registry.py`
- `argus/runtime/plugins.py`
- `argus/planning/task_generator.py`
- `argus/graph/attack_surface.py`

Your Mission:
1. `argus/runtime/registry.py`:
   Register tool `xss` (and ensure lookup by aliases `cross_site_scripting` works if queried):
   ```python
   registry.register(
       Tool(
           id="xss",
           name="Cross-Site Scripting (XSS) Collector",
           capability="xss_detector",
           description="Actively injects context-aware XSS payloads into discovered endpoint parameters and forms detecting reflected and stored XSS using AuthenticatedHttpClient.",
           supported_tasks=["XSS Detection", "Cross-Site Scripting", "Vulnerability Scanning", "Evidence Correlation", "API Discovery"],
           required_inputs=["endpoints"],
           produced_outputs=["vulnerabilities", "observations", "evidence"],
           capabilities=["xss_detector", "xss_collector"],
           safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
           timeout=300.0,
           priority=95,
       )
   )
   ```
2. `argus/runtime/plugins.py`:
   In `PluginExecutorAdapter._instantiate_specialist_fallback`:
   Add:
   ```python
   elif "xss" in plugin_id or "cross_site_scripting" in plugin_id:
       from argus.collectors.xss import XSSCollector
       return XSSCollector()
   ```
3. `argus/planning/task_generator.py`:
   - Add template `"xss"` to `_RECON_TEMPLATES`:
     ```python
     "xss": {
         "title": "Fuzz Cross-Site Scripting (XSS)",
         "goal": "Actively inject context-aware XSS payloads into discovered endpoint parameters and forms detecting reflected and stored XSS using AuthenticatedHttpClient.",
         "category": TaskCategory.EVIDENCE_CORRELATION,
         "required_inputs": ["endpoints"],
         "expected_outputs": ["vulnerabilities", "observations", "evidence"],
         "dependencies": ["Discover API Endpoints"],
         "required_specialists": [],
         "metadata": {"tool_id": "xss"},
         "estimated_duration_minutes": 10,
         "priority": 0.81,
     }
     ```
   - In `_resolve_template_for_gap`:
     - Map `area_lower in ("xss", "xss detection", "cross site scripting", "cross-site scripting", "stored xss", "reflected xss", "dom xss")` -> `_RECON_TEMPLATES["xss"]`.
     - In `gap.category == TaskCategory.EVIDENCE_CORRELATION`:
       `if "xss" in gap_desc_lower or "cross-site" in gap_desc_lower or "scripting" in gap_desc_lower: return _RECON_TEMPLATES["xss"]`.
   - In `from_gaps`:
     Add `"xss"` to `elif tool_id in ("katana_crawler", "nuclei", "info_disclosure", "access_control", "path_traversal", "sql_injection", "xss"):`.
4. `argus/graph/attack_surface.py`:
   - In `AttackSurfaceGraphBuilder.build_from_evidence()`:
     Add handler for `getattr(ev, "category", None) in ("xss", "cross_site_scripting")`:
     - Extract `target_url`, `base_url`, `template_id`, `param_name`, `xss_type`.
     - Severity mapping: Stored XSS -> `"critical"`, Reflected XSS -> `"high"`, DOM/header -> `"medium"`.
     - Create and register `live_host`, `endpoint`, and `vulnerability` nodes in graph.
     - Connect `live_host -> endpoint` with `HAS_ENDPOINT`.
     - Connect `live_host -> vulnerability` with `HAS_VULNERABILITY`.
     - Connect `endpoint -> vulnerability` with `HAS_VULNERABILITY`.
5. Run tests:
   - `python -m pytest tests/graph/test_attack_surface_builder.py tests/planning/test_task_generator.py -v`
   - `python -m pytest tests/collectors/test_xss.py tests/tools/test_environment_detector.py -v`
   - `python -m pytest tests/ --ignore=tests/workspace -x -q`
6. Write handoff report to `/home/varun/argus/.agents/worker_m3/handoff.md`.
7. Send a final completion message to the orchestrator.
