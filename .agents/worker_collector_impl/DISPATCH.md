## 2026-09-02T03:11:00Z
You are Worker 1 (API Security Core & Pipeline Worker) for the ARGUS API Security Testing Module.
Your working directory is `/home/varun/argus/.agents/worker_collector_impl`.

MANDATORY FIRST STEP:
Read `/home/varun/argus/.agents/ORIGINAL_REQUEST.md` (specifically requirements R1, R2, R3, R4, R5 for the API Security Testing Module).

Read the detailed blueprints and research reports from the survey explorers:
- `/home/varun/argus/.agents/explorer_survey_patterns/handoff.md` (detailed architecture, models, probers, analyzers for `api_security.py`)
- `/home/varun/argus/.agents/explorer_survey_pipeline/handoff.md` (exact diff blueprints for `task_generator.py`, `registry.py`, `plugins.py`, `attack_surface.py`, `cvss.py`)

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your Exclusive Write Ownership:
1. `argus/collectors/api_security.py`:
   - Implement Tripartite architecture:
     * Models & Enums: `APISecuritySeverity`, `APIVulnerabilityType`, `APIMutationStrategy`, `APIProbe`, `APIProbeResponse`, `APISecurityResult`, and compatibility aliases.
     * `APISecurityPayloadGenerator`: 6 detection modes (Parameter Tampering, Mass Assignment, Rate Limiting Bypass, BOLA/IDOR, Excessive Data Exposure, Method Tampering) + 5 mutation strategies (Content-Type Switching, Parameter Pollution, Header-Based Auth Bypass, Version Downgrade, Encoding Variations) + baseline and canary token generation.
     * `APISecurityProber`: Using `AuthenticatedHttpClient`, handling bursts, headers, auth tokens, differential identity checks, and timeouts.
     * `APISecurityAnalyzer`: Sensitive field detection (regexes for PII, keys, hashes, tokens), error disclosure (stack traces, SQL errors, internal paths), rate limit header parsing (`X-RateLimit-*`, `Retry-After`), and strict false positive rejection.
     * `APISecurityCollector`: Inherits `BaseCollector`, discovers endpoints/hosts/identities from mission, coordinates probing, and implements Quadruple State Publishing (`raw_mission.evidence`, `raw_mission.vulnerabilities`, `raw_mission.attack_surface_graph`, `ControlledMission.publish_finding`).
2. `argus/planning/task_generator.py`:
   - Add `"api_security"` to `_RECON_TEMPLATES` with dependency `["Discover API Endpoints"]` and `metadata={"tool_id": "api_security"}`.
   - Add API security keywords matching in `_resolve_template_for_gap` (under area_lower checks and TaskCategory.EVIDENCE_CORRELATION).
   - Add `"api_security"` to `from_gaps` tool_id tuple for binding `endpoints`.
3. `argus/runtime/registry.py`:
   - Add aliases for `api_security` in `ToolRegistry.get()`.
   - Register `Tool` with `id="api_security"` and capability `api_security_detector`.
4. `argus/runtime/plugins.py`:
   - Add fallback branch for `"api_security"` etc. in `_instantiate_specialist_fallback` BEFORE `"api" in plugin_id`.
5. `argus/graph/attack_surface.py`:
   - Add Section 27 for API security evidence categories creating `Node(type="vulnerability")` and `HAS_VULNERABILITY` / `HAS_ENDPOINT` edges.
6. `argus/reporting/cvss.py`:
   - Add CWE mappings in `CWE_DATABASE` (CWE-639 for BOLA/IDOR, CWE-915 for Mass Assignment, CWE-770 for Rate Limiting, CWE-602, CWE-200, CWE-650).
   - Update `_get_preset_vector` High and Medium bands.

Verify python syntax and module imports across all modified files.
Write a detailed handoff report to `/home/varun/argus/.agents/worker_collector_impl/handoff.md`.
Update `/home/varun/argus/.agents/worker_collector_impl/progress.md` upon completion.
When 100% finished, notify the orchestrator with send_message.
