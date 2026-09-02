## 2026-09-02T05:57:26Z

You are the Core Architecture & Pipeline Specialist Worker for Milestone 1 of the ARGUS platform sprint: Authentication Bypass & Credential Attack Detection Module.

Working Directory: /home/varun/argus
Agent Working Directory: /home/varun/argus/.agents/worker_m1_core
Original Request: /home/varun/argus/.agents/ORIGINAL_REQUEST.md
Project Plan: /home/varun/argus/PROJECT.md
Reference Surveys:
- /home/varun/argus/.agents/explorer_survey_arch/handoff.md
- /home/varun/argus/.agents/explorer_survey_pipeline/handoff.md
- /home/varun/argus/.agents/spec_miner_survey/handoff.md

Your exclusive write ownership for this milestone:
- `argus/collectors/auth_bypass.py` (CREATE)
- `argus/collectors/__init__.py` (EDIT)
- `argus/planning/task_generator.py` (EDIT)
- `argus/runtime/registry.py` (EDIT)
- `argus/runtime/plugins.py` (EDIT)
- `argus/scanning/dag.py` (EDIT)
- `argus/scanning/engine.py` (EDIT)
- `argus/graph/attack_surface.py` (EDIT)
- `argus/reporting/cvss.py` (EDIT)

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Mission Objectives:
1. Implement `argus/collectors/auth_bypass.py`:
   - `AuthVulnerabilityType` enum (covering BRUTE_FORCE, PASSWORD_RESET, MFA_BYPASS, SESSION_FIXATION, JWT_MANIPULATION, DEFAULT_CREDENTIALS, SESSION_TOKEN_ANALYSIS, CREDENTIAL_STUFFING, EVASION).
   - Dataclasses: `AuthBypassProbe`, `AuthBypassProbeResponse`, `AuthBypassResult`.
   - `AuthBypassCollector(BaseCollector)` with complete endpoint discovery (`_discover_candidate_endpoints`), probe execution loop, `collect(mission)`, `execute(mission)`, and Quadruple State Publishing in `_emit_evidence(...)` updating `raw_mission.evidence`, `raw_mission.vulnerabilities`, `attack_surface_graph` KnowledgeGraph (`HAS_ENDPOINT` and `HAS_VULNERABILITY` edges), and `ControlledMission.publish_finding`.
   - `AuthBypassPayloadGenerator` skeleton with canary generator (`generate_canary`), benign baseline generator (`generate_benign_baseline_probes`), method hooks for all 6 detection modes and 5 evasion strategies, and `generate_all_probes`.
   - `AuthBypassProber` with `execute_probe`, `execute_burst_sequence`, `execute_differential_identity_probe`, handling polymorphic `AuthenticatedHttpClient` and mock clients.
   - `AuthBypassAnalyzer` with `is_false_positive` (strict suppression of benign baselines, standard 401/403/429 rejections without leaks, error handling), sensitive credential detection, error disclosure regexes, and `evaluate_probe`.
2. Update `argus/collectors/__init__.py` to export `AuthBypassCollector`, `AuthBypassPayloadGenerator`, `AuthBypassProber`, `AuthBypassAnalyzer`.
3. Update `argus/planning/task_generator.py`:
   - Add `"auth_bypass"` template to `_RECON_TEMPLATES` with dependencies on `["Discover API Endpoints"]` and category `TaskCategory.AUTHENTICATION_ANALYSIS`.
   - Update `_resolve_template_for_gap` to match authentication gaps and auth keywords (`auth`, `login`, `jwt`, `session`, `mfa`, `credential`).
   - Update `from_gaps` to populate required inputs.
4. Update `argus/runtime/registry.py` and `argus/runtime/plugins.py`:
   - Register `Tool(id="auth_bypass", ...)` in `registry` with aliases (`authentication_bypass`, `credential_attack`, `jwt`, `session_fixation`, `password_reset`, `mfa_bypass`, `default_credentials`).
   - Add fallback instantiation in `PluginExecutorAdapter._instantiate_specialist_fallback`.
5. Update `argus/scanning/dag.py` and `argus/scanning/engine.py` to ensure `auth_bypass` maps cleanly in `collector_class_map`.
6. Update `argus/graph/attack_surface.py`:
   - Add category matching for `auth_bypass`, `authentication`, `credential_attack` in `AttackSurfaceGraphBuilder.build_from_evidence` and ensure proper `HAS_VULNERABILITY` and `HAS_ENDPOINT` graph edges.
7. Update `argus/reporting/cvss.py`:
   - Add entries in `CWE_DATABASE` and vector presets for CWE-287, CWE-307, CWE-384, CWE-640, CWE-288, CWE-1390, CWE-798, CWE-522, CWE-613.
