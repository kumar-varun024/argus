## 2026-08-29T14:20:19Z
You are worker_impl_1, a specialized implementation engineer for ARGUS Sprint 6: Access Control / IDOR Engine.
Your working directory is `/home/varun/argus/.agents/sprint6_impl/`.
Target codebase root: `/home/varun/argus`

Read `/home/varun/argus/.agents/ORIGINAL_REQUEST.md`, `/home/varun/argus/.agents/PROJECT.md`, and `/home/varun/argus/.agents/orchestrator/implementation_plan.md`.

MANDATORY INTEGRITY WARNING — DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A forensic auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Code Ownership & Tasks:
1. `argus/http/coordinator.py`: Implement `MultiIdentitySessionCoordinator` and `MultiIdentityComparison` with isolated `AuthenticatedHttpClient` instances, cookie jar isolation, `execute_as`, `execute_across_identities`, `execute_comparison`, `authenticate_all`, `close_all`.
2. `argus/http/__init__.py`: Re-export `MultiIdentitySessionCoordinator`, `MultiIdentityComparison`.
3. `argus/analyzers/response_discrepancy.py`: Implement `ResponseDiscrepancyAnalyzer` and `DiscrepancyVerdict` with differential response comparison (`analyze_horizontal`, `analyze_vertical`, `analyze_header_bypass`, `is_error_or_login_response`, `extract_identity_leakage`).
4. `argus/analyzers/__init__.py`: Re-export `ResponseDiscrepancyAnalyzer`, `DiscrepancyVerdict`.
5. `argus/collectors/access_control.py`: Implement `AccessControlCollector` with horizontal IDOR, vertical privilege escalation, header bypass (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host`), evidence creation (`Evidence(category="broken_access_control", severity="critical")`), and graph node/edge creation (`HAS_VULNERABILITY`).
6. `argus/collectors/__init__.py`: Re-export `AccessControlCollector`.
7. `argus/planning/task_generator.py`: Add `access_control` template to `_RECON_TEMPLATES` with `dependencies=["Discover API Endpoints"]`, `category=TaskCategory.AUTHORIZATION_ANALYSIS`, `priority=0.81`.
8. `argus/runtime/registry.py`: Register `Tool(id="access_control", name="Access Control & IDOR Collector", capability="access_control_collector", ...)` in `ToolRegistry`.
9. `argus/runtime/plugins.py`: Add fallback in `PluginExecutorAdapter._instantiate_specialist_fallback()` returning `AccessControlCollector()`.
10. `argus/graph/attack_surface.py`: Add `category == "broken_access_control"` handling in `AttackSurfaceGraphBuilder.build_from_evidence()` to connect `HAS_VULNERABILITY` edges.
11. `tests/auth/test_multi_identity_coordinator.py`: Unit tests for multi-identity coordinator (session isolation, cookie independence, replay, fallback).
12. `tests/collectors/test_access_control.py`: Tests for IDOR, vertical escalation, header bypass, discrepancy analyzer, graph edge creation, graph rebuilding.
13. `tests/runtime/test_e2e_access_control.py`: End-to-end integration test verifying collector execution during mission loop, task scheduling, evidence generation, graph connectivity.

Acceptance Criteria:
- Run `python -m pytest tests/ --ignore=tests/workspace -x -q` and verify all 701+ existing tests pass with 0 regressions, plus >= 15 new tests pass (716+ total passing).
- Write full handoff report with verification commands and evidence to:
  - `/home/varun/argus/.agents/sprint6_idor/handoff.md`
  - `/home/varun/argus/.agents/sprint6_impl/handoff.md`
- Send a completion message to the orchestrator when finished.
