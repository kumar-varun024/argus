# BRIEFING — 2026-09-01T17:10:00Z

## Mission
Explore and analyze BaseCollector architecture, lifecycle, interface conventions, AuthenticatedHttpClient/HTTP client utilities, active collector probing/response inspection/finding emission patterns, error handling, rate limiting/timeouts, and data structures.

## 🔒 My Identity
- Archetype: explorer
- Roles: Explorer 1 (Codebase Architecture & Collectors)
- Working directory: /home/varun/argus/.agents/explorer_survey_1
- Original parent: ac325e58-b49d-49f7-85f0-4322a0e92502
- Milestone: codebase-survey

## 🔒 Key Constraints
- Read-only investigation — do NOT implement or modify source code files
- Write analysis report to /home/varun/argus/.agents/explorer_survey_1/handoff.md
- Maintain progress.md as heartbeat

## Current Parent
- Conversation ID: ac325e58-b49d-49f7-85f0-4322a0e92502
- Updated: 2026-09-01T17:10:00Z

## Investigation State
- **Explored paths**:
  - `argus/collectors/base.py`
  - `argus/collectors/` (`cache_security.py`, `websocket.py`, `graphql.py`, `deserialization.py`, `sql_injection.py`, `xss.py`, `oauth.py`, `ssrf.py`, `command_injection.py`, `access_control.py`, `__init__.py`)
  - `argus/http/client.py` (`AuthenticatedHttpClient`, `AuthorizedHttpClient`, `HttpResponse`)
  - `argus/evidence/model.py` (`Evidence`, `ProvenanceData`)
  - `argus/graph/node.py`, `argus/graph/graph.py`, `argus/graph/attack_surface.py` (`KnowledgeGraph`, `Node`, `AttackSurfaceGraphBuilder`)
  - `argus/planning/task_generator.py` (`TaskGenerator`, `_RECON_TEMPLATES`)
  - `argus/runtime/registry.py` (`ToolRegistry`, `Tool`)
  - `argus/runtime/plugins.py` (`PluginExecutorAdapter`)
  - `argus/runtime/mission.py` (`Mission`, `MissionState`)
  - `argus/plugins/interfaces.py` (`ControlledMission`, `BasePlugin`)
  - `argus/reporting/cvss.py` (`CVSSCalculator`, `CWE_DATABASE`)
  - `tests/collectors/` (`test_cache_security.py`, `test_websocket.py`, etc.)
- **Key findings**:
  - `BaseCollector` defines `@abstractmethod def collect(self, mission: Any) -> List[Evidence]`.
  - Active collectors implement `collect(mission)` and alias `execute(mission)`.
  - Endpoint discovery uses `_discover_candidate_endpoints(mission)` extracting from `mission.endpoints`, `mission.live_hosts`, `mission.target`, and `mission.evidence`.
  - Probers utilize polymorphic HTTP dispatch supporting both mock clients (callable, `.get()`, `.post()`, `.request()`, `.options()`) and production `AuthenticatedHttpClient(timeout=..., max_retries=1)` context managers.
  - Emission follows the Quadruple State Publishing standard (`mission.evidence`, `mission.vulnerabilities`, `attack_surface_graph`, `ControlledMission.publish_finding`).
  - Pipeline integration is standardized across `TaskGenerator`, `ToolRegistry`, `PluginExecutorAdapter`, `AttackSurfaceGraphBuilder`, and `CVSSCalculator`.
- **Unexplored areas**: None for collector architecture survey.

## Key Decisions Made
- Fully cataloged all collector conventions, prober architectures, HTTP dispatch rules, evidence schemas, and graph wiring rules.

## Artifact Index
- /home/varun/argus/.agents/explorer_survey_1/DISPATCH.md — Dispatch history
- /home/varun/argus/.agents/explorer_survey_1/progress.md — Liveness heartbeat
- /home/varun/argus/.agents/explorer_survey_1/handoff.md — Final investigation report
