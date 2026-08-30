# BRIEFING — 2026-08-28T08:23:00Z

## Mission
Investigate R1 (Graph-Aware Correlation Engine) across argus/correlation, argus/graph, and mission runtime, and produce a detailed architectural proposal and handoff report.

## 🔒 My Identity
- Archetype: Teamwork explorer
- Roles: Codebase Investigator, Architecture Analyst, Synthesis
- Working directory: /home/varun/argus/.agents/explorer_survey_correlation
- Original parent: 8641e78b-540c-4e37-89b6-010068e8774e
- Milestone: Survey & Architectural Design for R1 (Graph-Aware Correlation Engine)

## 🔒 Key Constraints
- Read-only investigation — do NOT implement in source files
- All output in `.agents/explorer_survey_correlation/`
- Communicate findings and handoff report via `send_message` to parent

## Current Parent
- Conversation ID: 8641e78b-540c-4e37-89b6-010068e8774e
- Updated: 2026-08-28T08:23:00Z

## Investigation State
- **Explored paths**:
  - `argus/correlation/engine.py`, `matcher.py`, `rules.py`, `fusion.py`, `graph.py`, `scoring.py`, `models.py`
  - `argus/graph/graph.py`, `attack_surface.py`
  - `argus/runtime/controller.py`, `mission_runtime.py`, `executor.py`
  - `tests/correlation/test_*.py`
- **Key findings**:
  - `CorrelationEngine` currently lacks `knowledge_graph` and relies on string-only rules in `rules.py`.
  - `KnowledgeGraph` has `in_same_host_subgraph`, `are_connected`, `get_host_for_node`, `neighbors`, `get_node_degree`.
  - `match_shared_graph_nodes` must be upgraded to support both string fallback and graph traversal.
  - `match_graph_neighborhood` must be added to `DEFAULT_RULES`.
  - In `AutonomousMissionRuntime.step()` under `CORRELATING`, `knowledge_graph` must be synchronized to `CorrelationEngine` and `obs.graph_nodes` populated.
- **Unexplored areas**: None for R1 scope.

## Key Decisions Made
- Fully specified interface signatures, rule implementations, and test plan in `handoff.md`.

## Artifact Index
- `/home/varun/argus/.agents/explorer_survey_correlation/DISPATCH.md` — Inbound dispatch log
- `/home/varun/argus/.agents/explorer_survey_correlation/BRIEFING.md` — Persistent briefing
- `/home/varun/argus/.agents/explorer_survey_correlation/progress.md` — Progress heartbeat
- `/home/varun/argus/.agents/explorer_survey_correlation/handoff.md` — Completed handoff report
