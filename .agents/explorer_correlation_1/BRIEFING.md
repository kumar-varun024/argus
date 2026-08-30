# BRIEFING — 2026-08-28T07:44:00Z

## Mission
Investigate the Correlation subsystem for ARGUS Sprint 3 (CorrelationEngine, CorrelationMatcher, rules, EvidenceFusionEngine, tests) and produce a detailed investigation report.

## 🔒 My Identity
- Archetype: explorer
- Roles: explorer_correlation
- Working directory: /home/varun/argus/.agents/explorer_correlation_1
- Original parent: 20873a95-5ff7-4f2c-a08c-738f6f7a7783
- Milestone: Sprint 3 Correlation Investigation

## 🔒 Key Constraints
- Read-only investigation — do NOT implement / modify source code
- Self-contained handoff with 5 components
- Silent execution until completion

## Current Parent
- Conversation ID: 20873a95-5ff7-4f2c-a08c-738f6f7a7783
- Updated: not yet

## Investigation State
- **Explored paths**:
  - `argus/correlation/engine.py` (`CorrelationEngine`)
  - `argus/correlation/matcher.py` (`CorrelationMatcher`)
  - `argus/correlation/rules.py` (12 default matching rules)
  - `argus/correlation/fusion.py` (`EvidenceFusionEngine`)
  - `argus/correlation/graph.py` (`CorrelationGraph`)
  - `argus/correlation/scoring.py` (`CorrelationScorer`)
  - `argus/correlation/strength.py` (`EvidenceStrengthScorer`)
  - `argus/correlation/confidence.py` (`ConfidenceCalculator`)
  - `argus/correlation/deduplication.py` (`EvidenceDeduplicator`)
  - `argus/correlation/observation.py` (`Observation`)
  - `argus/correlation/correlation.py` (`Correlation`)
  - `argus/correlation/evidence.py` (`EvidenceBundle`)
  - `argus/correlation/registry.py` (Observation, Correlation, EvidenceBundle registries)
  - `argus/graph/graph.py` (`KnowledgeGraph`)
  - `argus/graph/attack_surface.py` (`AttackSurfaceGraphBuilder`)
  - `argus/runtime/mission.py` (`Mission`, `MissionState`)
  - `argus/runtime/mission_runtime.py` (`AutonomousMissionRuntime`)
  - `argus/runtime/controller.py` (`MissionController`)
  - `tests/correlation/` (14 test suites)
  - `tests/runtime/test_e2e_mission.py`
- **Key findings**:
  1. `CorrelationEngine` currently maintains an internal `CorrelationGraph` (NetworkX DiGraph linking Observation <-> Observation and Observation -> Correlation). It does not receive or use `KnowledgeGraph`.
  2. `CorrelationMatcher` evaluates 12 rules (`DEFAULT_RULES`). All 12 take `(obs1, obs2) -> bool`. `match_shared_graph_nodes` currently does a shallow string set intersection (`set(obs1.graph_nodes) & set(obs2.graph_nodes)`).
  3. `KnowledgeGraph` has topology traversal query methods (`in_same_host_subgraph`, `are_connected`, `get_host_for_node`, `get_node_degree`, `get_connected_endpoints`).
  4. Passing `KnowledgeGraph` to `CorrelationEngine` and `CorrelationMatcher`, upgrading `match_shared_graph_nodes`, and adding graph-neighborhood matching enables topological correlation of disparate observations on the same host subgraph.
  5. In `AutonomousMissionRuntime.step()`, observations generated from evidence during `CORRELATING` must populate `graph_nodes` (matching node IDs built by `AttackSurfaceGraphBuilder`).
  6. `EvidenceFusionEngine.process_mission_state()` fuses observations and correlations into `EvidenceBundle`s using 9 fusion rules.
- **Unexplored areas**: None within correlation scope.

## Key Decisions Made
- Completed deep inspection of correlation engine, matcher, rules, fusion engine, graph structures, and existing test suites.
- Formulated concrete, zero-regression graph traversal design for `match_shared_graph_nodes`, `match_graph_neighborhood`, `CorrelationMatcher`, `CorrelationEngine`, and runtime loop.

## Artifact Index
- /home/varun/argus/.agents/explorer_correlation_1/DISPATCH.md — Dispatch log
- /home/varun/argus/.agents/explorer_correlation_1/progress.md — Progress tracker
- /home/varun/argus/.agents/explorer_correlation_1/BRIEFING.md — Situational awareness
- /home/varun/argus/.agents/explorer_correlation_1/handoff.md — Final 5-component report
