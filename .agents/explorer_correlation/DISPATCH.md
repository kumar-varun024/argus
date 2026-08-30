## 2026-08-28T07:05:04Z

Investigate the Correlation Engine and graph integration requirements (Requirement R1 and related acceptance criteria).
Files to inspect:
- `argus/correlation/engine.py` — `CorrelationEngine.process_observation()`, internal `CorrelationGraph`
- `argus/correlation/matcher.py` — `CorrelationMatcher`, `match_shared_graph_nodes`
- `argus/correlation/rules.py` — correlation rules
- `argus/correlation/fusion.py` — `EvidenceFusionEngine.process_mission_state()`
- `argus/graph/graph.py` — `KnowledgeGraph` methods and edge/node models
- `argus/graph/attack_surface.py` — `AttackSurfaceGraphBuilder`
- `argus/runtime/mission_runtime.py` — `AutonomousMissionRuntime.step()` during `CORRELATING`
- Existing correlation tests in `tests/correlation/`

Investigate:
1. How does `CorrelationEngine` currently receive or ignore `mission.attack_surface_graph`?
2. How is `match_shared_graph_nodes` currently implemented in `matcher.py` / `rules.py`?
3. What methods on `KnowledgeGraph` exist (or need to exist) to query topological neighborhoods (same host, subdomain subgraph, connected nodes)?
4. How should two observations referencing nodes in the same host subgraph be correlated?
5. How does the mission loop pass the graph into `CorrelationEngine` / `EvidenceFusionEngine`?
6. Run the current correlation tests (e.g. `pytest tests/correlation/ -v`) to check current status and structure.
