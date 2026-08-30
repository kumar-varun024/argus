## 2026-08-28T08:20:19Z
Read /home/varun/argus/ORIGINAL_REQUEST.md.
Your working directory is /home/varun/argus/.agents/explorer_survey_correlation.
Task: Investigate R1 (Graph-Aware Correlation Engine).
1. Examine `argus/correlation/engine.py`, `argus/correlation/matcher.py`, `argus/correlation/rules.py`, `argus/correlation/fusion.py`.
2. Examine `argus/graph/graph.py` and `argus/graph/attack_surface.py` to see what KnowledgeGraph query methods exist (e.g. neighbors, paths, connectivity).
3. Trace how `CorrelationEngine.correlate(...)` is currently called in `AutonomousMissionRuntime._execute_correlating(...)` or similar runtime phases.
4. How should `KnowledgeGraph` (or `mission.attack_surface_graph`) be passed to `CorrelationEngine` and `CorrelationMatcher`?
5. Analyze the `match_shared_graph_nodes` rule and any graph-neighborhood matching rule: how two observations should be correlated if they reference entities topologically connected in the graph (e.g. shortest path, neighbor traversal, shared parent/child).
6. Propose exact interface signatures, rule implementations, and test cases needed for R1.
7. Write a thorough handoff report to `/home/varun/argus/.agents/explorer_survey_correlation/handoff.md`.
8. Send a completion message to the parent with your findings and the handoff file path.
