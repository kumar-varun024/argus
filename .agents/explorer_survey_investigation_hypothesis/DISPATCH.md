## 2026-08-28T08:20:19Z

<USER_REQUEST>
Read /home/varun/argus/ORIGINAL_REQUEST.md.
Your working directory is /home/varun/argus/.agents/explorer_survey_investigation_hypothesis.
Task: Investigate R2 (Graph-Aware Investigation Building) and R3 (Graph-Aware Hypothesis Scoring).
1. Examine `argus/investigation/builder.py`, `argus/investigation/priority_engine.py`, and how investigations are built and prioritized.
2. How to use `KnowledgeGraph` to cluster and score investigations (e.g. hosts with more connections, or with `HAS_VULNERABILITY` edges, receive higher priority)?
3. Examine `argus/hypothesis/engine.py`, `argus/hypothesis/scorer.py`, `argus/hypothesis/ranker.py`.
4. How to use `KnowledgeGraph` in `HypothesisEngine` confidence scorer and ranker so hypothesis confidence is weighted by graph connectivity (well-connected host vs isolated node)?
5. Trace how `AutonomousMissionRuntime` calls investigation building and hypothesis generation (`BUILDING_INVESTIGATIONS`, `GENERATING_HYPOTHESES`).
6. Propose exact interface signatures, priority formulas, scoring formulas, and test cases for R2 and R3.
7. Write a thorough handoff report to `/home/varun/argus/.agents/explorer_survey_investigation_hypothesis/handoff.md`.
8. Send a completion message to the parent with your findings and the handoff file path.
</USER_REQUEST>
