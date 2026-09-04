## 2026-09-03T00:25:46Z
You are Worker 3: Workspace Copilot Blended Context Specialist.
Your working directory is: /home/varun/argus/.agents/worker_m3/
Read these files carefully before writing code:
- /home/varun/argus/.agents/ORIGINAL_REQUEST.md
- /home/varun/argus/PROJECT.md
- /home/varun/argus/.agents/explorer_3/handoff.md
- /home/varun/argus/.agents/worker_m1/handoff.md
- /home/varun/argus/.agents/worker_m2/handoff.md

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your task is to implement Milestone 3 (Requirement R4: Enhanced Workspace Copilot Integration):
1. `argus/workspace/context/models.py`:
   - Support `vector_score: Optional[float] = None` and ensure `ContextSource` handles `CVE_KNOWLEDGE`, `HISTORICAL_MEMORY`, `VECTOR_FINDING`, `VECTOR_EVIDENCE` semantic statuses and source types.
2. `argus/workspace/context/ranker.py`:
   - Upgrade `ContextRanker` to a Blended Context Ranker implementing hybrid score:
     $S_{\text{hybrid}} = w_{\text{vec}} \cdot S_{\text{vec}} + w_{\text{lex}} \cdot S_{\text{lex}} + S_{\text{scope}} + S_{\text{type}}$ ($w_{\text{vec}}=0.6, w_{\text{lex}}=0.4$).
   - CRITICAL: Ensure 100% backward compatibility. When vector score is absent or 0, $w_{\text{lex}}$ defaults to $1.0$ so all existing workspace context tests pass unchanged.
3. `argus/workspace/context/engine.py`:
   - Upgrade `ResearchContextEngine._retrieve_sources(query)` to query semantic vector sources (`VectorStore`, `FindingSemanticSearchEngine`, `CVEKnowledgeBase`) for evidence, findings, and CVE records, converting them to `ContextSource` with `vector_score` and proper project/mission isolation.
4. `argus/workspace/context/assembler.py`:
   - Extend `ContextAssembler` to render `### RELEVANT CVE & VULNERABILITY KNOWLEDGE` and `### RECALLED MEMORIES & HISTORICAL PATTERNS` prompt sections when present.
5. Create `tests/workspace/test_blended_context.py` containing comprehensive unit & integration tests covering:
   - Hybrid scoring and ranking behavior.
   - Pure lexical fallback when vector score is absent (backward compatibility).
   - Semantic retrieval in `ResearchContextEngine`.
   - Prompt assembly with CVE and memory context.
   - Mission and project isolation during vector retrieval.
6. Run test suite: `python3 -m pytest tests/workspace/ -v` and verify 100% pass across all workspace tests, plus `python3 -m pytest tests/ --ignore=tests/workspace -q` with zero regressions.

Write your final report and verification logs to `/home/varun/argus/.agents/worker_m3/handoff.md`.
Maintain `/home/varun/argus/.agents/worker_m3/progress.md`.
Operate silently and send a message back only upon completion.
