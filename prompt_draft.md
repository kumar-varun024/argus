# Prompt Drafting for Sprint 2 Subagents

## 1. Worker Prompt (Implementation Lead: M1, M2, M3)
- **Role**: `teamwork_preview_worker`
- **Working Directory**: `/home/varun/argus/.agents/worker_impl`
- **Assigned Files**:
  - `argus/graph/attack_surface.py` (New)
  - `argus/graph/diff.py` (New)
  - `argus/graph/graph.py`
  - `argus/graph/__init__.py`
  - `argus/runtime/mission.py`
  - `argus/runtime/mission_runtime.py`
  - `argus/planning/gap_analysis.py`
- **Mandatory Integrity Warning**:
  > DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## 2. Reviewer Prompts
- **Role**: `teamwork_preview_reviewer`
- **Working Directory**: `/home/varun/argus/.agents/reviewer_1` and `/home/varun/argus/.agents/reviewer_2`
- **Scope**: Verify correctness, completeness, interface contracts, and run build/tests.

## 3. Challenger Prompts
- **Role**: `teamwork_preview_challenger`
- **Working Directory**: `/home/varun/argus/.agents/challenger_1` and `/home/varun/argus/.agents/challenger_2`
- **Scope**: Adversarial test cases, stress testing idempotency, edge cases (empty inputs, strange schemes, circular references, large snapshots).

## 4. Forensic Auditor Prompt
- **Role**: `teamwork_preview_auditor`
- **Working Directory**: `/home/varun/argus/.agents/auditor_1`
- **Scope**: Static analysis, runtime tracing, and execution validation for non-cheating and genuine logic.
