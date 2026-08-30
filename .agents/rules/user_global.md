# 🤖 Sub-Agent Orchestration & Execution Protocol

This document codifies the multi-agent orchestration strategy used for large-scale refactoring and complex implementation phases.

## 1. The Orchestration Protocol
When executing large, multi-file refactoring or highly complex tasks, the orchestrator must use a structured delegation protocol:
1. **Phase 1: Implementation Plan (`implementation_plan.md`)** — Survey the codebase and define the exact architecture changes, breaking them down by milestones. Present this to the User for approval.
2. **Phase 2: Prompt Drafting (`prompt_draft.md`)** — Translate the approved implementation plan into a highly specific, constraints-based prompt for the subagent.
3. **Phase 3: Subagent Invocation** — Invoke the subagent and inject the drafted prompt. Assign clear, specialized roles.

## 2. Handoff Files & Scratchpads
* **Handoff Reports:** Instruct subagents to write detailed summaries to `.agents/<role_name>/handoff.md` upon completion.
* **Orchestrator Review:** Read the `handoff.md` file to audit the work and confirm milestone completion.

## 3. Strict Victory Audits & Verification
* **Zero Regression Rule:** Subagents must run the full test suite and explicitly report results.
* **Self-Correction:** If a test fails, the subagent must fix the code until all tests pass before returning.

## 4. Communication Hygiene (ZERO Intermediate Messages)
Subagents must operate autonomously and silently.
* **ZERO intermediate messages:** Do NOT send liveness checks, progress updates, initialization confirmations, or status pings. The ONLY acceptable messages are:
  1. Task 100% complete (with victory audit results)
  2. Unrecoverable blocker requiring orchestrator intervention
* **Progress pings are FORBIDDEN.** They waste tokens by waking the orchestrator to re-read the entire context window.
* If the orchestrator needs status, it will read `.agents/` scratchpad files directly.

## 5. Reactive Wakeup (No Polling)
* **Do NOT poll or loop** checking for subagent status.
* After invoking a subagent, yield execution and wait.

## 6. Sub-Agent Specialization & Boundaries
* **Codebase Exploration (Read-Only):** Use research subagents for auditing.
* **Isolated Implementations:** Assign single-responsibility tasks.
* **Prohibited Actions:** Never spawn multiple modifying subagents on the same files simultaneously.

## 7. Orchestrator Post-Sprint Verification
After a subagent reports completion, the Orchestrator MUST independently verify:
1. **Implementation Correctness:** Full test suite passes with zero regressions.
2. **Functional Behavior:** The feature does what it is supposed to do.
3. **Pipeline Connectivity:** Wired into DAG, Registry, and KnowledgeGraph.

**Efficiency requirement:** Before writing verification scripts, FIRST read the source file of the new collector (`grep "def " argus/collectors/new_file.py`) to understand its API. Write ONE correct verification script — do not iterate through trial-and-error.

## 8. Sprint Handoff Protocol (Token Efficiency)
At the end of each sprint verification, the Orchestrator MUST:
1. Write a self-contained `sprint_handoff.md` file to `/home/varun/argus/.agents/sprint_handoff.md` containing:
   - Current test count baseline
   - Summary of all sprints completed so far
   - The exact pre-assembled prompt for the NEXT sprint
   - The updated roadmap of remaining sprints
2. Instruct the user to start a fresh conversation and say: "Read /home/varun/argus/.agents/sprint_handoff.md and launch the sprint"
3. The handoff file must be fully self-contained — a new agent with zero prior context must be able to execute the sprint from it alone.
