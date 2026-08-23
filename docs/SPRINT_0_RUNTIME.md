# Sprint 0: Runtime Plumbing Architecture

## Overview
This document describes the runtime plumbing implementation for Argus as completed in Sprint 0. The goal of Sprint 0 was to construct a robust, deterministic, event-driven, and testable orchestrator loop for executing AI-driven security missions.

## Core Architectural Changes

### 1. `AutonomousMissionRuntime` Refactoring
The central `step()` loop in `AutonomousMissionRuntime` was refactored to use an explicit, strict sequential state execution model. This prevents "infinite loops" where the state machine could fall through or improperly replay logic based on boolean threshold checks alone.

The execution loop sequentially processes phases:
- **PLANNING**: Evaluates the mission scope and plans out research tasks. Transition is made directly to `RESEARCHING` after planning finishes.
- **RESEARCHING**: Evaluates pending tasks, schedules them, executes batches, collects raw results, and parses them via the `ToolOrchestrator` into evidence.
- **COLLECTING_EVIDENCE**: Bridges raw tool outcomes into internal state updates.
- **CORRELATING**: Merges evidence into normalized `Observation` models, tracking correlated evidence by ID safely without mutating read-only schemas (like `slots=True` dataclasses).
- **BUILDING_INVESTIGATIONS**: Feeds correlated observations to the `InvestigationBuilder` to form higher-level strategic investigation branches.
- **GENERATING_HYPOTHESES**: Consumes investigations to formulate and rank working hypotheses. Once the execution queue is empty, triggers a checkpoint evaluation for completion, ending the loop gracefully.

### 2. State Machine Hardening
The `MissionStateMachine` provides deterministic transition rules. State overrides and arbitrary jumps are strictly prohibited, ensuring tasks always execute within their defined context window (e.g., executing tools in `RESEARCHING` only).

### 3. Execution Phase Bug Fixes
Several logical gaps were resolved in the integration tests:
- **Null Reference Handing:** Ensured `EvidenceStore` boolean casting errors didn't drop evidence when tracking findings.
- **Dataclass slot preservation:** Avoided dynamic attribute assignment (e.g., `_correlated`) on `slots=True` dataclass models. Replaced with instance-level `_correlated_evidence_ids` sets.
- **Planner Signature Correctness:** The `MissionPlanner.analyze()` and `ResearchPlanner.plan()` method signatures were corrected, removing redundant `mission` passing since context is managed at class boundaries.

### 4. Integration Test Success
We implemented a robust local integration script `tests/runtime/test_e2e_mission.py` that utilizes an isolated, clean ToolRegistry to route simulated inputs (like HTTPX and Subfinder output) through the pipeline. The successful execution proves:
1. Tool scheduling properly respects priority.
2. Tools route to the `ExternalToolExecutor`.
3. Output is parsed by `ReconParser` and collected in the `EvidenceStore`.
4. The mission completes gracefully without getting stuck in endless plan/research loops.

## Event System & Observability
The `EventBus` has been successfully integrated, providing global state visibility without tight coupling. Event types like `OrchestratorEventType.TOOL_STARTED` and `RuntimeEventType.EVIDENCE_CREATED` are reliably emitted across phases and recorded.

## Next Steps (Sprint 1)
- Extend AI Agent orchestration capabilities into the runtime engine.
- Integrate active learning policies to shape the `HypothesisEngine`.
- Enable distributed asynchronous processing of the `ExecutionQueue` for multi-node deployments.
