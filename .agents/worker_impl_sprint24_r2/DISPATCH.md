## 2026-09-01T15:24:23Z
You are the Implementation Lead Worker for Sprint 24: Scan Orchestration Engine in ARGUS.
Your working directory is `/home/varun/argus/.agents/worker_impl_sprint24_r2`.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Please read the following documents before starting:
- `/home/varun/argus/ORIGINAL_REQUEST.md`
- `/home/varun/argus/PROJECT.md`
- `/home/varun/argus/.agents/orchestrator/implementation_plan.md`
- `/home/varun/argus/.agents/explorer_survey_1/analysis.md`
- `/home/varun/argus/.agents/explorer_survey_2/analysis.md`
- `/home/varun/argus/.agents/spec_miner_survey/analysis.md`

Your Task:
Implement the complete, production-grade Scan Orchestration Engine across:
1. `argus/scanning/models.py`:
   - `CollectorStatus` enum (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `SKIPPED`).
   - `CollectorResult` dataclass: `tool_id: str`, `task_title: str`, `status: CollectorStatus`, `evidence_count: int = 0`, `duration_ms: float = 0.0`, `error: Optional[str] = None`, `start_time: Optional[str] = None`, `end_time: Optional[str] = None`.
   - `ScanResult` dataclass: `scan_id: str`, `target: str`, `status: str`, `start_time: str`, `end_time: str`, `duration_seconds: float`, `collectors_total: int`, `collectors_run: int`, `collectors_skipped: int`, `collectors_failed: int`, `total_evidence: int`, `vulnerabilities_by_severity: Dict[str, int]`, `collector_results: List[CollectorResult]`, `state_transitions: List[Dict[str, Any]]`, `report_paths: List[str] = field(default_factory=list)`, `graph_summary: Dict[str, Any] = field(default_factory=dict)`.
2. `argus/scanning/dag.py`:
   - `ScanTask` dataclass: `key: str`, `title: str`, `tool_id: str`, `dependencies: List[str]`, `category: str`, `phase: str`.
   - `ScanDAG` class: Resolves the 21 task templates from `_RECON_TEMPLATES` in `argus/planning/task_generator.py`. Provides `get_execution_order() -> List[ScanTask]` using Kahn's algorithm or DFS topological sort, mapping task titles to keys/tool_ids and ordering dependencies strictly (recon tasks first, then vulnerability modules). Also support `get_task(key)` and custom task injection for testing.
3. `argus/runtime/state_machine.py`:
   - Ensure `MissionStateMachine.valid_transitions` includes the scanner transition pathways (`CREATED -> READY`, `READY -> RUNNING`, `CORRELATING -> COMPLETED`).
4. `argus/scanning/engine.py`:
   - `ScanEngine` class with `run(mission: Mission) -> ScanResult`:
     - Drives `mission.status` across `CREATED` -> `READY` -> `RUNNING` -> `COLLECTING_EVIDENCE` -> `CORRELATING` -> `COMPLETED` (or `FAILED`).
     - Appends every transition to `mission.state_transitions` with ISO8601 UTC timestamp and reason.
     - Topologically resolves tasks from `ScanDAG`.
     - Dynamically resolves each collector via `ToolRegistry.get(tool_id)` or `PluginExecutorAdapter` fallback / dynamic import from `argus.collectors`.
     - Executes each collector (`collector.collect(mission)` or `collector.execute(mission)`).
     - Aggregates returned `Evidence` objects into `mission.evidence` (`EvidenceStore`).
     - Isolates exceptions per collector: if a collector fails, mark its `CollectorResult` as `FAILED`, record the error, and mark any downstream tasks that depend on it as `SKIPPED`, while continuing execution of independent tasks.
     - In the `CORRELATING` phase, updates the attack surface graph using `AttackSurfaceGraphBuilder(mission.attack_surface_graph).build(mission)` or building nodes/edges (`HAS_VULNERABILITY`, `HAS_ENDPOINT`).
     - Generates Markdown and JSON reports using `ReportGenerator(output_dir=...).generate_and_save(mission)` and attaches report paths to `ScanResult.report_paths` and `mission.reports`.
     - Computes vulnerability counts by severity from `mission.evidence` and returns the final `ScanResult`.
5. `argus/scanning/__init__.py`:
   - Re-exports `ScanEngine`, `ScanResult`, `CollectorResult`, `CollectorStatus`, `ScanDAG`, `ScanTask`.
6. `argus/models/__init__.py`:
   - Re-exports `ScanResult`, `CollectorResult`, `CollectorStatus`, and `MissionStatus = MissionState`.

Verification & Zero Regression:
- Run verification tests to ensure all imports work and existing tests continue to pass (`python -m pytest tests/ --ignore=tests/workspace -q`).
- Write detailed progress and handoff report to `/home/varun/argus/.agents/worker_impl_sprint24_r2/handoff.md`.
- Maintain `/home/varun/argus/.agents/worker_impl_sprint24_r2/progress.md`.
- When done, send a completion message with the path to your handoff.
