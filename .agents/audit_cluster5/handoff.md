# Handoff Report — Cluster 5 Audit (Sections 49–57)

## Executive Summary

This audit evaluates Cluster 5 (Sections 49 through 57) of the Argus Feature Inventory Specification:
- **Section 49**: Planning → Investigation → Hypothesis → Evidence → Validation → Report Lifecycle
- **Section 50**: Investigation Philosophy
- **Section 51**: Reporting
- **Section 52**: Explainability
- **Section 53**: Learning
- **Section 54**: Benchmarking
- **Section 55**: Testing
- **Section 56**: Current External Tool Environment
- **Section 57**: Important Architectural Cleanup (Dual execution paths: older collectors vs Mission Runtime)

### Cluster Status Dashboard

| Section | Title | Status | Primary Source Paths | Primary Test Paths |
|---|---|:---:|---|---|
| **49** | Lifecycle Stages | ✅ Implemented | `argus/planning/`, `argus/investigation/`, `argus/hypothesis/`, `argus/evidence/`, `argus/reporting/` | `tests/hypothesis/`, `tests/investigation/`, `tests/planning/`, `tests/reporting/` |
| **50** | Investigation Philosophy | ✅ Implemented | `argus/investigation/models.py`, `argus/investigation/builder.py`, `argus/investigation/generator.py`, `argus/investigation/manual_validation.py` | `tests/investigation/test_manual_validation.py`, `tests/investigation/test_generator.py` |
| **51** | Reporting | ✅ Implemented | `argus/reporting/generator.py`, `argus/reporting/processor.py`, `argus/reporting/markdown.py`, `argus/reporting/json.py`, `argus/reporting/cvss.py` | `tests/reporting/test_generator.py`, `tests/reporting/test_processor.py`, `tests/reporting/test_renderers.py` |
| **52** | Explainability | ✅ Implemented | `argus/explain/engine.py`, `argus/explain/models.py`, `argus/explain/reasoning.py`, `argus/cli/explain_cli.py` | `tests/explain/test_explain.py` |
| **53** | Learning | ✅ Implemented | `argus/learning/engine.py`, `argus/learning/metrics.py`, `argus/learning/history.py`, `argus/learning/patterns.py`, `argus/learning/recommendations.py`, `argus/cli/learning_cli.py` | `tests/learning/` (97 tests) |
| **54** | Benchmarking | ✅ Implemented | `argus/benchmark/framework.py`, `argus/benchmark/datasets/`, `argus/benchmark/ground_truth/`, `argus/benchmark/leaderboard/`, `argus/benchmark/metrics/`, `argus/benchmark/reports/`, `argus/cli/benchmark_cli.py` | `tests/benchmark/` (42 tests) |
| **55** | Testing | ✅ Implemented | `tests/planning/`, `tests/runtime/`, `tests/tools/`, `tests/collectors/`, `tests/scanning/` | Full test suite (>2,260 tests across repo) |
| **56** | External Tool Environment | ✅ Implemented | `argus/utils/environment.py`, `argus/runtime/registry.py`, `argus/runtime/executor.py` | `tests/tools/test_environment_detector.py` (29 tests) |
| **57** | Architectural Cleanup | ⚠️ Partial | `argus/scanning/engine.py`, `argus/scanning/dag.py`, `argus/collectors/*.py` vs `argus/runtime/mission_runtime.py`, `argus/runtime/orchestrator.py`, `argus/runtime/dispatcher.py` | `tests/scanning/`, `tests/runtime/`, `tests/collectors/` |

**Cluster Metrics**: 8 Implemented (✅), 1 Partial (⚠️), 0 Missing (❌), 0 Broken (🔴). Total direct test suite passes: 390+ passed tests across cluster modules.

---

## 1. Observation

### Section 49: Planning → Investigation → Hypothesis → Evidence → Validation → Report Lifecycle

#### Specification Requirement
> Planning → Investigation → Hypothesis → Evidence → Validation → Report. These concepts remain deliberately separate stages.

#### Direct Code Observations
1. **Planning**: Defined in `argus/planning/research_planner.py` and `argus/planning/models.py`.
   - `ResearchPlanner` computes coverage via `CoverageTracker` (`argus/planning/coverage.py`), runs gap analysis via `GapAnalyzer` (`argus/planning/gap_analysis.py`), and generates `ResearchTask` objects via `TaskGenerator` (`argus/planning/task_generator.py`).
   - Line 9–12 of `argus/planning/research_planner.py`:
     ```python
     # The Research Planner NEVER executes tools or specialists.
     # It NEVER exploits systems.
     # It NEVER bypasses Mission Scope or Policy.
     # It only generates ResearchTask objects.
     ```
2. **Investigation**: Defined in `argus/investigation/generator.py` and `argus/investigation/models.py`.
   - `InvestigationGenerator.process_bundle()` turns raw `EvidenceBundle` objects into `Investigation` instances without asserting vulnerabilities.
   - `Investigation` dataclass in `argus/investigation/models.py` (lines 36–75) defines structured areas for human review, holding `observations`, `correlations`, `evidence_bundles`, `priority_score`, `confidence`, and `manual_validation`.
3. **Hypothesis**: Defined in `argus/hypothesis/engine.py` and `argus/hypothesis/models.py`.
   - `HypothesisEngine.process_investigation()` converts investigations into `Hypothesis` instances.
   - `HypothesisLifecycleManager` in `argus/hypothesis/lifecycle.py` manages transitions across states: `DRAFT`, `PROPOSED`, `UNDER_REVIEW`, `VALIDATED`, `REJECTED`, `ARCHIVED`, maintaining a full audit log in `HypothesisHistoryEntry`.
4. **Evidence**: Defined in `argus/evidence/model.py` and `argus/evidence/store.py`.
   - `Evidence` dataclass tracks `status` (`UNVERIFIED`, `USER_REVIEWED`, `CORROBORATED`, `CONFIRMED`, `REJECTED`, `SUPERSEDED`), `source_type`, `provenance` (`ProvenanceData`), and `relationships` (`EvidenceRelationship`).
5. **Validation**: Defined in `argus/investigation/manual_validation.py` (`ManualValidationGenerator`) and `argus/hypothesis/lifecycle.py` (`validate(hypothesis, reason)`).
   - Validation provides non-destructive, safe steps for human reviewers to confirm or reject hypotheses.
6. **Report**: Defined in `argus/reporting/generator.py` and `argus/reporting/processor.py`.
   - `ReportGenerator` orchestrates `EvidenceProcessor` to normalize confirmed evidence and findings, score via CVSS v3.1, deduplicate, and render to HackerOne-style Markdown and JSON reports upon mission completion (`argus/runtime/lifecycle.py`, line 40–58).

#### Test Observations
- `tests/hypothesis/test_integration.py` (55 lines) confirms the full evidence bundle → investigation → hypothesis pipeline.
- `tests/hypothesis/test_lifecycle.py` confirms state transitions and history logging.
- `tests/runtime/test_e2e_reporting.py` confirms mission lifecycle completion triggers automatic report generation.

---

### Section 50: Investigation Philosophy

#### Specification Requirement
> An investigation is NOT automatically a vulnerability. It should explain: what to inspect, why it matters, affected assets, supporting evidence, confidence, priority, validation approach, methodology, classification.

#### Direct Code Observations
1. **Model Non-Assertion Invariants**:
   - `argus/investigation/models.py` (lines 37–40):
     ```python
     class Investigation(BaseModel):
         """
         Represents an evidence-backed area for human review.
         Does NOT assert vulnerabilities or exploits.
         """
     ```
   - `argus/hypothesis/models.py` (lines 44–48):
     ```python
     class Hypothesis(BaseModel):
         """
         Represents an evidence-backed research question.
         A hypothesis is NOT a vulnerability.
         It proposes structured areas that should be investigated further based on evidence.
         """
     ```
2. **Required Attributes Verification**:
   - **What to inspect**: `title: str`, `summary: str`, `description: str`, `category: InvestigationCategory` (12 categories: `AUTHORIZATION`, `BUSINESS_LOGIC`, `AUTHENTICATION`, `SESSION_MANAGEMENT`, `API`, `GRAPHQL`, `WORKFLOW`, `FILE_HANDLING`, `CLIENT_SIDE`, `CONFIGURATION`, `INFRASTRUCTURE`, `TECHNOLOGY`).
   - **Why it matters**: `reasoning: str`, `priority_explanation: List[str]`.
   - **Affected assets**: `business_objects: List[str]`, `workflows: List[str]`, `related_endpoints: List[str]`, `related_graph_nodes: List[str]`, `related_graph_edges: List[str]`.
   - **Supporting evidence**: `observations: List[uuid.UUID]`, `correlations: List[uuid.UUID]`, `evidence_bundles: List[uuid.UUID]`, `supporting_evidence: List[Any]`.
   - **Confidence**: `confidence: float = Field(0.0, ge=0.0, le=1.0)` scored via `InvestigationConfidenceScorer` in `argus/investigation/confidence.py`.
   - **Priority**: `priority: InvestigationPriority` (`INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `priority_score: float = Field(0.0, ge=0.0, le=100.0)` evaluated via `PriorityEngine` in `argus/investigation/priority_engine.py`.
   - **Validation approach**: `manual_validation: str` populated by `ManualValidationGenerator.generate_guidance()` in `argus/investigation/manual_validation.py` with safe, non-destructive steps.
   - **Reasoning Provenance**: `ReasoningTreeBuilder` in `argus/investigation/explanation.py` builds trees mapping `Observation` → `Correlation` → `EvidenceBundle` → `Investigation`.

#### Test Observations
- `tests/investigation/test_manual_validation.py` tests non-destructive guidance generation across authorization, business logic, authentication, API, and technology categories.
- `tests/investigation/test_priority.py` verifies prioritization formulas and explanations.
- `tests/investigation/test_generator.py` verifies bundle filtering, category determination, and graph node deduplication.

---

### Section 51: Reporting

#### Specification Requirement
> Reporting converts validated research into evidence-backed, traceable, understandable, reproducible reports based on validated findings.

#### Direct Code Observations
1. **Core Pipeline**:
   - `argus/reporting/generator.py`: `ReportGenerator` accepts a `Mission` or collection of `Evidence`, processes them through `EvidenceProcessor`, renders them to Markdown and JSON, and saves them to disk (`.argus/reports/`).
   - `argus/reporting/processor.py`: `EvidenceProcessor` normalizes raw evidence into deduplicated `Finding` dataclasses using tuple key `(category, host, endpoint, parameter)`. It merges evidence IDs, computes CVSS v3.1 metrics, attaches reproduction steps, impact, remediation, and calculates `ReportSummary`.
   - `argus/reporting/cvss.py`: `CVSSCalculator` computes standard CVSS v3.1 scores and vectors.
   - `argus/reporting/markdown.py`: `HackerOneMarkdownRenderer` renders HackerOne bug-bounty ready markdown reports with executive summary, severity tables, findings grouped by category/host, proof of concept, impact, remediation, and evidence references.
   - `argus/reporting/json.py`: `JSONReportRenderer` renders machine-readable structured JSON.
   - `argus/reporting/vector_indexer.py`: `ScanEvidenceIndexer` and `FindingSemanticSearchEngine` index completed mission findings and evidence into the vector store for semantic recall.
2. **Traceability**:
   - Every `Finding` retains `evidence_ids: list[str]`, directly pointing to the specific `Evidence` objects in `EvidenceStore` with full provenance.
3. **Mission Lifecycle Integration**:
   - In `argus/runtime/lifecycle.py` lines 47–58, `MissionLifecycle.complete()` automatically instantiates `ReportGenerator` and writes reports to disk upon mission completion.

#### Test Observations
- `tests/reporting/test_generator.py`: Verifies report generation, file persistence, and formatting.
- `tests/reporting/test_processor.py`: Verifies evidence normalization, deduplication, grouping by host and category, and summary counts.
- `tests/reporting/test_renderers.py`: Verifies Markdown and JSON output formatting.
- `tests/reporting/test_cvss.py`: Verifies CVSS calculation logic.
- `tests/reporting/test_challenger_adversarial.py`: Adversarial edge case tests.

---

### Section 52: Explainability

#### Specification Requirement
> CLI: `argus explain`. Purpose: explain why an investigation was generated, show supporting evidence/correlations/methodology, explain confidence, show validation guidance.

#### Direct Code Observations
1. **Engine Architecture**:
   - `argus/explain/engine.py`: `ExplainabilityEngine` generates structured `Explanation` objects containing `ReasoningStep` chain, `TimelineEvent` chronology, `ExplanationGraph`, priority breakdown, confidence breakdown, and manual validation guidance.
   - `argus/explain/reasoning.py`: `ReasoningChainBuilder` traces backwards through Investigation → Evidence Bundle → Correlation → Observation.
   - `argus/explain/timeline.py`: `TimelineBuilder` constructs a chronological event log.
   - `argus/explain/graph.py`: `ExplanationGraphBuilder` constructs node/edge graph representations.
   - `argus/explain/export.py`: `ExplanationExporter` formats explanations into JSON, Markdown, HTML, or Graph JSON.
2. **CLI Registration and Commands**:
   - `argus/cli/explain_cli.py`: Typer app implementing:
     - `argus explain summary <inv_id> [--mission <id>]`: Shows title, reasoning chain, priority breakdown, confidence breakdown, manual validation.
     - `argus explain graph <inv_id> [--mission <id>]`: Displays nodes and edges with relationships.
     - `argus explain timeline <inv_id> [--mission <id>]`: Displays timestamped event timeline.
     - `argus explain export <inv_id> --format [json|markdown|html|graph]`: Exports explanation data.
   - Registered in `argus/cli/app.py` lines 67–68:
     ```python
     from argus.cli.explain_cli import app as explain_app
     app.add_typer(explain_app, name="explain")
     ```

#### Test Observations
- `tests/explain/test_explain.py` ran and passed all 5 test cases:
  - `test_explainability_engine_generate` PASSED
  - `test_explain_cli_summary` PASSED
  - `test_explain_cli_graph` PASSED
  - `test_explain_cli_timeline` PASSED
  - `test_explain_cli_export` PASSED

---

### Section 53: Learning

#### Specification Requirement
> Learning subsystem for future improvement of: prioritization, methodology, historical research outcomes. Must never silently change safety policy.

#### Direct Code Observations
1. **Code-Enforced Safety Constraints**:
   - `argus/learning/engine.py` docstring (lines 13–19) and implementation:
     ```python
     Constraints (enforced in code):
       - Does NOT train or fine-tune AI models.
       - Does NOT modify execution plans automatically.
       - Does NOT alter mission policy.
       - Every recommendation carries requires_planner_approval = True.
       - Recommendations without a rationale are rejected before storage.
     ```
   - In `argus/learning/models.py` (`Recommendation`), `requires_planner_approval: bool = True` is immutable and enforced.
2. **Subsystem Components**:
   - `MissionMetricsCalculator` (`argus/learning/metrics.py`): Computes coverage, execution time, investigation/hypothesis counts, evidence quality, task completion rates, and plugin usage effectiveness.
   - `MissionHistoryStore` (`argus/learning/history.py`): Records historical `LearningRecord` snapshots into `LearningRegistry`.
   - `FeedbackCollector` (`argus/learning/feedback.py`): Ingests researcher feedback on investigations/hypotheses (`useful`, `false_positive`, `interesting`, `duplicate`, `confirmed`, `rejected`).
   - `PatternDiscovery` (`argus/learning/patterns.py`): Discovers recurring patterns across missions (e.g. auth validation effectiveness, noisy heuristics, bottlenecked coverage areas).
   - `RecommendationEngine` (`argus/learning/recommendations.py`): Produces prioritized advisory recommendations for future planning.
3. **CLI Interface**:
   - `argus/cli/learning_cli.py`: Commands `metrics`, `history`, `recommendations`, `feedback`.
   - Registered in `argus/cli/app.py` line 77: `app.add_typer(learning_app, name="learning")`.

#### Test Observations
- `tests/learning/` suite ran and passed all 97 tests across 9 test modules in 1.09s.

---

### Section 54: Benchmarking

#### Specification Requirement
> Benchmark CLI for evaluating: task selection, tool resolution, execution latency, coverage, investigation quality, false positives, evidence quality.

#### Direct Code Observations
1. **Subsystem Architecture**:
   - `argus/benchmark/framework.py`: Central facade coordinating dataset management, evaluation running, metrics calculation, and reporting.
   - `argus/benchmark/datasets/`: Dataset models, JSON schema validation (`validator.py`), registry, and versioning.
   - `argus/benchmark/ground_truth/`: `GroundTruthEngine`, `GroundTruthMatcher` (exact vs partial match), `GroundTruthComparer` (unexpected false positives, missed false negatives).
   - `argus/benchmark/metrics/`:
     - `CoverageCalculator` (`coverage.py`): Measures API, parameter, and endpoint coverage.
     - `PerformanceCalculator` (`performance.py`): Evaluates execution latency and runtime overhead.
     - `QualityCalculator` (`quality.py`): Measures investigation quality, evidence quality, and false positive rates.
     - `ScoringEngine` (`scoring.py`): Computes composite benchmark score with penalties for noise.
   - `argus/benchmark/leaderboard/`: Tracks baselines, historical score trends, and provides `CIHandler` for automated regression detection.
   - `argus/benchmark/reports/`: Generators for Markdown, HTML, JSON, and PDF reports.
2. **CLI Commands**:
   - `argus/cli/benchmark_cli.py`: Commands `list`, `run`, `show`, `metrics`, `score`, `coverage`, `report`, `export`, `baseline`, `compare`, `ci`, `history`, `regression`.
   - Registered in `argus/cli/app.py` lines 86–88 (`benchmark`, `dataset`, `ground-truth`).

#### Test Observations
- `tests/benchmark/` suite ran and passed all 42 tests in 1.39s.

---

### Section 55: Testing

#### Specification Requirement
> Tests cover: planner, task categories, scheduler, dispatcher, runtime orchestrator, end-to-end missions, Nuclei, tool registration, compatibility resolution.

#### Direct Code Observations
1. **Coverage by Area**:
   - **Planner**: `tests/planning/test_research_planner.py`, `tests/planning/test_planning.py`, `tests/planning/test_task_generator.py`.
   - **Task Categories**: `tests/planning/test_recon_task_generation.py`, `tests/planning/test_info_disclosure_task_generation.py`.
   - **Scheduler**: `tests/runtime/test_scheduler.py`.
   - **Dispatcher**: `tests/planning/test_recon_task_generation.py` (explicit test classes `TestExplicitDispatcherRouting`, lines 16–405), `tests/runtime/test_runtime_orchestrator.py`.
   - **Runtime Orchestrator**: `tests/runtime/test_runtime_orchestrator.py`.
   - **End-to-End Missions**: `tests/runtime/test_e2e_mission.py`, `tests/runtime/test_e2e_reporting.py`, `tests/runtime/test_e2e_access_control.py`, `tests/runtime/test_e2e_sql_injection.py`, `tests/runtime/test_e2e_xss.py`, `tests/runtime/test_e2e_oauth.py`, `tests/runtime/test_e2e_path_traversal.py`.
   - **Nuclei**: `tests/runtime/test_adversarial_recon.py` (`TestAdversarialNuclei`), `tests/authorization/test_adversarial_scope_recon.py`.
   - **Tool Registration & Compatibility Resolution**: `tests/runtime/test_runtime_orchestrator.py` (lines 116–145: candidate compatibility, priority sorting, fallback resolution).

#### Test Observations
- The dedicated test modules for these components pass with 0 failures:
  - `tests/runtime/`: 17 test files, all passing.
  - `tests/planning/`: 6 test files, all passing.
  - `tests/tools/`: 1 test file (29 tests), all passing.
  - Total test suite execution: **2,356 passed**, 0 failed, 0 errors in 84.17s (`python -m pytest tests/ --ignore=tests/workspace -q`).

---

### Section 56: Current External Tool Environment

#### Specification Requirement
> Environment-specific tool paths (subfinder, httpx, katana, nuclei). Must be rechecked when needed.

#### Direct Code Observations
1. **Environment Detection Mechanism**:
   - `argus/utils/environment.py`: `EnvironmentDetector` class with `DEFAULT_EXTERNAL_TOOLS = ["subfinder", "httpx", "nuclei", "katana", "dnsx", "node", "npm"]`.
   - `check_tools()`: Validates tool existence using `shutil.which()`. Handles `httpx` aliasing by checking both `httpx` and `httpx-toolkit`.
   - `check_network()`: Safely parses target URLs, raw IPv4/IPv6, bracketed IPv6, resolves DNS via `socket.getaddrinfo`, and probes HTTP reachability via `httpx.Client(timeout=2.0, verify=False)`.
   - `check_cloud_metadata()`: Checks AWS, GCP, and Azure IMDS endpoints with 1.0s timeout and redirect prevention.
   - Lifecycle Integration: `AutonomousMissionRuntime.__init__` and `step()` automatically run `EnvironmentDetector().detect(mission.target)` if `mission.environment` is empty.
2. **Active Environment Tool Verification**:
   - Empirical verification via `which` command confirmed the presence of all required external binaries on the host system:
     - `subfinder` → `/home/varun/go/bin/subfinder`
     - `httpx` → `/usr/local/bin/httpx` (and `/usr/bin/httpx-toolkit`)
     - `katana` → `/home/varun/go/bin/katana`
     - `nuclei` → `/usr/bin/nuclei`
     - `dnsx` → `/home/varun/go/bin/dnsx`
3. **Tool Command Resolution in Runtime**:
   - In `argus/runtime/registry.py`: `_resolve_httpx_command()` probes `["httpx-toolkit", "httpx", "/usr/bin/httpx-toolkit", "/usr/bin/httpx"]`.
   - In `argus/collectors/subfinder.py` (lines 66–75): checks `shutil.which(cmd)` and falls back gracefully to Python-native target seeding if missing.
   - In `argus/runtime/executor.py` (`ExternalToolExecutor` lines 195–218): formats execution arguments for `subfinder` (`-d target -silent`), `httpx` (`-u target -json` or `-l <subs>`), `katana` (`-u target`), and `nuclei` (`-u target -json-export -`).

#### Test Observations
- `tests/tools/test_environment_detector.py` passed all 29 tests (default tools list, tool detection, httpx-toolkit fallback, network checks, bracketed IPv6, cloud metadata, mission integration).

---

### Section 57: Important Architectural Cleanup (Dual Execution Paths)

#### Specification Requirement
> Dual execution paths: older collector/agent-style AND newer Mission Runtime/Registry/Dispatcher/Orchestrator. Long-term goal: unify to single pipeline.

#### Direct Code Observations
1. **Identified Execution Paths**:
   - **Path A: Older / Intermediate Collector Scanning DAG**:
     - Files: `argus/scanning/engine.py` (`ScanEngine`), `argus/scanning/dag.py` (`ScanDAG`, `ScanTask`), `argus/collectors/*.py` (32 modules inheriting from `BaseCollector` in `argus/collectors/base.py`).
     - Invocation: `argus scan <target>` in `argus/cli/app.py` lines 198–203 executes `ScanEngine(dag=dag).run(mission)`.
     - Mechanism: Directly calls `collector.collect(mission)`. Collectors directly mutate mission attributes (`mission.findings`, `mission.vulnerabilities`, `mission.endpoints`).
   - **Path B: Newer Autonomous Mission Runtime**:
     - Files: `argus/runtime/mission_runtime.py` (`AutonomousMissionRuntime`), `argus/runtime/controller.py` (`MissionController`), `argus/runtime/orchestrator.py` (`ToolOrchestrator`), `argus/runtime/dispatcher.py` (`ToolDispatcher`), `argus/runtime/registry.py` (`ToolRegistry`), `argus/runtime/executor.py` (`TaskScheduler`, `ToolExecutor`).
     - Invocation: `argus mission run <target>` in `argus/cli/mission_cli.py` lines 26–42 calls `MissionController.start(mission)` which runs `AutonomousMissionRuntime` across formal state transitions (`PLANNING` → `RESEARCHING` → `COLLECTING_EVIDENCE` → `CORRELATING` → `INVESTIGATING` → `HYPOTHESIZING` → `REPORTING` → `COMPLETED`).
     - Mechanism: Emits lifecycle events via `EventBus`, tracks tasks in `PriorityTaskQueue`, resolves tools via `ToolDispatcher`, enforces safety via `SafetyValidator`, isolates execution in `Sandbox`.
   - **Path C: Legacy Agent Step Execution**:
     - Files: `argus/execution/engine.py` (`ExecutionEngine`), `argus/agents/base.py` (`BaseAgent`), `argus/agents/scheduler.py` (`AgentScheduler`), `argus/agents/registry.py` (`AgentRegistry`).
     - Invocation: `argus execute` in `argus/cli/execution_cli.py`.
     - Mechanism: Executes steps using `think()`, `execute()`, `evaluate()`.
2. **Duplicated Code & Structural Redundancy**:
   - **Duplicated Resolution Maps**:
     - `ScanEngine.resolve_collector` (`argus/scanning/engine.py` lines 76–140) maintains a 65-line `collector_class_map` mapping 30+ string tool IDs to `argus.collectors.*` classes.
     - `PluginExecutorAdapter._instantiate_specialist_fallback` (`argus/runtime/plugins.py` lines 65–270) maintains an almost identical 200-line `if/elif` chain mapping the exact same tool IDs and aliases to `argus.collectors.*`, `argus.plugins.*`, and `argus.agents.*`.
     - `ToolRegistry` (`argus/runtime/registry.py` lines 354–420) registers `Tool` entries with duplicate metadata.
   - **Duplicated DAG Schedulers**:
     - `ScanDAG` has its own topological sort, dependency checking, and profile filtering (`full`, `recon`, `vuln`, `quick`).
     - `TaskScheduler` (`argus/runtime/executor.py`) has its own dependency resolution, retry handling, and task state tracking.
   - **Duplicated Result Models**:
     - `ScanResult` / `CollectorResult` (`argus/scanning/models.py`).
     - `ToolExecutionResult` (`argus/runtime/models.py`).
     - `AgentResult` / `AgentMetric` (`argus/agents/results.py`).
3. **Migration Gaps**:
   - **CLI Disconnect**: The user-facing primary command `argus scan` uses Path A (`ScanEngine`), meaning users running standard scans do not benefit from the Mission Runtime's state machine, planning loop, or hypothesis engine.
   - **Ad-hoc Cross-Path Adapter**: Path B relies on `PluginExecutorAdapter._instantiate_specialist_fallback()` to dynamically load the 32 Path A collectors as plugins.
   - **Collector Mutation vs Return Value**: Path A collectors mutate `mission` directly rather than returning typed `ToolExecutionResult` or `Evidence` objects.

---

## 2. Logic Chain

1. **Premise (Section 49)**: The spec mandates that Planning, Investigation, Hypothesis, Evidence, Validation, and Reporting remain distinct, separate stages.
   - **Direct Observation**: Each of these 6 stages is housed in its own dedicated package (`argus.planning`, `argus.investigation`, `argus.hypothesis`, `argus.evidence`, `argus.reporting`), with dedicated data models and state transitions. Planning only generates tasks; investigation categorizes areas for human review; hypothesis proposes research questions with confidence and history; evidence stores immutable artifacts with provenance; validation specifies safe manual checks; reporting summarizes confirmed findings.
   - **Deduction**: Section 49 is **✅ Implemented**.

2. **Premise (Section 50)**: Investigations must NOT automatically declare vulnerabilities; they must explain inspection targets, significance, affected assets, supporting evidence, confidence, priority, validation approach, and classification.
   - **Direct Observation**: Both `Investigation` and `Hypothesis` models contain explicit docstring invariants forbidding vulnerability assertions. `Investigation` fields contain all 8 required elements, including `manual_validation` from `ManualValidationGenerator` providing safe, non-destructive verification steps.
   - **Deduction**: Section 50 is **✅ Implemented**.

3. **Premise (Section 51)**: Reporting must convert validated findings into evidence-backed, traceable, reproducible reports.
   - **Direct Observation**: `ReportGenerator`, `EvidenceProcessor`, and `CVSSCalculator` normalize findings, compute CVSS scores, deduplicate by `(category, host, endpoint, parameter)`, attach reproduction steps, and generate HackerOne Markdown and JSON reports. Provenance is preserved via `evidence_ids`. Reports are automatically generated upon mission completion.
   - **Deduction**: Section 51 is **✅ Implemented**.

4. **Premise (Section 52)**: CLI `argus explain` must explain why an investigation was generated, showing evidence, correlations, methodology, confidence, and validation guidance.
   - **Direct Observation**: `ExplainabilityEngine` and `argus/cli/explain_cli.py` implement `summary`, `graph`, `timeline`, and `export` subcommands. All 5 dedicated CLI tests pass.
   - **Deduction**: Section 52 is **✅ Implemented**.

5. **Premise (Section 53)**: Learning must improve future prioritization and research outcomes without silently changing safety policies.
   - **Direct Observation**: `LearningEngine` enforces `requires_planner_approval = True` on all recommendations. Metrics, history, and pattern discovery are fully implemented across 9 modules and verified by 97 passing tests.
   - **Deduction**: Section 53 is **✅ Implemented**.

6. **Premise (Section 54)**: Benchmarking CLI must evaluate task selection, tool resolution, latency, coverage, quality, false positives, and evidence quality.
   - **Direct Observation**: `argus/benchmark/` is an enterprise-grade framework with ground truth matching, scoring with noise penalties, regression detection, multi-format reports, and CLI `argus benchmark`. All 42 tests pass.
   - **Deduction**: Section 54 is **✅ Implemented**.

7. **Premise (Section 55)**: Testing must cover planner, task categories, scheduler, dispatcher, runtime orchestrator, e2e missions, Nuclei, tool registration, and compatibility resolution.
   - **Direct Observation**: Dedicated test suites exist and pass for all listed areas in `tests/planning/`, `tests/runtime/`, `tests/tools/`, and `tests/scanning/`.
   - **Deduction**: Section 55 is **✅ Implemented**.

8. **Premise (Section 56)**: External tool environment must handle tool paths, detection, and availability checks for subfinder, httpx, katana, nuclei.
   - **Direct Observation**: `EnvironmentDetector` discovers all 4 tools plus dnsx, node, npm, with `httpx-toolkit` fallback, network resolution, and cloud IMDS checks. All tools exist on the host PATH. 29 tests pass.
   - **Deduction**: Section 56 is **✅ Implemented**.

9. **Premise (Section 57)**: Dual execution paths (older collectors vs newer Mission Runtime) must be investigated, identifying duplication and migration gaps.
   - **Direct Observation**: There are three parallel execution paradigms (`ScanEngine` + 32 collectors, `AutonomousMissionRuntime` + `ToolOrchestrator`, and legacy `ExecutionEngine` + `AgentScheduler`). `ScanEngine` and `PluginExecutorAdapter` duplicate 200+ lines of fallback resolution code. `argus scan` uses the older path while `argus mission run` uses the newer path. Unification has not yet occurred.
   - **Deduction**: Section 57 is **⚠️ Partial** (significant architectural technical debt).

---

## 3. Caveats

1. **`tests/workspace` Test Suite**: `tests/workspace/` was excluded from the general test suite baseline in accordance with project test guidelines (`--ignore=tests/workspace`) due to legacy test fixtures. All other test directories relevant to Sections 49–57 (`tests/reporting`, `tests/investigation`, `tests/explain`, `tests/learning`, `tests/benchmark`, `tests/runtime`, `tests/tools`, `tests/scanning`) execute with zero errors and zero failures.
2. **PDF Report Renderer**: In Section 51, core vulnerability reporting generates Markdown and JSON. A PDF renderer exists in the benchmarking subsystem (`argus/benchmark/reports/pdf.py`), but has not been ported to `argus/reporting/`.
3. **External Tools Dependency**: While all external binaries (`subfinder`, `httpx`, `katana`, `nuclei`, `dnsx`) are verified present on the audit machine, tests use mocked subprocess calls and sandboxes to ensure deterministic execution in non-networked CI environments.

---

## 4. Conclusion

1. **Overall Assessment**: Cluster 5 represents one of the most mature and thoroughly tested segments of the Argus codebase.
   - Sections 49 through 56 are **✅ Implemented**, fully documented, and backed by comprehensive unit, adversarial, and integration test suites.
   - Section 57 is **⚠️ Partial**, as the codebase actively maintains dual execution paths (`ScanEngine` + `argus/collectors/` vs `AutonomousMissionRuntime` + `ToolOrchestrator` / `ToolDispatcher`).
2. **Key Recommendations for Section 57 Unification**:
   - **Phase 1: Wrap Collectors as Unified Plugins**: Refactor the 32 collectors in `argus/collectors/` into standard plugins registered in `ToolRegistry` with declared inputs, outputs, and capabilities.
   - **Phase 2: Route CLI `argus scan` Through Mission Runtime**: Update `argus/cli/app.py` so that `argus scan` delegates directly to `AutonomousMissionRuntime` (or `MissionController`), making `ScanEngine` a deprecated alias.
   - **Phase 3: Eliminate Redundant Fallback Tables**: Remove the duplicated 200-line fallback mapping in `PluginExecutorAdapter._instantiate_specialist_fallback` and the 65-line `collector_class_map` in `ScanEngine`.
   - **Phase 4: Deprecate `argus/execution/`**: Remove or integrate the unused `ExecutionEngine` in `argus/execution/engine.py` into the Mission Runtime.

---

## 5. Verification Method

To independently verify all findings in this audit report, execute the following commands from `/home/varun/argus`:

### 1. Test Suite Execution Across Cluster 5
```bash
# Verify Explainability (5 tests)
python -m pytest tests/explain/ -v

# Verify Learning (97 tests)
python -m pytest tests/learning/ -v

# Verify Benchmarking (42 tests)
python -m pytest tests/benchmark/ -v

# Verify External Tool Environment (29 tests)
python -m pytest tests/tools/test_environment_detector.py -v

# Verify Reporting & Investigation
python -m pytest tests/reporting/ tests/investigation/ tests/hypothesis/ -v

# Verify Scanning Engine & Runtime Orchestrator
python -m pytest tests/scanning/ tests/runtime/test_mission_runtime.py tests/runtime/test_runtime_orchestrator.py -v
```

### 2. External Tools Environment Verification
```bash
# Verify external tool presence on host
which subfinder httpx httpx-toolkit katana nuclei dnsx
```

### 3. Dual Execution Path Inspection (Section 57)
```bash
# Inspect CLI scan command using ScanEngine
grep -n -C 5 "ScanEngine" argus/cli/app.py

# Inspect CLI mission run command using MissionController / AutonomousMissionRuntime
grep -n -C 5 "controller.start" argus/cli/mission_cli.py

# Inspect duplicate fallback resolution logic
grep -n -C 10 "_instantiate_specialist_fallback" argus/runtime/plugins.py
grep -n -C 10 "collector_class_map" argus/scanning/engine.py
```

### Invalidation Conditions
- If `tests/explain/`, `tests/learning/`, `tests/benchmark/`, or `tests/tools/` fail, the corresponding Implemented status is invalidated.
- If `argus/collectors/` are removed and all CLI commands route exclusively through `AutonomousMissionRuntime`, Section 57 status shifts from ⚠️ Partial to ✅ Implemented.
