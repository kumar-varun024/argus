# Handoff Report — Explorer 2: Sprint 24 Architectural Survey (Models, State Transitions, & Reporting)

**Agent**: Explorer 2  
**Working Directory**: `/home/varun/argus/.agents/explorer_survey_2`  
**Milestone**: Sprint 24 Survey (Scan Orchestration Engine)  
**Status**: Complete  

---

## 1. Observation

### 1.1 Data Models & Graph
- **`Mission`** is defined in `argus/runtime/mission.py:76` as a dataclass with fields `target`, `id`, `name`, `status` (`MissionState`), `phase`, `scope`, `policy`, `test_identities`, `active_identity_id`, `subdomains`, `live_hosts`, `endpoints`, `vulnerabilities`, `evidence` (`EvidenceStore`), `attack_surface_graph` (`KnowledgeGraph`), `reports`, and `state_transitions`.
- **`MissionState`** is defined in `argus/runtime/mission.py:24` as a string Enum: `CREATED`, `READY`, `RUNNING`, `PLANNING`, `RESEARCHING`, `COLLECTING_EVIDENCE`, `CORRELATING`, `BUILDING_INVESTIGATIONS`, `GENERATING_HYPOTHESES`, `WAITING_FOR_APPROVAL`, `COMPLETED`, `PAUSED`, `CANCELLED`, `FAILED`, `RECOVERING`.
- **`Evidence`** is defined in `argus/evidence/model.py:26` with `evidence_id`, `category`, `value`, `source`, `status`, `confidence`, `severity`, `provenance`, `relationships`, `tags`, and `metadata`.
- **`EvidenceStore`** is defined in `argus/evidence/store.py:4` with `add(evidence)`, `all()`, `filter(category)`, `count()`, `clear()`, `__iter__`, and `__len__`.
- **`KnowledgeGraph`** is defined in `argus/graph/graph.py:6` and populated with typed `Node` (`id`, `type`, `value`, `metadata`) and `Edge` (`source`, `target`, `type`, `metadata`).
- **`AttackSurfaceGraphBuilder`** in `argus/graph/attack_surface.py:11` populates `KnowledgeGraph` from `EvidenceStore` or `Mission`, creating nodes (`target`, `subdomain`, `live_host`, `technology`, `endpoint`, `vulnerability`, `secret`, `cname`) and edges (`RESOLVES_TO`, `HOSTS`, `RUNS_TECHNOLOGY`, `HAS_ENDPOINT`, `HAS_VULNERABILITY`, `POINTS_TO_CNAME`, `EXPOSES_SECRET`, `DISCLOSED_SUBDOMAIN`).
- **`ScanResult`** does not currently exist in the codebase.

### 1.2 State Transitions & Duration Tracking
- `MissionStateMachine` in `argus/runtime/state_machine.py:11` governs state transitions and validates against `self.valid_transitions`.
- `MissionLifecycle` in `argus/runtime/lifecycle.py:4` implements lifecycle helpers (`create`, `start`, `pause`, `resume`, `cancel`, `complete`).
- `mission.state_transitions` holds transition history entries `{"from": ..., "to": ..., "reason": ..., "timestamp": ...}`.

### 1.3 Reporting Pipeline
- **`ReportGenerator`** in `argus/reporting/generator.py:16` implements `generate(mission)`, `render_markdown(report)`, `render_json(report)`, `save_report(report, output_dir)`, and `generate_and_save(mission, output_dir)`.
- `EvidenceProcessor` in `argus/reporting/processor.py:20` normalizes evidence, computes CVSS v3.1 scores, and deduplicates findings on `(category, host, endpoint, parameter)`.
- `HackerOneMarkdownRenderer` in `argus/reporting/markdown.py:7` renders HackerOne Markdown reports with executive summaries, scorecard tables, and reproduction steps.
- `JSONReportRenderer` in `argus/reporting/json.py:16` renders and parses lossless JSON reports.
- `generate_and_save` generates both `.md` and `.json` files in `.argus/reports/` and appends their paths to `mission.reports`.

### 1.4 Baseline Test Execution
- Executed `python -m pytest tests/ --ignore=tests/workspace -q`.
- Verbatim result: `1678 passed, 29080 warnings in 68.72s (0:01:08)`.

---

## 2. Logic Chain

1. **Model Unification**:
   - `Mission` already contains `evidence: EvidenceStore` and `attack_surface_graph: KnowledgeGraph`.
   - The enum is `MissionState`, and `mission.status` holds this enum value. Aliasing `MissionStatus = MissionState` and re-exporting in `argus/models/__init__.py` prevents naming collisions.
   - Creating `ScanResult` in `argus/scanning/models.py` allows `ScanEngine` to return a strongly typed summary of collector statuses, execution durations, errors, aggregate metrics, and report paths.

2. **State Transition Cohesion**:
   - `ScanEngine` must progress `Mission` across `CREATED` $\rightarrow$ `READY` $\rightarrow$ `RUNNING` $\rightarrow$ `COLLECTING_EVIDENCE` $\rightarrow$ `CORRELATING` $\rightarrow$ `COMPLETED` (or `FAILED` on unrecoverable errors).
   - Adding missing transitions (`CREATED -> READY`, `READY -> RUNNING`, `CORRELATING -> COMPLETED`) to `MissionStateMachine.valid_transitions` ensures full compatibility without breaking any existing runtime tests.

3. **Report Consolidation & Graph Integration**:
   - As collectors complete, `Evidence` objects are added to `mission.evidence`.
   - Running `AttackSurfaceGraphBuilder().build(mission)` ensures the `KnowledgeGraph` snapshot is updated with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges before reporting.
   - Calling `ReportGenerator().generate_and_save(mission)` creates both `.md` and `.json` report files, attaches their paths to `ScanResult.report_paths` and `mission.reports`, and embeds graph summary metrics into `ScanResult.graph_summary`.

---

## 3. Caveats

- `Mission.created_at` and `updated_at` currently use `datetime.utcnow().isoformat()` in several legacy modules, producing deprecation warnings in Python 3.13. New scanning modules should use `datetime.now(timezone.utc).isoformat()`.
- Some collectors update `mission.vulnerabilities` directly, while others only return `List[Evidence]`. `ScanEngine` must handle both patterns by taking returned evidence and ensuring it is added to `mission.evidence`.
- No source code modifications were performed during this survey (read-only investigation).

---

## 4. Conclusion

The ARGUS models and reporting infrastructure are robust, fully modular, and ready for `ScanEngine` integration in Sprint 24.
The proposed layout:
- `argus/scanning/models.py`: `ScanResult`, `CollectorExecutionResult`
- `argus/scanning/dag.py`: DAG resolution from `_RECON_TEMPLATES` & topological sorting
- `argus/scanning/engine.py`: `ScanEngine` orchestrating state transitions, collector dispatch, error handling, graph snapshots, and report generation.
- Re-exports in `argus/models/__init__.py` and `argus/scanning/__init__.py`.

---

## 5. Verification Method

1. **Review Survey Artifacts**:
   - Detailed survey: `/home/varun/argus/.agents/explorer_survey_2/survey_report.md`
   - Handoff report: `/home/varun/argus/.agents/explorer_survey_2/handoff.md`

2. **Verify Baseline Test Suite**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -q
   ```
   Must yield 1,678 passed tests with zero failures.
