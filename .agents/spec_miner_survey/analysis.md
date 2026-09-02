# Sprint 24: Scan Orchestration Engine Specification Mining & Test Architecture Analysis

## 1. Executive Summary & Sprint Mission
Sprint 24 delivers the **Scan Orchestration Engine** (`ScanEngine` located in `argus/scanning/engine.py` and `argus/scanning/models.py`) for the ARGUS defensive security assessment platform. The Scan Orchestration Engine replaces previous simulated workflows with a real, deterministic, end-to-end scan runner.

Given a target domain, `ScanEngine` executes the complete reconnaissance-to-vulnerability detection directed acyclic graph (DAG) across **21 task templates** (3 reconnaissance discovery modules + 18 vulnerability detection modules), aggregates returned `Evidence` into `EvidenceStore`, maintains attack surface graph topology (`HAS_ENDPOINT`, `HAS_VULNERABILITY`), tracks lifecycle state transitions, handles collector failures gracefully without scan abortion, and invokes `ReportGenerator` to produce consolidated Markdown and JSON assessment reports.

---

## 2. Requirement Mining (R1–R5 & Acceptance Criteria)

### Explicit Requirements
- **R1. ScanEngine Core (`argus/scanning/engine.py`)**:
  - Accepts a `Mission` instance (or target domain string wrapped into `Mission`).
  - Resolves DAG tasks from `_RECON_TEMPLATES` in `argus/planning/task_generator.py`.
  - Performs topological sort respecting task prerequisites (`Discover Subdomains` $\rightarrow$ `Fingerprint Live Hosts` $\rightarrow$ `Discover API Endpoints` $\rightarrow$ vulnerability collectors; and `Fingerprint Live Hosts` $\rightarrow$ `nuclei` / `info_disclosure`).
  - Resolves and instantiates each collector via `ToolRegistry.get()` and `PluginExecutorAdapter` fallback (`argus/runtime/plugins.py`).
  - Calls `collector.collect(mission)` (or `collector.execute(mission)`), passing accumulated mission state.
  - Aggregates all returned `Evidence` objects into `mission.evidence` (`EvidenceStore`) and `mission.attack_surface_graph` (`KnowledgeGraph`).

- **R2. DAG-Driven Collector Dispatch**:
  - `_RECON_TEMPLATES` is the single source of truth for task templates, ordering, and dependencies.
  - Template `metadata.tool_id` drives collector resolution without hardcoded imports.
  - Resilient dispatch: If a collector fails or raises an unhandled exception, the engine logs the error, marks the collector as `FAILED`, and continues executing independent tasks.
  - Dependency enforcement: A collector executes only after all prerequisite tasks have completed successfully (`COMPLETED`). If any dependency failed or was skipped, downstream dependent tasks are marked `SKIPPED`.

- **R3. Scan Lifecycle & Progress Tracking**:
  - Drives `Mission.status` through strict lifecycle states:
    `CREATED` $\rightarrow$ `READY` $\rightarrow$ `RUNNING` $\rightarrow$ `COLLECTING_EVIDENCE` $\rightarrow$ `CORRELATING` $\rightarrow$ `COMPLETED` (or `FAILED` if unrecoverable initialization error occurs).
  - Records timestamps for every state transition in `mission.state_transitions` and `ScanResult.state_transitions`.
  - Produces a `ScanResult` dataclass capturing:
    - `scan_id`: Unique UUID/ID string.
    - `target`: Target domain/host.
    - `started_at` & `completed_at`: ISO-8601 UTC timestamps.
    - `status`: Final mission status (`COMPLETED` / `FAILED`).
    - `state_transitions`: List of transition dictionaries `[{"from": ..., "to": ..., "timestamp": ..., "reason": ...}]`.
    - `collector_results`: Per-collector execution breakdown (`name`, `status` [completed/failed/skipped], `evidence_count`, `duration_seconds`, `error`).
    - `stats`: Aggregate metrics (`total_evidence`, `vulnerabilities_by_severity` [critical, high, medium, low, info], `collectors_run`, `collectors_skipped`, `collectors_failed`).
    - `report_paths`: List of paths to generated report files (`.md` and `.json`).
    - `attack_surface_graph_snapshot`: Node and edge count metrics (`node_count`, `edge_count`, `has_vulnerability_edges`, `has_endpoint_edges`).

- **R4. Report Consolidation**:
  - Invokes `ReportGenerator.generate_and_save(mission, output_dir=...)` post-scan.
  - Saves both Markdown (`.md`) and JSON (`.json`) report artifacts to disk.
  - Adds file paths to `mission.reports` and `ScanResult.report_paths`.
  - Reconciles `AttackSurfaceGraph` ensuring all `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges are linked properly.

- **R5. Zero Regression & Test Validation**:
  - 100% pass on existing test suite: baseline `1678 passed`.
  - Add at least 25 new tests in `tests/scanning/test_scan_engine.py` and `tests/scanning/test_scan_engine_adversarial.py`.

### Implicit & Architectural Requirements
- **No Hardcoded Collector Imports in ScanEngine**: Resolution must go through `ToolRegistry.get()` and `PluginExecutorAdapter._instantiate_specialist_fallback()` or dynamic lookup in `argus.collectors`.
- **Collector Return Type Normalization**: Some collectors return `List[Evidence]`, some return a single `Evidence`, and some return `None` (mutating `mission.evidence` and `mission.attack_surface_graph` in-place). `ScanEngine` must handle all return styles seamlessly.
- **Evidence De-duplication**: When aggregating returned `Evidence`, prevent duplicate ID insertions into `EvidenceStore`.
- **Custom Output Directory Support**: `ScanEngine(output_dir=...)` or `ScanEngine.run(mission, output_dir=...)` must respect user-specified directories for reports.
- **Clean Graph Initialization**: If `mission.attack_surface_graph` is uninitialized, `ScanEngine` must ensure an instance of `KnowledgeGraph` is present.

---

## 3. Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | DAG Parsing | `_RECON_TEMPLATES` Extraction | Extracts all 21 recon and vulnerability templates from `argus.planning.task_generator`. | `_RECON_TEMPLATES` dict | Dict/List of template objects with `title`, `dependencies`, `metadata.tool_id` | Raises `KeyError` if required fields missing | `argus/planning/task_generator.py:13` |
| 2 | DAG Ordering | Topological Sorter (Kahn's / DFS) | Computes linear execution order respecting dependencies (`subfinder` $\rightarrow$ `httpx` $\rightarrow$ `katana` $\rightarrow$ vuln collectors). | Graph of task dependencies | List of task IDs / titles in topological order | Detects cycles and raises `ValueError` / `CyclicDependencyError` | `argus/planning/task_generator.py` & R1 |
| 3 | Tool Resolution | `ToolRegistry` Integration | Maps template `metadata.tool_id` to registered tool definition. | `tool_id: str` | `Tool` instance or `None` | Returns `None` if tool not registered | `argus/runtime/registry.py:15` |
| 4 | Specialist Resolution | `PluginExecutorAdapter` Fallback | Instantiates internal collector/specialist class when tool is not a CLI binary. | `tool_id: str` | Collector instance conforming to `BaseCollector` / `execute` hook | Returns `None` and logs error if unresolvable | `argus/runtime/plugins.py:65` |
| 5 | Collector Dispatch | `BaseCollector.collect()` Invocation | Invokes `collector.collect(mission)` or `collector.execute(mission)` with current mission state. | `collector_instance, mission` | `List[Evidence]`, `Evidence`, or `None` | Catches exceptions, logs, marks collector `failed` in `ScanResult` | `argus/collectors/base.py:7` |
| 6 | Evidence Ingestion | `EvidenceStore` Aggregation | Stores all returned `Evidence` items in `mission.evidence` and deduplicates by ID. | `List[Evidence]` | Updated `mission.evidence` (`EvidenceStore`) | Validates Evidence object schema | `argus/evidence/store.py` & R1 |
| 7 | Graph Linking | `AttackSurfaceGraph` Correlation | Reconciles `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges across discovered hosts, endpoints, and vulns. | `mission.evidence`, `mission.live_hosts`, `mission.endpoints` | Updated `KnowledgeGraph` with nodes and directed edges | Gracefully handles missing node references | `argus/graph/graph.py` & R4 |
| 8 | State Machine | `MissionLifecycle` Transitions | Drives mission status `CREATED` $\rightarrow$ `READY` $\rightarrow$ `RUNNING` $\rightarrow$ `COLLECTING_EVIDENCE` $\rightarrow$ `CORRELATING` $\rightarrow$ `COMPLETED`. | `Mission`, `target_state: MissionState` | State updated, timestamped transition appended | Raises `ValueError` on illegal transition | `argus/runtime/lifecycle.py:4` & `argus/runtime/state_machine.py:67` |
| 9 | Reporting | `ReportGenerator.generate_and_save()` | Generates HackerOne-style Markdown and machine-readable JSON vulnerability assessment reports. | `mission, output_dir: Optional[str]` | `[md_path, json_path]` (List[str]) | Traps file write errors, logs warning, returns partial paths | `argus/reporting/generator.py:95` |
| 10 | Result Packaging | `ScanResult` Compilation | Compiles per-collector execution metrics, overall stats, report paths, and graph summary into dataclass. | Accumulated run data, `mission` | `ScanResult` dataclass instance | Safe default values for missing data | R3 & R4 |
| 11 | Severity Breakdown | Vulnerability Categorization | Groups discovered vulnerabilities by severity (`critical`, `high`, `medium`, `low`, `info`). | `mission.evidence` / `mission.vulnerabilities` | `Dict[str, int]` | Normalizes case-insensitive severity strings | `argus/reporting/processor.py` |
| 12 | Subdomain Enumeration | `subfinder` Task Execution | Discovers target subdomains, populating `mission.subdomains`. | `mission.target` | `mission.subdomains: List[str]` | Empty list if no subdomains found | `argus/collectors/subfinder.py:12` |
| 13 | Host Probing | `httpx` Task Execution | Probes subdomains for live HTTP/HTTPS hosts and technology stack. | `mission.subdomains` | `mission.live_hosts: List[dict]`, `technologies` | Skips probing if subdomains empty | `argus/collectors/httpx.py:12` |
| 14 | API Crawling | `katana_crawler` Task Execution | Crawls live hosts to discover API endpoints and parameters. | `mission.live_hosts` | `mission.endpoints: List[dict]` | Skips crawling if live hosts empty | `argus/collectors/katana.py:12` |
| 15 | Vulnerability Scanning | Automated Nuclei Probing | Scans live hosts using automated vulnerability templates. | `mission.live_hosts` | `mission.vulnerabilities`, `mission.notes` | Skips if live hosts empty | `argus/collectors/nuclei.py:10` |
| 16 | Info Disclosure | Info Disclosure Collector | Probes exposed `.env`, `.git`, actuators, and leaked credentials. | `mission.live_hosts` | `Evidence(category="information_disclosure")` | Handles HTTP timeouts gracefully | `argus/collectors/information_disclosure.py` |
| 17 | Access Control & IDOR | Access Control Collector | Tests authorization boundaries and privilege escalation. | `mission.endpoints` | `Evidence(category="access_control")` | Logs HTTP connection failures | `argus/collectors/access_control.py` |
| 18 | Injection Detection | SQL Injection Collector | Injects multi-DBMS error/blind payloads into endpoint parameters. | `mission.endpoints` | `Evidence(category="sql_injection")` | Catches prober errors | `argus/collectors/sql_injection.py` |
| 19 | XSS Detection | XSS Collector | Injects context-aware payloads into forms and query parameters. | `mission.endpoints` | `Evidence(category="xss")` | Ignores malformed HTML responses | `argus/collectors/xss.py` |
| 20 | Command Injection | OS Command Injection Collector | Fuzzes parameters for blind and error-based command injection. | `mission.endpoints` | `Evidence(category="command_injection")` | Traps prober exceptions | `argus/collectors/command_injection.py` |
| 21 | SSRF Validation | SSRF Collector | Probes cloud metadata endpoints and internal network ports. | `mission.endpoints` | `Evidence(category="ssrf")` | Traps network unreachable errors | `argus/collectors/ssrf.py` |
| 22 | OAuth/OIDC Security | OAuth Collector | Validates JWT signatures, tokens, and OAuth flow misconfigurations. | `mission.endpoints` | `Evidence(category="oauth")` | Handles non-OAuth endpoints | `argus/collectors/oauth.py` |
| 23 | XML Parser Security | XXE / XML Parser Collector | Validates external entity resolution and entity expansion. | `mission.endpoints` | `Evidence(category="xml_parser")` | Ignores non-XML endpoints | `argus/collectors/xml_parser.py` |
| 24 | Deserialization Check | Insecure Deserialization Collector | Fuzzes parameters with Java, Python pickle, PHP, Ruby payloads. | `mission.endpoints` | `Evidence(category="deserialization")` | Traps serialization errors | `argus/collectors/deserialization.py` |
| 25 | GraphQL Security | GraphQL Security Collector | Tests introspection leakage, depth DoS, and batching abuse. | `mission.endpoints` | `Evidence(category="graphql")` | Handles non-GraphQL endpoints | `argus/collectors/graphql.py` |
| 26 | WebSocket Security | WebSocket Security Collector | Tests CSWSH and unauthenticated handshakes. | `mission.endpoints` | `Evidence(category="websocket")` | Traps WebSocket handshake failures | `argus/collectors/websocket.py` |
| 27 | Smuggling Detection | Request Smuggling Collector | Probes CL.TE, TE.CL, and HTTP/2 desync flaws. | `mission.endpoints` | `Evidence(category="request_smuggling")` | Handles socket reset errors | `argus/collectors/request_smuggling.py` |
| 28 | Race Conditions | Race Conditions Collector | Executes concurrent synchronized burst requests for TOCTOU. | `mission.endpoints` | `Evidence(category="race_conditions")` | Traps thread synchronization errors | `argus/collectors/race_conditions.py` |
| 29 | Business Logic | Business Logic Collector | Validates multi-step workflow bypasses and parameter tampering. | `mission.endpoints` | `Evidence(category="business_logic")` | Ignores invalid workflow steps | `argus/collectors/business_logic.py` |
| 30 | SSTI Validation | SSTI Collector | Probes template injection across Jinja, Mako, Twig, Freemarker. | `mission.endpoints` | `Evidence(category="ssti")` | Handles non-template responses | `argus/collectors/ssti.py` |
| 31 | Cache Security | Cache Security Collector | Probes web cache poisoning and cache deception vulnerabilities. | `mission.endpoints` | `Evidence(category="cache_security")` | Traps cache probe mismatches | `argus/collectors/cache_security.py` |

---

## 4. Edge Cases & Adversarial Scenarios

| # | Feature | Input / Condition | Observed / Required Behavior |
|---|---------|-------------------|-----------------------------|
| 1 | DAG Sorter | Circular dependency injected (A $\rightarrow$ B $\rightarrow$ A) | Sorter detects cycle, raises `ValueError("Cycle detected in DAG")`, prevents infinite loop. |
| 2 | DAG Sorter | Disjoint DAG components (two independent recon roots) | Sorter topologically orders all nodes correctly; independent roots run without blocking. |
| 3 | DAG Sorter | Empty template registry | Sorter returns empty execution list without error; scan transitions gracefully to `COMPLETED`. |
| 4 | Collector Dispatch | Collector raises unhandled `RuntimeError` during `collect()` | Engine catches exception, records `status="failed"`, logs error trace, continues independent tasks. |
| 5 | Collector Dispatch | Root dependency (`subfinder`) fails | Downstream dependent collectors (`httpx`, `katana`, `sql_injection`, etc.) marked `status="skipped"`. |
| 6 | Collector Dispatch | Intermediate dependency (`katana_crawler`) fails | Collectors depending on `katana_crawler` skipped; collectors depending only on `httpx` (`nuclei`, `info_disclosure`) still execute. |
| 7 | Collector Dispatch | Collector raises `TimeoutError` or exceeds duration limit | Engine traps timeout, marks collector `failed` with error message, captures elapsed duration. |
| 8 | Collector Dispatch | Tool ID unknown / missing from registry | Engine logs warning, marks collector `failed` with reason `UnresolvableTool`, continues scan. |
| 9 | Evidence Aggregation | Collector returns `None` (mutates mission in-place) | Engine checks `mission.evidence` and counts newly added items without `TypeError`. |
| 10 | Evidence Aggregation | Collector returns single `Evidence` instead of `List[Evidence]` | Engine normalizes single item to list and appends to `mission.evidence`. |
| 11 | Evidence Aggregation | Collector returns malformed object (dict or string instead of `Evidence`) | Engine wraps dict into `Evidence` or ignores malformed non-Evidence, preserving store integrity. |
| 12 | Evidence Aggregation | 10,000+ evidence items emitted in single scan | Engine handles high volume efficiently without memory exhaustion or duplicate IDs. |
| 13 | Graph Construction | Collector adds evidence for host/endpoint not yet in graph | Engine auto-creates missing `live_host` and `endpoint` nodes, connecting `HAS_VULNERABILITY` edges. |
| 14 | Graph Construction | Graph contains isolated nodes with zero edges | Snapshot records node count and zero edge count accurately without crashing. |
| 15 | Lifecycle State | Target domain string passed instead of `Mission` object | Engine auto-instantiates `Mission(target=...)` and initializes all datastores. |
| 16 | Lifecycle State | Mission passed with invalid initial state (`COMPLETED` or `CANCELLED`) | Engine raises `ValueError` or resets mission state to `CREATED` with explicit transition reason. |
| 17 | Reporting | Output directory does not exist (`/tmp/custom_scan_reports_xyz`) | `ReportGenerator` creates parent directories recursively and writes report files. |
| 18 | Reporting | Read-only filesystem / disk write failure during report save | Engine catches `OSError`/`IOError`, logs warning, completes scan with `report_paths=[]`. |
| 19 | Reporting | Scan finds 0 vulnerabilities / 0 evidence items | Generates valid, clean report files documenting zero findings without formatting crashes. |
| 20 | ScanResult Integrity | Scan completes with mix of completed, failed, and skipped collectors | `ScanResult.stats` accurately tallies `collectors_run`, `collectors_failed`, `collectors_skipped`, matching sum of individual statuses. |
| 21 | ScanResult Integrity | Vulnerability severity casing varies (`"HIGH"`, `"High"`, `"high"`) | Engine normalizes severity keys in `vulnerabilities_by_severity` dict (`critical`, `high`, `medium`, `low`, `info`). |
| 22 | Concurrency Isolation | Two `ScanEngine` instances execute concurrently on different missions | Mission states, evidence stores, and reports remain strictly isolated without shared state corruption. |

---

## 5. Existing Test Architecture & Baseline Analysis

### Pytest Configuration & Execution Command
- **Command**: `python -m pytest tests/ --ignore=tests/workspace -x -q`
- **Baseline Result**: **`1678 passed, 29079 warnings in 67.95s (0:01:07)`**
- **Exit Code**: `0`

### Test Suite Structure
- `tests/orchestration/test_orchestrator.py`: Tests workflow step planning, tool execution blocking by policy, and event logging.
- `tests/runtime/test_e2e_mission.py`: Tests E2E mission lifecycle, mocking external commands (`subfinder`, `httpx`, `katana`, `nuclei`) via `mock_execute_command` and verifying `EvidenceStore` categories.
- `tests/runtime/test_e2e_reporting.py`: Tests `ReportGenerator` triggered upon mission completion.
- `tests/collectors/`: Tests individual vulnerability collectors with mock HTTP responses (`AuthenticatedHttpClient` mocking).
- `tests/reporting/`: Tests Markdown renderer (`HackerOneMarkdownRenderer`) and JSON renderer (`JSONReportRenderer`).

### Testing Conventions & Best Practices Observed
1. **Mocking Collectors**: Use `unittest.mock.patch` or custom mock classes implementing `BaseCollector.collect(mission)` to test orchestration without making real network or subprocess calls.
2. **Registry Isolation**: Use pytest fixtures with teardown to restore `registry.tools` if modifying global tool definitions.
3. **Temporary Directories**: Use `tmp_path` fixture for report output directory tests.
4. **Deterministic Assertions**: Verify exact counts, state lists, and dictionary structures.

---

## 6. Proposed Test Plan: 30 New Tests

We design **30 comprehensive tests** across two new test files:
- `tests/scanning/test_scan_engine.py` (18 Unit & Integration Tests)
- `tests/scanning/test_scan_engine_adversarial.py` (12 Adversarial & Edge Case Tests)

### Part A: Unit & Integration Tests (`tests/scanning/test_scan_engine.py`)

```python
# Test File: tests/scanning/test_scan_engine.py
```

1. **`test_scan_engine_initialization`**
   - **Scope**: Verifies `ScanEngine` initializes with default and custom configurations (`output_dir`, `tool_registry`, `plugin_adapter`).
   - **Assertions**: `engine.output_dir`, `engine.registry`, `engine.adapter` are properly set.

2. **`test_dag_resolution_complete_recon_templates`**
   - **Scope**: Verifies `ScanEngine._build_dag()` parses all 21 templates from `_RECON_TEMPLATES`.
   - **Assertions**: All 21 task keys present; dependencies match `_RECON_TEMPLATES` specification.

3. **`test_topological_sort_linear_ordering`**
   - **Scope**: Verifies topological sort produces an order where every task appears strictly after its dependencies.
   - **Assertions**: `subfinder` is first; `httpx` is after `subfinder`; `katana_crawler` is after `httpx`; all endpoint-dependent collectors are after `katana_crawler`.

4. **`test_topological_sort_determinism`**
   - **Scope**: Runs topological sort 50 times on the same DAG.
   - **Assertions**: Returned task order is identical on every iteration.

5. **`test_collector_resolution_via_registry_and_adapter`**
   - **Scope**: Verifies each `metadata.tool_id` in `_RECON_TEMPLATES` resolves to a valid executable collector instance.
   - **Assertions**: No unresolved tool IDs; returned collectors have `collect` or `execute` callable.

6. **`test_scan_engine_executes_all_collectors_in_order`**
   - **Scope**: Executes `ScanEngine.run(mission)` with mocked collectors that record execution timestamp and call order.
   - **Assertions**: Execution log order exactly matches topological sort; all 21 collectors invoked.

7. **`test_mission_lifecycle_state_transitions`**
   - **Scope**: Tracks `mission.status` throughout a scan run.
   - **Assertions**: Sequence is `CREATED -> READY -> RUNNING -> COLLECTING_EVIDENCE -> CORRELATING -> COMPLETED`; all recorded in `mission.state_transitions`.

8. **`test_state_transition_timestamps_valid_iso`**
   - **Scope**: Validates timestamps on every state transition record.
   - **Assertions**: All timestamps parse as valid ISO-8601 UTC datetimes and are monotonically increasing.

9. **`test_evidence_aggregation_into_evidence_store`**
   - **Scope**: Mock collectors return distinct `Evidence` objects.
   - **Assertions**: `mission.evidence.all()` contains all emitted evidence; total evidence count matches sum of collector outputs.

10. **`test_evidence_deduplication`**
    - **Scope**: Two collectors emit `Evidence` with identical IDs.
    - **Assertions**: `EvidenceStore` de-duplicates by ID without throwing errors.

11. **`test_attack_surface_graph_has_vulnerability_edges`**
    - **Scope**: Mock vulnerability collectors return findings linking live hosts and endpoints.
    - **Assertions**: `mission.attack_surface_graph` contains `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges; `graph.node_count()` > 0.

12. **`test_attack_surface_graph_snapshot_in_scan_result`**
    - **Scope**: Verifies `ScanResult.attack_surface_graph_snapshot` contains accurate node and edge summaries.
    - **Assertions**: Snapshot reflects graph node counts by type (`live_host`, `endpoint`, `vulnerability`) and edge counts by type.

13. **`test_report_generation_creates_markdown_and_json`**
    - **Scope**: Executes scan and inspects generated report files in `tmp_path`.
    - **Assertions**: Both `.md` and `.json` files exist on disk, non-empty, with valid syntax and report contents.

14. **`test_report_paths_registered_in_mission_and_scan_result`**
    - **Scope**: Verifies generated file paths appear in `mission.reports` and `ScanResult.report_paths`.
    - **Assertions**: `len(result.report_paths) == 2`, paths exist, and `mission.reports` matches `result.report_paths`.

15. **`test_scan_result_per_collector_breakdown`**
    - **Scope**: Verifies `ScanResult.collector_results` dictionary.
    - **Assertions**: Every collector has entry with `collector_name`, `status="completed"`, `evidence_count >= 0`, `duration_seconds >= 0.0`, `error=None`.

16. **`test_scan_result_aggregate_statistics`**
    - **Scope**: Verifies `ScanResult.stats` metrics.
    - **Assertions**: `total_evidence == sum(per-collector evidence)`, `collectors_run == 21`, `collectors_failed == 0`, `collectors_skipped == 0`.

17. **`test_scan_result_severity_breakdown`**
    - **Scope**: Mock collectors emit evidence across critical, high, medium, low, info severities.
    - **Assertions**: `result.stats.vulnerabilities_by_severity` accurately counts each severity level.

18. **`test_scan_engine_accepts_target_string_directly`**
    - **Scope**: Calls `ScanEngine.run("example.com")` with string target instead of `Mission`.
    - **Assertions**: Engine auto-wraps into `Mission(target="example.com")` and completes scan successfully.

---

### Part B: Adversarial & Resilience Tests (`tests/scanning/test_scan_engine_adversarial.py`)

```python
# Test File: tests/scanning/test_scan_engine_adversarial.py
```

19. **`test_collector_runtime_exception_does_not_abort_scan`**
    - **Scope**: Injects `RuntimeError("SQL prober crashed")` into `sql_injection` collector.
    - **Assertions**: Scan continues; `xss`, `command_injection`, `ssrf` execute successfully; `ScanResult.collector_results["sql_injection"].status == "failed"`.

20. **`test_root_recon_failure_skips_downstream_dependents`**
    - **Scope**: `subfinder` raises `Exception("Subfinder binary missing")`.
    - **Assertions**: `subfinder` marked `failed`; `httpx`, `katana_crawler`, and all vulnerability collectors marked `skipped`; scan exits cleanly with `status="COMPLETED"` (or completed with skips).

21. **`test_intermediate_recon_failure_selective_skipping`**
    - **Scope**: `katana_crawler` fails, while `httpx` succeeds.
    - **Assertions**: Collectors dependent on `katana_crawler` (e.g. `sql_injection`, `xss`) are `skipped`; collectors dependent on `httpx` (`nuclei`, `info_disclosure`) still run and complete.

22. **`test_collector_instantiation_failure_graceful_handling`**
    - **Scope**: One template specifies a non-existent `tool_id="unknown_scanner"`.
    - **Assertions**: Engine logs error, marks task `failed`, continues executing remaining valid collectors.

23. **`test_circular_dependency_in_dag_detection`**
    - **Scope**: Manually injects circular dependency into task graph.
    - **Assertions**: `ScanEngine` raises `ValueError` or `CyclicDependencyError` with message indicating cycle, without hanging.

24. **`test_disconnected_graph_components_execution`**
    - **Scope**: DAG contains two disconnected trees of tasks.
    - **Assertions**: All nodes across both trees are executed in valid dependency order.

25. **`test_collector_slow_execution_duration_tracking`**
    - **Scope**: Mock collector sleeps for 0.1 seconds during `collect()`.
    - **Assertions**: `duration_seconds >= 0.1` recorded in `ScanResult.collector_results`.

26. **`test_collector_returns_malformed_evidence_types`**
    - **Scope**: Mock collector returns `[None, 123, "not_evidence", {"bad": "dict"}]`.
    - **Assertions**: Engine sanitizes/filters non-Evidence objects without throwing `AttributeError` or corrupting `EvidenceStore`.

27. **`test_report_generator_disk_error_isolation`**
    - **Scope**: Patches `ReportGenerator.save_report` to raise `IOError("Permission denied")`.
    - **Assertions**: Scan completes successfully; warning logged; `ScanResult.report_paths == []`; scan status is not crashed.

28. **`test_zero_evidence_scan_clean_report_output`**
    - **Scope**: Executes scan on clean target where 0 vulnerabilities are detected.
    - **Assertions**: Reports generated successfully; Markdown shows "0 Vulnerabilities Found"; `ScanResult.stats.total_evidence == 0`.

29. **`test_concurrent_scans_state_isolation`**
    - **Scope**: Runs two `ScanEngine` scans concurrently on two different `Mission` instances.
    - **Assertions**: No evidence leakage or cross-contamination between `mission1` and `mission2`.

30. **`test_large_evidence_volume_performance`**
    - **Scope**: Mock collectors emit 5,000 evidence items across 20 collectors.
    - **Assertions**: Scan completes in < 5 seconds; evidence store size is 5,000; stats calculation accurate.

---

## 7. Implementation Architecture Blueprint

### Module Layout
```
argus/
├── scanning/
│   ├── __init__.py           # Exports ScanEngine, ScanResult, CollectorResult
│   ├── engine.py             # Core ScanEngine orchestrator (R1-R4)
│   └── models.py             # ScanResult, CollectorResult dataclasses
tests/
├── scanning/
│   ├── __init__.py
│   ├── test_scan_engine.py               # 18 unit & integration tests
│   └── test_scan_engine_adversarial.py   # 12 adversarial & edge case tests
```

### ScanEngine Execution Flow
1. **Input Normalization**: Accept `Mission` or `target: str` (wrapping into `Mission`).
2. **Lifecycle Start**: Transition `CREATED -> READY -> RUNNING` with timestamp recording.
3. **DAG Resolution & Sorting**: Extract `_RECON_TEMPLATES`, build graph, compute topological sort.
4. **Transition to Evidence Collection**: Transition `RUNNING -> COLLECTING_EVIDENCE`.
5. **Collector Dispatch Loop**:
   - For each task in topological order:
     - Check if all prerequisites succeeded. If not, mark `SKIPPED`.
     - Resolve collector via `ToolRegistry` and `PluginExecutorAdapter` fallback.
     - Execute `collector.collect(mission)`.
     - Ingest returned evidence into `mission.evidence`.
     - Record duration, evidence count, and status (`completed` / `failed`).
6. **Transition to Correlation**: Transition `COLLECTING_EVIDENCE -> CORRELATING`.
7. **Graph Snapshot & Reconciliation**: Ensure all evidence items have corresponding `AttackSurfaceGraph` nodes and `HAS_VULNERABILITY` / `HAS_ENDPOINT` edges.
8. **Report Generation**: Invoke `ReportGenerator.generate_and_save(mission, output_dir)`.
9. **Lifecycle Completion**: Transition `CORRELATING -> COMPLETED`.
10. **Result Packaging**: Return strongly typed `ScanResult`.
