# Sprint 24: Scan Orchestration Engine — Test Architecture & Scenario Survey

**Author**: Explorer Survey 3 (Test Suite Surveyor & QA Architect)  
**Date**: 2026-09-01  
**Project**: ARGUS Defensive Security Assessment Platform  
**Target Module**: Scan Orchestration Engine (`argus/scanning/engine.py`)  
**Test Targets**: `tests/scanning/test_scan_engine.py`, `tests/scanning/test_scan_engine_adversarial.py`  
**Baseline Status**: **1,678 passed** in 66.81s (`python -m pytest tests/ --ignore=tests/workspace -x -q`) with zero regressions.

---

## 1. Executive Summary

Sprint 24 delivers the **Scan Orchestration Engine** (`ScanEngine` in `argus/scanning/engine.py`), replacing simulated orchestrators with a concrete end-to-end runner that executes a dependency-directed acyclic graph (DAG) across **21 task templates** (including all 16 vulnerability detection modules), aggregates evidence into `EvidenceStore`, builds the `AttackSurfaceGraph`, tracks lifecycle state, and consolidates findings into Markdown and JSON reports via `ReportGenerator`.

This survey provides:
1. **Baseline Test Audit**: Verified test execution command and existing framework patterns.
2. **DAG & Architecture Analysis**: Complete mapping of the 21-node recon and vulnerability detection DAG from `_RECON_TEMPLATES` in `argus/planning/task_generator.py`.
3. **Core Test Suite Specification**: **20 comprehensive unit and integration test scenarios** for `tests/scanning/test_scan_engine.py`.
4. **Adversarial Test Suite Specification**: **14 rigorous stress and edge-case scenarios** for `tests/scanning/test_scan_engine_adversarial.py`.
5. **Total Test Target**: **34 new high-quality tests** (well exceeding the >= 25 requirement) designed for strict zero regression.

---

## 2. Baseline Test Environment & Suite Architecture

### 2.1 Baseline Verification
- **Command**: `python -m pytest tests/ --ignore=tests/workspace -x -q`
- **Result**: `1678 passed, 29080 warnings in 66.81s (0:01:06)`
- **Exit Code**: 0 (Clean baseline pass)
- **Framework**: `pytest 9.0.3` / `9.1.1` on Python 3.13 Linux environment.
- **Location of New Directory**: `tests/scanning/` (directory to be created, containing `__init__.py`, `test_scan_engine.py`, and `test_scan_engine_adversarial.py`).

### 2.2 System Component Topology & Source-of-Truth

| Component | File Path | Responsibilities in Sprint 24 |
|---|---|---|
| **ScanEngine** | `argus/scanning/engine.py` *(New)* | DAG resolution, topological sorting, collector dispatch, error isolation, lifecycle orchestration, evidence aggregation, report consolidation. |
| **ScanResult** | `argus/scanning/engine.py` *(New)* | Immutable dataclass recording per-collector durations, statuses, errors, finding totals, evidence count, and report paths. |
| **TaskGenerator / DAG Templates** | `argus/planning/task_generator.py` | `_RECON_TEMPLATES` dictionary containing 21 task definitions, titles, dependencies, priorities, tool IDs, and input/output contracts. |
| **ToolRegistry** | `argus/runtime/registry.py` | Tool lookup and capability aliasing for standard tools (`subfinder`, `httpx`, `katana`, `nuclei`). |
| **PluginExecutorAdapter** | `argus/runtime/plugins.py` | Specialist collector dynamic fallback instantiation for advanced vulnerability collectors (`xss`, `sql_injection`, `oauth`, `graphql_security`, `websocket_security`, `deserialization`, `business_logic`, `ssti`, `cache_security`, etc.). |
| **EvidenceStore** | `argus/evidence/store.py` | In-memory thread-safe evidence repository (`mission.evidence`). |
| **AttackSurfaceGraph / KnowledgeGraph** | `argus/graph/graph.py` | Node and edge network mapping (`HAS_ENDPOINT`, `HAS_VULNERABILITY`, `RESOLVES_TO`). |
| **ReportGenerator** | `argus/reporting/generator.py` | Markdown and JSON vulnerability report generation and persistence (`generate_and_save`). |
| **Mission / MissionState** | `argus/runtime/mission.py` | Core mission context and lifecycle enum (`CREATED` -> `READY` -> `RUNNING` -> `COLLECTING_EVIDENCE` -> `CORRELATING` -> `COMPLETED`/`FAILED`). |

---

## 3. DAG Topology & Dependency Matrix (Source of Truth)

The 21 task templates in `_RECON_TEMPLATES` form a 4-tier directed acyclic graph:

```
[Level 0]
   └── subfinder ("Discover Subdomains")
         │
[Level 1]
         └── httpx ("Fingerprint Live Hosts")
               │
[Level 2]     ├── nuclei ("Scan Live Hosts")
               ├── info_disclosure ("Probe Information Disclosure")
               └── katana_crawler ("Discover API Endpoints")
                     │
[Level 3: 16 Vulnerability Detection Modules]
                     ├── access_control ("Analyze Access Control & IDOR")
                     ├── path_traversal ("Fuzz Path & Directory Traversal")
                     ├── sql_injection ("Fuzz SQL Injection")
                     ├── xss ("Fuzz Cross-Site Scripting (XSS)")
                     ├── command_injection ("Fuzz OS Command Injection")
                     ├── ssrf ("Fuzz Server-Side Request Forgery (SSRF)")
                     ├── oauth ("Analyze OAuth & OIDC Authentication")
                     ├── xml_parser_validation ("Validate XML Parser Security")
                     ├── deserialization ("Validate Insecure Deserialization")
                     ├── graphql_security ("Validate GraphQL Security")
                     ├── websocket_security ("Validate WebSocket Security")
                     ├── request_smuggling ("Validate HTTP Request Smuggling")
                     ├── race_conditions ("Validate Race Conditions & Concurrency")
                     ├── business_logic ("Validate Business Logic & State Machine Security")
                     ├── ssti ("Validate Server-Side Template Injection (SSTI)")
                     └── cache_security ("Validate Web Cache Security & Cache Deception")
```

### Dependency Validation Rules:
1. `subfinder` has 0 dependencies.
2. `httpx` requires `["Discover Subdomains"]`.
3. `katana_crawler`, `nuclei`, `info_disclosure` require `["Fingerprint Live Hosts"]`.
4. All 16 vulnerability collectors require `["Discover API Endpoints"]`.
5. Topological sorting must produce a valid execution sequence where all prerequisite tasks strictly precede dependent tasks.

---

## 4. Core Test Suite Specification: `tests/scanning/test_scan_engine.py`

Target: **20 Core Unit & Integration Tests** organized into 6 test classes.

### Class 1: `TestScanEngineDAGResolution`
1. **`test_dag_extraction_from_recon_templates`**
   - **Goal**: Verify `ScanEngine` accurately parses `_RECON_TEMPLATES` from `argus.planning.task_generator`.
   - **Assertions**: Extracts all 21 templates; creates internal task nodes with correct `tool_id`, `dependencies`, and `category`.
2. **`test_topological_sort_linear_sequence`**
   - **Goal**: Verify topological sorting for a simple linear dependency path (e.g. `subfinder` -> `httpx` -> `katana_crawler` -> `xss`).
   - **Assertions**: Sorted execution list guarantees indices: `idx(subfinder) < idx(httpx) < idx(katana_crawler) < idx(xss)`.
3. **`test_topological_sort_full_21_node_graph`**
   - **Goal**: Validate topological sort across the full 21-node graph.
   - **Assertions**: `subfinder` is first; `httpx` is before `katana`, `nuclei`, `info_disclosure`; all 16 Level 3 collectors appear strictly after `katana_crawler`.
4. **`test_targeted_subgraph_execution`**
   - **Goal**: Test executing a restricted scope or specific target tasks (e.g. only recon or a single vulnerability module).
   - **Assertions**: If target is `["xss"]`, engine automatically includes transitive prerequisites `["subfinder", "httpx", "katana_crawler", "xss"]` and executes them in valid topological order.

### Class 2: `TestScanEngineCollectorDispatch`
5. **`test_standard_tool_registry_resolution`**
   - **Goal**: Verify resolution of standard recon tools (`subfinder`, `httpx`, `katana_crawler`, `nuclei`) via `ToolRegistry`.
   - **Assertions**: Correct tool class or executable mapping is resolved; no unresolved tool exceptions.
6. **`test_specialist_collector_plugin_adapter_fallback`**
   - **Goal**: Verify resolution of the 16 vulnerability modules via `PluginExecutorAdapter._instantiate_specialist_fallback()`.
   - **Assertions**: Each of `xss`, `sql_injection`, `oauth`, `graphql_security`, `websocket_security`, `deserialization`, `business_logic`, `ssti`, `cache_security`, `command_injection`, `ssrf`, `xml_parser_validation`, `access_control`, `path_traversal`, `request_smuggling`, `race_conditions` is cleanly instantiated with `.collect()` or `.execute()`.
7. **`test_collector_collect_invocation_and_return_handling`**
   - **Goal**: Verify `ScanEngine.run_collector(task, mission)` invokes `.collect(mission)` and captures returned `List[Evidence]`.
   - **Assertions**: Returned evidence is registered; collector duration is measured; collector status is marked `"SUCCESS"`.
8. **`test_collector_mission_mutation_compatibility`**
   - **Goal**: Verify engine handles collectors that mutate `mission.subdomains`, `mission.live_hosts`, `mission.endpoints`, or `mission.vulnerabilities` in-place.
   - **Assertions**: Mutated state is preserved across downstream tasks in the DAG.

### Class 3: `TestScanEngineLifecycleAndState`
9. **`test_full_mission_lifecycle_state_transitions`**
   - **Goal**: Verify state transitions throughout scan execution.
   - **Assertions**: Mission transitions monotonically: `CREATED` -> `READY` -> `RUNNING` -> `COLLECTING_EVIDENCE` -> `CORRELATING` -> `COMPLETED`. All states logged in `mission.state_transitions` with UTC ISO timestamps.
10. **`test_mission_failure_state_transition`**
    - **Goal**: Verify state transition to `FAILED` if unrecoverable initialization error occurs.
    - **Assertions**: `mission.status == MissionState.FAILED`; `mission.phase == "failed"`; error recorded in `ScanResult`.
11. **`test_scan_duration_and_timing_metrics`**
    - **Goal**: Verify `start_time`, `end_time`, `duration_seconds` are accurately populated in `ScanResult` and match sum of individual collector durations within tolerance.
    - **Assertions**: `ScanResult.duration_seconds >= 0`; valid ISO timestamps in `start_time` and `end_time`.

### Class 4: `TestScanEngineEvidenceStore`
12. **`test_evidence_aggregation_across_collectors`**
    - **Goal**: Verify evidence produced by multiple distinct collectors aggregates cleanly into `mission.evidence` (`EvidenceStore`).
    - **Assertions**: Total evidence count equals sum of evidence items emitted; all items queryable via `mission.evidence.all()` and `mission.evidence.filter(category)`.
13. **`test_evidence_category_and_severity_preservation`**
    - **Goal**: Verify evidence items maintain their original severity (`critical`, `high`, `medium`, `low`, `info`) and category values.
    - **Assertions**: Severities and categories are not overwritten or normalized incorrectly during aggregation.
14. **`test_evidence_provenance_and_metadata`**
    - **Goal**: Verify evidence objects contain collector source metadata, endpoint/host reference, and timestamps.
    - **Assertions**: `ev.metadata["discovered_by"]` or `ev.source` identifies originating collector.

### Class 5: `TestScanEngineAttackSurfaceGraph`
15. **`test_attack_surface_graph_node_population`**
    - **Goal**: Verify nodes for target, discovered subdomains, live hosts, endpoints, and vulnerabilities are added to `mission.attack_surface_graph`.
    - **Assertions**: `graph.nodes` contains nodes of type `target`, `subdomain`, `live_host`, `endpoint`, `vulnerability`.
16. **`test_attack_surface_graph_edge_integrity`**
    - **Goal**: Verify graph connections: `target` -> `subdomain` (`RESOLVES_TO`), `live_host` -> `endpoint` (`HAS_ENDPOINT`), `endpoint` -> `vulnerability` (`HAS_VULNERABILITY`), `live_host` -> `vulnerability` (`HAS_VULNERABILITY`).
    - **Assertions**: `graph.edge_count() > 0`; correct `edge.type` values; no self-referential or dangling edges.
17. **`test_multi_host_multi_endpoint_graph_consistency`**
    - **Goal**: Test graph expansion across multiple hosts with shared and distinct endpoints.
    - **Assertions**: Node deduplication works (no duplicate node IDs); edge count accurately reflects topology.

### Class 6: `TestScanEngineReportingAndConsolidation`
18. **`test_report_generator_invocation`**
    - **Goal**: Verify `ScanEngine` invokes `ReportGenerator.generate_and_save(mission, output_dir)` upon scan completion.
    - **Assertions**: Both `.md` and `.json` report files are generated on disk in specified or default output directory; file contents match mission evidence.
19. **`test_scan_result_dataclass_fields_and_stats`**
    - **Goal**: Verify complete schema of `ScanResult` dataclass.
    - **Assertions**: Contains `mission_id`, `target`, `status`, `collector_results` (dict of `CollectorResult`), `total_evidence`, `total_vulnerabilities`, `report_paths`, `graph_nodes`, `graph_edges`, `duration_seconds`.
20. **`test_e2e_full_scan_mocked_pipeline`**
    - **Goal**: End-to-end integration test with mocked collectors producing subdomains, hosts, endpoints, and vulnerabilities across all 21 tasks.
    - **Assertions**: Full pipeline runs without error; produces valid `ScanResult`, populated `AttackSurfaceGraph`, `EvidenceStore`, and valid Markdown/JSON reports on disk.

---

## 5. Adversarial Test Suite Specification: `tests/scanning/test_scan_engine_adversarial.py`

Target: **14 Adversarial & Stress-Testing Scenarios** organized into 4 test classes.

### Class 1: `TestScanEngineDAGCorruptionAdversarial`
1. **`test_direct_cyclic_dag_rejection`**
   - **Scenario**: Introduce direct 2-node circular dependency (`A -> B -> A`).
   - **Assertion**: `ScanEngine` raises `CyclicDependencyError` (or `ValueError` with "cycle detected"), mission status transitions to `FAILED`, and execution immediately halts without infinite recursion.
2. **`test_deep_multi_node_cyclic_dag_rejection`**
   - **Scenario**: Multi-hop cycle in a complex subgraph (`A -> B -> C -> D -> E -> B`).
   - **Assertion**: Cycle is identified; descriptive error names the cycle participants; engine aborts cleanly.
3. **`test_self_referential_task_dependency`**
   - **Scenario**: Task configured with itself as dependency (`dependencies: ["Discover Subdomains"]` inside `Discover Subdomains`).
   - **Assertion**: Detected during DAG validation before any collector execution starts.
4. **`test_missing_dependency_reference_handling`**
   - **Scenario**: Task specifies dependency `"NonExistentPrerequisiteTask"`.
   - **Assertion**: Engine catches missing dependency, marks task as `BLOCKED`/`SKIPPED` or raises structured validation error without unhandled key error.

### Class 2: `TestScanEngineCrashingCollectorsAdversarial`
5. **`test_isolated_collector_crash_resilience`**
   - **Scenario**: A single vulnerability collector (e.g. `sql_injection`) raises `RuntimeError("Database driver panic")` or `ZeroDivisionError`.
   - **Assertion**: Exception is caught and isolated; `ScanResult.collector_results["sql_injection"].status == "FAILED"`; error message and traceback captured; remaining 15 independent vulnerability collectors continue execution successfully.
6. **`test_cascading_failure_skip_dependents`**
   - **Scenario**: Root recon task `subfinder` fails completely.
   - **Assertion**: Dependent task `httpx` and downstream tasks (`katana_crawler`, vulnerability modules) are cleanly marked `SKIPPED` / `BLOCKED` with reason `"Prerequisite 'Discover Subdomains' failed"`.
7. **`test_all_collectors_failing_graceful_degradation`**
   - **Scenario**: Every collector in the pipeline raises an exception.
   - **Assertion**: `ScanEngine` executes lifecycle to completion without unhandled crash; sets status to `FAILED` or `COMPLETED_WITH_ERRORS`; produces structured `ScanResult` documenting all 21 failures.
8. **`test_collector_timeout_isolation`**
   - **Scenario**: Collector simulates slow execution / hang exceeding per-task timeout threshold.
   - **Assertion**: Engine interrupts task, records `"TIMEOUT"` in collector result, and proceeds to next task.

### Class 3: `TestScanEngineMalformedInputAdversarial`
9. **`test_empty_mission_target_and_assets`**
   - **Scenario**: `Mission(target="", subdomains=[], live_hosts=[], endpoints=[])`.
   - **Assertion**: Engine runs without crashing or throwing `IndexError` / `TypeError`; completes with 0 findings and empty reports.
10. **`test_malformed_evidence_emission`**
    - **Scenario**: Faulty collector emits `[None, "invalid_string", 12345, {"broken": "dict"}]` instead of valid `Evidence` instances.
    - **Assertion**: Engine sanitizes and filters out invalid items; logs warnings; avoids corrupting `EvidenceStore`.
11. **`test_hostile_target_and_payload_injection_safety`**
    - **Scenario**: Target domain containing path traversal and command injection metacharacters: `target = "../../etc/passwd; rm -rf /; <script>alert(1)</script>"`.
    - **Assertion**: Safe sanitization in output report filenames, graph node IDs, and logs; no path traversal or code injection vulnerability.
12. **`test_corrupted_attack_surface_graph_defensiveness`**
    - **Scenario**: `mission.attack_surface_graph` is `None` or an object missing standard methods.
    - **Assertion**: Engine defensively initializes or re-attaches a valid `KnowledgeGraph` without crashing.

### Class 4: `TestScanEngineLifecycleInterruptionAdversarial`
13. **`test_mid_scan_cancellation`**
    - **Scenario**: `engine.cancel()` or `mission.status = MissionState.CANCELLED` triggered while collectors are running.
    - **Assertion**: Engine halts pending queue immediately, marks remaining tasks `CANCELLED`, records final duration, and returns `ScanResult` with `status == "CANCELLED"`.
14. **`test_unwriteable_report_directory_resilience`**
    - **Scenario**: Report output directory path is read-only / unwriteable (simulated with `mock` or permission failure).
    - **Assertion**: Report generation error is captured in `ScanResult.errors`; scan status and in-memory evidence remain intact; collector findings are not discarded.

---

## 6. Implementation Guidance for ScanEngine & ScanResult

### 6.1 Recommended `ScanResult` Dataclass Signature
```python
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

@dataclass
class CollectorExecutionResult:
    tool_id: str
    title: str
    status: str  # "SUCCESS", "FAILED", "SKIPPED", "TIMEOUT", "CANCELLED"
    duration_seconds: float
    evidence_count: int
    error_message: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

@dataclass
class ScanResult:
    mission_id: str
    target: str
    status: str  # "COMPLETED", "FAILED", "CANCELLED"
    collector_results: Dict[str, CollectorExecutionResult] = field(default_factory=dict)
    total_collectors: int = 0
    succeeded_collectors: int = 0
    failed_collectors: int = 0
    skipped_collectors: int = 0
    total_evidence: int = 0
    total_vulnerabilities: int = 0
    report_paths: List[str] = field(default_factory=list)
    graph_nodes: int = 0
    graph_edges: int = 0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)
```

### 6.2 Recommended `ScanEngine` Class Interface
```python
class ScanEngine:
    """End-to-end Scan Orchestration Engine for ARGUS security assessment."""

    def __init__(
        self,
        tool_registry: Optional[ToolRegistry] = None,
        plugin_adapter: Optional[PluginExecutorAdapter] = None,
        report_generator: Optional[ReportGenerator] = None,
        max_workers: int = 1,
        output_dir: Optional[str] = None,
    ): ...

    def run(self, mission: Mission, target_tools: Optional[List[str]] = None) -> ScanResult:
        """Executes full or partial scan DAG against target mission."""
        ...

    def resolve_dag(self, target_tools: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Extracts and topologically sorts task templates from _RECON_TEMPLATES."""
        ...

    def cancel(self):
        """Signals active scan runner to halt execution."""
        ...
```

---

## 7. Zero-Regression Verification Strategy

To guarantee strict compliance with the **Zero Regression Rule**:
1. **Target Subagent Run**:
   - `python -m pytest tests/scanning/ -q` -> Must pass 34/34 new tests.
2. **Full Repo Victory Audit**:
   - `python -m pytest tests/ --ignore=tests/workspace -x -q` -> Must pass >= 1,712 total tests (1,678 baseline + 34 new tests) with zero errors.
3. **No Global Mock Leakage**:
   - Ensure all `unittest.mock.patch` calls in tests use clean context managers (`with patch(...)`) or pytest `mocker`/`monkeypatch` fixtures to prevent side effects in other suites.
4. **Clean Disk Cleanup**:
   - Always use `tmp_path` fixture for all report output directories and scratch files.

---

## 8. Summary of Findings & Next Steps

- **Baseline is 100% stable**: 1,678 passed tests.
- **DAG source of truth confirmed**: `_RECON_TEMPLATES` in `argus/planning/task_generator.py` defines 21 tasks across 4 dependency tiers with all 16 vulnerability modules.
- **34 test scenarios fully specified**: 20 core tests + 14 adversarial tests covering all edge cases, crashes, cycles, malformed inputs, and lifecycle states.
- **Ready for Implementation & Test Writing**: Implementing Worker and Test Worker subagents can proceed with exact specifications.
