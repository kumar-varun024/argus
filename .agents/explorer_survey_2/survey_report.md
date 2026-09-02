# ARGUS Sprint 24 Architectural Survey Report: Models, State Transitions, & Reporting Engine

**Author**: Explorer 2 (Sprint 24 Architectural Survey Agent)  
**Date**: 2026-09-01  
**Working Directory**: `/home/varun/argus/.agents/explorer_survey_2`  
**Target Scope**: Models (`Mission`, `MissionState`/`MissionStatus`, `Evidence`, `EvidenceStore`, `AttackSurfaceGraph`, `ScanResult`), State Transitions & Duration Tracking, and Reporting Engine (`ReportGenerator`, Markdown/JSON renderers, Graph Snapshots).

---

## 1. Executive Summary

Sprint 24 delivers the **Scan Orchestration Engine** (`argus/scanning/engine.py`), replacing simulated orchestrators with an end-to-end execution pipeline running the full recon-to-collector DAG across all 16 vulnerability detection modules. 

This survey investigated the core data models, state transition machines, and reporting subsystems to provide an authoritative design blueprint for Sprint 24.

### Key Architectural Discoveries:
1. **Mission & State Representation**:
   - `Mission` is defined in `argus/runtime/mission.py` as a rich dataclass containing configuration, policies, test identities, datastores (`evidence: EvidenceStore`, `attack_surface_graph: KnowledgeGraph`), and lifecycle metadata.
   - The state enumeration is named `MissionState` in `argus/runtime/mission.py` (with member states `CREATED`, `READY`, `RUNNING`, `PLANNING`, `RESEARCHING`, `COLLECTING_EVIDENCE`, `CORRELATING`, `COMPLETED`, `FAILED`, etc.).
   - Recommendation: Define `MissionStatus = MissionState` as an alias and re-export `Mission`, `MissionState`, `MissionStatus`, `Evidence`, `EvidenceStore`, `AttackSurfaceGraph` in `argus/models/__init__.py` and `argus/scanning/models.py`.
2. **ScanResult Dataclass**:
   - Does not currently exist in the codebase; must be created in `argus/scanning/models.py`.
   - Designed to track end-to-end scan execution metrics: per-collector durations, error logs, evidence and vulnerability counts, severity distributions, generated report paths, and an `AttackSurfaceGraph` snapshot summary.
3. **State Machine Transitions**:
   - Scan engine transitions follow: `CREATED` $\rightarrow$ `READY` $\rightarrow$ `RUNNING` $\rightarrow$ `COLLECTING_EVIDENCE` $\rightarrow$ `CORRELATING` $\rightarrow$ `COMPLETED` (or `FAILED`).
   - `MissionStateMachine` in `argus/runtime/state_machine.py` maintains a transition matrix. The matrix currently requires minor additions to permit direct transitions like `CREATED -> READY -> RUNNING` and `CORRELATING -> COMPLETED`.
   - `Mission.state_transitions` preserves an audit log of `{"from": ..., "to": ..., "reason": ..., "timestamp": ...}`.
4. **Consolidated Reporting Pipeline**:
   - `ReportGenerator` in `argus/reporting/generator.py` coordinates `EvidenceProcessor`, `HackerOneMarkdownRenderer`, and `JSONReportRenderer`.
   - `generator.generate_and_save(mission, output_dir)` generates both Markdown and JSON reports, saves them to disk (default `.argus/reports/`), and appends the generated file paths to `mission.reports`.
   - `AttackSurfaceGraphBuilder` transforms raw evidence into a `KnowledgeGraph` populated with nodes (`target`, `subdomain`, `live_host`, `technology`, `endpoint`, `vulnerability`, `secret`, `cname`) and relationships (`HAS_ENDPOINT`, `HAS_VULNERABILITY`, `RUNS_TECHNOLOGY`, `HOSTS`, `RESOLVES_TO`).

---

## 2. Deep Dive: Model Architecture

### 2.1 Mission (`argus/runtime/mission.py`)
`Mission` is the primary runtime state container for all security testing activities in ARGUS.

```python
@dataclass
class Mission:
    target: str
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    workspace: str = "default"
    
    # Lifecycle
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    status: MissionState = MissionState.CREATED
    phase: str = "planning"
    
    # Config & Policy
    scope: list[str] = field(default_factory=list)
    policy: dict = field(default_factory=dict)
    credentials: list[dict] = field(default_factory=list)
    configuration: dict = field(default_factory=dict)
    test_identities: list[TestIdentity] = field(default_factory=list)
    active_identity_id: Optional[str] = None
    environment: dict = field(default_factory=dict)
    
    # State & Graph
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    evidence: EvidenceStore = field(default_factory=EvidenceStore)
    attack_surface_graph: KnowledgeGraph = field(default_factory=KnowledgeGraph)
    reports: list[str] = field(default_factory=list)
    state_transitions: list = field(default_factory=list)
```

In `__post_init__`, `self.attack_surface_graph` is guaranteed to be a `KnowledgeGraph` instance and is aliased to `self.graph`.

### 2.2 MissionState & MissionStatus Enum
Defined in `argus/runtime/mission.py`:
```python
class MissionState(str, Enum):
    CREATED = "CREATED"
    READY = "READY"
    RUNNING = "RUNNING"
    PLANNING = "PLANNING"
    RESEARCHING = "RESEARCHING"
    COLLECTING_EVIDENCE = "COLLECTING_EVIDENCE"
    CORRELATING = "CORRELATING"
    BUILDING_INVESTIGATIONS = "BUILDING_INVESTIGATIONS"
    GENERATING_HYPOTHESES = "GENERATING_HYPOTHESES"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    COMPLETED = "COMPLETED"
    PAUSED = "PAUSED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"
    RECOVERING = "RECOVERING"
```
*Note*: `MissionStatus` is an alias for `MissionState`. Both names should be exported across model interfaces.

### 2.3 Evidence & EvidenceStore (`argus/evidence/`)
- **`Evidence`** (`argus/evidence/model.py`):
  ```python
  @dataclass(slots=True)
  class Evidence:
      evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
      project_id: str = ""
      mission_id: str = ""
      investigation_id: str = ""
      source_type: str = "SYSTEM" # SCREENSHOT, LOG, OBSERVATION
      source_id: str = ""
      created_by: str = "SYSTEM_GENERATED"
      created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
      updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
      title: str = ""
      description: str = ""
      content_reference: str = ""
      category: str = "Other" # e.g. sql_injection, xss, command_injection, etc.
      value: str = ""
      source: str = ""
      status: str = "UNVERIFIED" # UNVERIFIED, CONFIRMED, USER_REVIEWED, etc.
      confidence: float = 1.0
      severity: str = "info" # critical, high, medium, low, info
      provenance: ProvenanceData = field(default_factory=ProvenanceData)
      relationships: List[EvidenceRelationship] = field(default_factory=list)
      tags: List[str] = field(default_factory=list)
      metadata: Dict[str, Any] = field(default_factory=dict)
  ```
- **`EvidenceStore`** (`argus/evidence/store.py`):
  - In-memory collection: `add(evidence: Evidence)`, `all() -> list[Evidence]`, `filter(category: str)`, `count() -> int`, `clear()`, `__iter__`, `__len__`.

### 2.4 AttackSurfaceGraph / KnowledgeGraph (`argus/graph/`)
The graph model consists of:
- **`Node`** (`argus/graph/node.py`): `id: str`, `type: str`, `value: str`, `metadata: dict[str, Any]`.
  - Node types: `target`, `subdomain`, `live_host`, `technology`, `endpoint`, `vulnerability`, `secret`, `cname`.
- **`Edge`** (`argus/graph/edge.py`): `source: str`, `target: str`, `type: str`, `metadata: dict[str, Any]`.
  - Edge types: `RESOLVES_TO`, `HOSTS`, `RUNS_TECHNOLOGY`, `HAS_ENDPOINT`, `HAS_VULNERABILITY`, `POINTS_TO_CNAME`, `EXPOSES_SECRET`, `DISCLOSED_SUBDOMAIN`.
- **`KnowledgeGraph`** (`argus/graph/graph.py`):
  - In-memory directional graph supporting queries:
    - `add(node)`: adds node idempotently.
    - `connect(source, target, edge_type, metadata)`: adds edge if both nodes exist.
    - `nodes_by_type(node_type)`: retrieves all nodes of given type.
    - `edges_from(node)`, `edges_to(node)`, `neighbors(node)`.
    - `summary()`: returns counts of nodes, relationships, and per-type node counts.
    - `get_asset_counts()`: returns counts for `target`, `subdomain`, `live_host`, `endpoint`, `technology`, `vulnerability`.
    - `get_hosts_without_endpoints()`, `get_hosts_without_vulnerabilities()`.
- **`AttackSurfaceGraphBuilder`** (`argus/graph/attack_surface.py`):
  - `build_from_evidence(evidence: EvidenceStore, target: str, graph: Optional[KnowledgeGraph]) -> KnowledgeGraph`
  - `build(mission: Any) -> KnowledgeGraph`: populates `mission.attack_surface_graph` from both `mission.evidence` and structured lists (`mission.subdomains`, `mission.live_hosts`, `mission.endpoints`, `mission.vulnerabilities`).

### 2.5 ScanResult Dataclass Specification
To fulfill Requirement R3 & R4, `ScanResult` will be implemented in `argus/scanning/models.py`:

```python
@dataclass
class CollectorExecutionResult:
    """Detailed execution metric for an individual collector module."""
    collector_id: str
    task_title: str
    status: str # "SUCCESS", "FAILED", "SKIPPED", "TIMED_OUT"
    duration_seconds: float
    evidence_count: int = 0
    vulnerabilities_count: int = 0
    error: Optional[str] = None
    started_at: str = ""
    completed_at: str = ""

@dataclass
class ScanResult:
    """Consolidated execution output of a ScanEngine execution run."""
    mission_id: str
    target: str
    status: MissionState # COMPLETED or FAILED
    start_time: str # ISO UTC
    end_time: str # ISO UTC
    duration_seconds: float
    
    # Per-collector and task breakdown
    tasks_executed: list[str] = field(default_factory=list)
    collector_results: dict[str, CollectorExecutionResult] = field(default_factory=dict)
    
    # Aggregate counts
    evidence_count: int = 0
    vulnerabilities_count: int = 0
    findings_count: int = 0
    severity_counts: dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    
    # Generated Reports & Graph Snapshot
    report_paths: list[str] = field(default_factory=list) # [.md, .json]
    graph_summary: dict[str, Any] = field(default_factory=dict) # Node and edge counts
    
    # Errors encountered during execution
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Lossless serialization to dictionary."""
        return {
            "mission_id": self.mission_id,
            "target": self.target,
            "status": self.status.value if isinstance(self.status, MissionState) else str(self.status),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "tasks_executed": list(self.tasks_executed),
            "collector_results": {
                k: v.__dict__ if hasattr(v, "__dict__") else v 
                for k, v in self.collector_results.items()
            },
            "evidence_count": self.evidence_count,
            "vulnerabilities_count": self.vulnerabilities_count,
            "findings_count": self.findings_count,
            "severity_counts": dict(self.severity_counts),
            "report_paths": list(self.report_paths),
            "graph_summary": dict(self.graph_summary),
            "errors": list(self.errors),
        }
```

---

## 3. Mission State Transitions & Duration Tracking

### 3.1 Scan Engine Lifecycle Sequence
The scan engine strictly drives the `Mission` through the following state transitions:

```
[CREATED]
    │
    ▼ (1. Initialization & DAG resolution)
 [READY]
    │
    ▼ (2. Scan runner starts execution)
[RUNNING]
    │
    ▼ (3. Collector DAG execution begins)
[COLLECTING_EVIDENCE]
    │
    ▼ (4. Collectors finish; graph construction & correlation)
[CORRELATING]
    │
    ▼ (5. Report generation & snapshot capture)
[COMPLETED]  (or [FAILED] on fatal unhandled engine error)
```

### 3.2 State Machine Matrix Alignment (`argus/runtime/state_machine.py`)
`MissionStateMachine` validates transitions using `self.valid_transitions`.
To ensure compatibility across both autonomous runtime workflows and ScanEngine workflows, the valid transition matrix should support:
- `MissionState.CREATED`: `[MissionState.READY, MissionState.PLANNING, MissionState.CANCELLED]`
- `MissionState.READY`: `[MissionState.RUNNING, MissionState.CANCELLED, MissionState.FAILED]`
- `MissionState.RUNNING`: `[MissionState.COLLECTING_EVIDENCE, MissionState.PLANNING, MissionState.RESEARCHING, MissionState.PAUSED, MissionState.CANCELLED, MissionState.FAILED, MissionState.COMPLETED]`
- `MissionState.COLLECTING_EVIDENCE`: `[MissionState.CORRELATING, MissionState.RESEARCHING, MissionState.PAUSED, MissionState.CANCELLED, MissionState.FAILED, MissionState.COMPLETED]`
- `MissionState.CORRELATING`: `[MissionState.BUILDING_INVESTIGATIONS, MissionState.RESEARCHING, MissionState.COMPLETED, MissionState.PAUSED, MissionState.CANCELLED, MissionState.FAILED]`

### 3.3 State Transition Logging & Duration Metrics
Every transition records:
```python
transition_record = {
    "from": previous_state.value,
    "to": target_state.value,
    "reason": reason,
    "timestamp": datetime.now(timezone.utc).isoformat()
}
mission.state_transitions.append(transition_record)
mission.status = target_state
mission.updated_at = datetime.now(timezone.utc).isoformat()
```
Total scan duration is computed using high-resolution monotonic timestamps (`time.perf_counter()`) for elapsed seconds, and recorded with UTC ISO timestamps in `start_time` and `end_time`.

---

## 4. Reporting Architecture & Graph Snapshots

### 4.1 Report Generation Pipeline (`argus/reporting/`)
`ReportGenerator` (`argus/reporting/generator.py`) coordinates the report lifecycle:

```
Mission.evidence (EvidenceStore) 
          │
          ▼
   EvidenceProcessor.process()
          │
          ├── Deduplication: key (category, host, endpoint, parameter)
          ├── CVSS v3.1 calculation & CWE mapping
          ├── Severity distribution & categorization
          ▼
  VulnerabilityReport
     ├── HackerOneMarkdownRenderer.render()  ──> .md report file
     └── JSONReportRenderer.render()        ──> .json report file
```

1. **`EvidenceProcessor`**:
   - Deduplicates findings matching `(category, host, endpoint, parameter)`.
   - Merges evidence occurrences while preserving highest severity and confidence.
   - Calculates CVSS v3.1 scores and vectors.
2. **`HackerOneMarkdownRenderer`**:
   - Produces executive summaries, severity tables, findings scorecard tables, and detailed sections with reproduction steps and PoC payloads.
3. **`JSONReportRenderer`**:
   - Serializes/deserializes lossless typed `VulnerabilityReport` structures.
4. **`ReportGenerator.generate_and_save(mission, output_dir)`**:
   - Saves both Markdown and JSON files named `report_<target>_<timestamp>_<id>.md/.json`.
   - Automatically registers paths in `mission.reports`.

### 4.2 AttackSurfaceGraph Snapshots in Reporting
At the end of a scan:
1. `AttackSurfaceGraphBuilder().build(mission)` synchronizes all discovered assets and vulnerabilities into `mission.attack_surface_graph`.
2. The graph contains topological relationships:
   - Live hosts connected to endpoints via `HAS_ENDPOINT`
   - Live hosts and endpoints connected to vulnerabilities via `HAS_VULNERABILITY`
   - Subdomains resolved to targets via `RESOLVES_TO`
   - Technologies linked to hosts via `RUNS_TECHNOLOGY`
3. Summary stats (`graph.summary()` and `graph.get_asset_counts()`) are embedded directly into `ScanResult.graph_summary`.

---

## 5. Collector & DAG Dispatch Architecture

### 5.1 Source of Truth: `_RECON_TEMPLATES` (`argus/planning/task_generator.py`)
`_RECON_TEMPLATES` defines the DAG tasks and dependencies:

| Tool ID | Task Title | Category | Dependencies |
|---|---|---|---|
| `subfinder` | Discover Subdomains | `TECHNOLOGY_DISCOVERY` | `[]` |
| `httpx` | Fingerprint Live Hosts | `TECHNOLOGY_DISCOVERY` | `["Discover Subdomains"]` |
| `katana_crawler` | Discover API Endpoints | `API_DISCOVERY` | `["Fingerprint Live Hosts"]` |
| `nuclei` | Scan Live Hosts | `EVIDENCE_CORRELATION` | `["Fingerprint Live Hosts"]` |
| `info_disclosure` | Probe Information Disclosure | `EVIDENCE_CORRELATION` | `["Fingerprint Live Hosts"]` |
| `access_control` | Analyze Access Control & IDOR | `AUTHORIZATION_ANALYSIS` | `["Discover API Endpoints"]` |
| `path_traversal` | Fuzz Path & Directory Traversal | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |
| `sql_injection` | Fuzz SQL Injection | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |
| `xss` | Fuzz Cross-Site Scripting (XSS) | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |
| `command_injection` | Fuzz OS Command Injection | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |
| `ssrf` | Fuzz Server-Side Request Forgery | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |
| `oauth` | Analyze OAuth & OIDC Authentication | `AUTHORIZATION_ANALYSIS` | `["Discover API Endpoints"]` |
| `xml_parser_validation` | Validate XML Parser Security | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |
| `deserialization` | Validate Insecure Deserialization | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |
| `graphql_security` | Validate GraphQL Security | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |
| `websocket_security` | Validate WebSocket Security | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |
| `request_smuggling` | Validate HTTP Request Smuggling | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |
| `race_conditions` | Validate Race Conditions & Concurrency | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |
| `business_logic` | Validate Business Logic Security | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |
| `ssti` | Validate Server-Side Template Injection | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |
| `cache_security` | Validate Web Cache Security & Deception | `EVIDENCE_CORRELATION` | `["Discover API Endpoints"]` |

### 5.2 Collector Invocation Pattern
- Collectors inherit from `BaseCollector` (`argus/collectors/base.py`) and implement `collect(mission) -> List[Evidence]`.
- Collectors are dynamically resolved via `ToolRegistry` (`argus/runtime/registry.py`) and `PluginExecutorAdapter` (`argus/runtime/plugins.py`).
- Each collector receives the `mission`, extracts candidate endpoints/hosts, executes tests, creates `Evidence` objects, appends to `mission.evidence`, and updates `mission.vulnerabilities` and graph edges.

---

## 6. Sprint 24 Module Design Recommendations

### 6.1 Directory & File Layout
To maintain clean separation and PROJECT.md layout compliance:
```
argus/
├── models/
│   ├── __init__.py           # Re-export Mission, MissionState, MissionStatus, Evidence, EvidenceStore, KnowledgeGraph, AttackSurfaceGraph, ScanResult
│   └── ...
├── scanning/                 # Sprint 24 New Package
│   ├── __init__.py           # Exports ScanEngine, ScanResult, CollectorExecutionResult
│   ├── engine.py             # Core ScanEngine implementing R1-R4
│   ├── models.py             # ScanResult and CollectorExecutionResult dataclasses
│   └── dag.py                # DAG resolver and topological sorter based on _RECON_TEMPLATES
tests/
└── scanning/
    ├── test_scan_engine.py             # Standard lifecycle, DAG, execution, reporting tests
    └── test_scan_engine_adversarial.py # Edge cases: timeouts, network failures, empty scopes, malformed targets
```

### 6.2 Test Plan
At least 25 new tests across `tests/scanning/`:
1. `test_scan_engine_dag_topological_sort`: verifies topological sort order matches dependency graph.
2. `test_scan_engine_lifecycle_transitions`: asserts exact state progression `CREATED -> READY -> RUNNING -> COLLECTING_EVIDENCE -> CORRELATING -> COMPLETED`.
3. `test_scan_engine_failed_state_transition`: verifies unhandled error transitions to `FAILED`.
4. `test_scan_engine_graceful_task_failure_recovery`: verifies that if an individual collector fails, the engine logs the error, records failure in `ScanResult.collector_results`, and continues executing independent tasks.
5. `test_scan_engine_evidence_aggregation`: verifies evidence from all collectors is merged into `mission.evidence`.
6. `test_scan_engine_report_generation`: verifies markdown and json reports are produced and paths attached to `ScanResult.report_paths` and `mission.reports`.
7. `test_scan_engine_attack_surface_graph_snapshot`: verifies `AttackSurfaceGraph` nodes and edges (`HAS_ENDPOINT`, `HAS_VULNERABILITY`) are built.
8. `test_scan_engine_duration_and_metrics`: verifies duration tracking per collector and total mission duration.
9. `test_scan_engine_empty_target_handling`: adversarial validation for empty or invalid target strings.
10. `test_scan_engine_collector_timeout_resilience`: adversarial validation when a collector exceeds configured timeouts.
11. `test_scan_engine_duplicate_evidence_deduplication`: verifies duplicate evidence across collectors is cleanly deduplicated by reporting processor.
12. `test_scan_engine_identity_context_propagation`: verifies test identities are preserved during collector execution.

---

## 7. Baseline Verification Status
- Full test suite execution: `python -m pytest tests/ --ignore=tests/workspace -q`
- **Result: 1,678 passed, 0 failed, 0 errors** (68.72s execution time).
- Baseline is 100% green and ready for Sprint 24 implementation.
