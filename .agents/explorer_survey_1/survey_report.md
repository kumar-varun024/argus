# Sprint 24 Codebase Survey & Scan Orchestration Engine Architecture Analysis

**Date:** 2026-09-01  
**Investigator:** Explorer 1  
**Project:** ARGUS Defensive Security Assessment Platform  
**Target Sprint:** Sprint 24 — Scan Orchestration Engine  

---

## 1. Executive Summary

This investigation provides a comprehensive architectural survey of the ARGUS codebase to prepare the implementation plan and execution blueprint for **Sprint 24: Scan Orchestration Engine**.

Sprint 24 delivers the production scan runner (`ScanEngine`) that replaces legacy simulation with end-to-end execution across the full reconnaissance-to-vulnerability DAG (encompassing all 16 vulnerability modules and recon discovery collectors), aggregating evidence into `EvidenceStore`, expanding the `AttackSurfaceGraph`, and generating consolidated security assessment reports via `ReportGenerator`.

---

## 2. Codebase Architecture & Key Component Survey

### 2.1. Task Generator & DAG Templates (`argus/planning/task_generator.py`)

`argus/planning/task_generator.py` contains `_RECON_TEMPLATES`, which serves as the **source of truth** for DAG topology and task dependencies:

```python
_RECON_TEMPLATES = {
    # Layer 0: Root Recon
    "subfinder": {
        "title": "Discover Subdomains",
        "goal": "Enumerate all subdomains in scope for the target.",
        "category": TaskCategory.TECHNOLOGY_DISCOVERY,
        "required_inputs": ["target"],
        "expected_outputs": ["subdomains"],
        "dependencies": [],
        "metadata": {"tool_id": "subfinder"},
        "priority": 0.95,
    },
    # Layer 1: Host Fingerprinting (depends on Layer 0)
    "httpx": {
        "title": "Fingerprint Live Hosts",
        "goal": "Probe subdomains to discover live HTTP/HTTPS hosts and fingerprint technologies.",
        "category": TaskCategory.TECHNOLOGY_DISCOVERY,
        "required_inputs": ["subdomains"],
        "expected_outputs": ["live_hosts", "technologies"],
        "dependencies": ["Discover Subdomains"],
        "metadata": {"tool_id": "httpx"},
        "priority": 0.90,
    },
    # Layer 2: Crawling & Broad Scans (depends on Layer 1)
    "katana_crawler": {
        "title": "Discover API Endpoints",
        "dependencies": ["Fingerprint Live Hosts"],
        "required_inputs": ["live_hosts"],
        "expected_outputs": ["endpoints"],
        "metadata": {"tool_id": "katana_crawler"},
        "priority": 0.85,
    },
    "nuclei": {
        "title": "Scan Live Hosts",
        "dependencies": ["Fingerprint Live Hosts"],
        "required_inputs": ["live_hosts"],
        "expected_outputs": ["vulnerabilities", "observations"],
        "metadata": {"tool_id": "nuclei"},
        "priority": 0.80,
    },
    "info_disclosure": {
        "title": "Probe Information Disclosure",
        "dependencies": ["Fingerprint Live Hosts"],
        "required_inputs": ["live_hosts"],
        "expected_outputs": ["vulnerabilities", "observations", "evidence", "subdomains"],
        "metadata": {"tool_id": "info_disclosure"},
        "priority": 0.82,
    },
    # Layer 3: 16 Specialized Endpoint Vulnerability Modules (depend on "Discover API Endpoints")
    "access_control": {"title": "Analyze Access Control & IDOR", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "access_control"}},
    "path_traversal": {"title": "Fuzz Path & Directory Traversal", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "path_traversal"}},
    "sql_injection": {"title": "Fuzz SQL Injection", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "sql_injection"}},
    "xss": {"title": "Fuzz Cross-Site Scripting (XSS)", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "xss"}},
    "command_injection": {"title": "Fuzz OS Command Injection", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "command_injection"}},
    "ssrf": {"title": "Fuzz Server-Side Request Forgery (SSRF)", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "ssrf"}},
    "oauth": {"title": "Analyze OAuth & OIDC Authentication", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "oauth"}},
    "xml_parser_validation": {"title": "Validate XML Parser Security", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "xml_parser_validation"}},
    "deserialization": {"title": "Validate Insecure Deserialization", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "deserialization"}},
    "graphql_security": {"title": "Validate GraphQL Security", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "graphql_security"}},
    "websocket_security": {"title": "Validate WebSocket Security", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "websocket_security"}},
    "request_smuggling": {"title": "Validate HTTP Request Smuggling", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "request_smuggling"}},
    "race_conditions": {"title": "Validate Race Conditions & Concurrency", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "race_conditions"}},
    "business_logic": {"title": "Validate Business Logic & State Machine Security", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "business_logic"}},
    "ssti": {"title": "Validate Server-Side Template Injection (SSTI)", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "ssti"}},
    "cache_security": {"title": "Validate Web Cache Security & Cache Deception", "dependencies": ["Discover API Endpoints"], "metadata": {"tool_id": "cache_security"}},
}
```

#### Topological Order & Dependency Graph:
- **Total Templates in `_RECON_TEMPLATES`:** 21 (3 recon/crawling + 2 broad scanning + 16 specialized vulnerability analyzers).
- **DAG Levels:**
  - `Level 0`: `subfinder`
  - `Level 1`: `httpx` (depends on `Discover Subdomains`)
  - `Level 2`: `katana_crawler`, `nuclei`, `info_disclosure` (depend on `Fingerprint Live Hosts`)
  - `Level 3`: 16 vulnerability detection modules (all depend on `Discover API Endpoints`)

---

### 2.2. Tool Registry & Execution Adapters

#### 1. `ToolRegistry` (`argus/runtime/registry.py`)
- Maintains a registry of `Tool` definitions with IDs, aliases, capabilities, supported task categories, and safety permissions.
- Supports alias resolution for fuzzers, e.g., `sqli` -> `sql_injection`, `cmdi` -> `command_injection`, `xxe` -> `xml_parser_validation`, `cswsh` -> `websocket_security`, `wcd` -> `cache_security`.

#### 2. `PluginExecutorAdapter` (`argus/runtime/plugins.py`)
- Provides `_instantiate_specialist_fallback(plugin_id)` and `execute_plugin(plugin_id, mission)`.
- Instantiates internal collector classes:
  - `InformationDisclosureCollector`
  - `AccessControlCollector`
  - `PathTraversalCollector`
  - `SQLInjectionCollector`
  - `XSSCollector`
  - `CommandInjectionCollector`
  - `SSRFCollector`
  - `OAuthCollector`
  - `XMLParserSecurityCollector`
  - `DeserializationCollector`
  - `GraphQLSecurityCollector`
  - `WebSocketSecurityCollector`
  - `HTTPRequestSmugglingCollector`
  - `RaceConditionsCollector`
  - `BusinessLogicCollector`
  - `SSTICollector`
  - `CacheSecurityCollector`

#### 3. Collector Interface (`argus/collectors/base.py` & `argus/collectors/*`)
- All collectors inherit from `BaseCollector`:
  ```python
  class BaseCollector(ABC):
      @abstractmethod
      def collect(self, mission) -> List[Evidence]:
          pass
  ```
- Collectors accept the `mission` object (or `ControlledMission(mission)`).
- When executed, collectors:
  1. Inspect `mission.target`, `mission.live_hosts`, `mission.endpoints`, `mission.subdomains`, `mission.test_identities`.
  2. Perform probes (HTTP requests, payload injections, AST parsing, concurrency checks, etc.).
  3. Instantiate `Evidence` objects and:
     - Add them to `mission.evidence` (`mission.evidence.add(ev)` or `append(ev)`).
     - Add dictionary entries to `mission.vulnerabilities`.
     - Expand `mission.attack_surface_graph` with `Node` and `Edge` objects.
  4. Return `List[Evidence]`.

---

### 2.3. Evidence Production & Attack Surface Graph Wiring

#### Evidence Model (`argus/evidence/model.py` & `argus/evidence/store.py`)
- `EvidenceStore` holds `Evidence` objects with methods: `add(ev)`, `all()`, `filter(category)`, `count()`, `clear()`, `__len__()`, `__iter__()`.
- Each `Evidence` record contains:
  - `evidence_id: str`
  - `mission_id: str`
  - `title: str`, `description: str`, `category: str`, `value: str`, `source: str`
  - `status: str` (e.g., `"CONFIRMED"`)
  - `confidence: float` (e.g., `0.95`)
  - `severity: str` (`"critical"`, `"high"`, `"medium"`, `"low"`, `"info"`)
  - `provenance: ProvenanceData`
  - `metadata: Dict[str, Any]` (e.g., `url`, `host`, `template_id`, `leaked_data`, `payload`, etc.)

#### KnowledgeGraph / AttackSurfaceGraph (`argus/graph/graph.py`)
- Nodes: `Node(id, type, value, metadata)`
  - `type="target"`, `type="subdomain"`, `type="live_host"`, `type="endpoint"`, `type="vulnerability"`, `type="technology"`
- Edges: `Edge(source, target, type, metadata)`
  - Standard edge types:
    - `HAS_SUBDOMAIN`: target -> subdomain
    - `RESOLVES_TO`: subdomain -> live_host
    - `HAS_ENDPOINT`: live_host -> endpoint
    - `HAS_TECHNOLOGY`: live_host -> technology
    - `HAS_VULNERABILITY`: live_host -> vulnerability OR endpoint -> vulnerability

---

### 2.4. Report Consolidation (`argus/reporting/generator.py`)

`ReportGenerator`:
- `generate(mission) -> VulnerabilityReport`
- `render_markdown(report) -> str` (HackerOne-style markdown)
- `render_json(report) -> str` (JSON format)
- `generate_and_save(mission, output_dir) -> List[str]` returns `[md_path, json_path]` and registers them in `mission.reports`.

---

### 2.5. Mission Lifecycle & State Machine (`argus/runtime/mission.py` & `argus/runtime/state_machine.py`)

`MissionState` values:
`CREATED` -> `READY` -> `RUNNING` -> `COLLECTING_EVIDENCE` -> `CORRELATING` -> `COMPLETED` (or `FAILED` upon catastrophic error).

State transitions track:
- `status`: current `MissionState`
- `updated_at`: ISO UTC timestamp
- `state_transitions`: list of transition records `{"from": ..., "to": ..., "reason": ..., "timestamp": ...}`

---

## 3. ScanEngine Design Specification (`argus/scanning/`)

### 3.1. Target Module Structure
```
argus/scanning/
├── __init__.py          # Exports ScanEngine, ScanResult, CollectorResult, ScanConfig
├── engine.py            # Main ScanEngine orchestrator
└── models.py            # ScanResult, CollectorResult, ScanConfig, TaskExecutionRecord
```

### 3.2. Data Models (`argus/scanning/models.py`)

```python
@dataclass
class CollectorResult:
    tool_id: str
    task_title: str
    status: str  # "SUCCEEDED", "FAILED", "SKIPPED"
    duration_ms: float
    evidence_count: int
    vulnerabilities_found: int
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

@dataclass
class ScanResult:
    mission_id: str
    target: str
    status: str  # "COMPLETED", "FAILED"
    started_at: str
    completed_at: str
    duration_seconds: float
    total_tasks: int
    tasks_succeeded: int
    tasks_failed: int
    tasks_skipped: int
    collector_results: Dict[str, CollectorResult] = field(default_factory=dict)
    total_evidence_count: int = 0
    total_vulnerabilities_count: int = 0
    report_paths: List[str] = field(default_factory=list)
    graph_node_count: int = 0
    graph_edge_count: int = 0
    error: Optional[str] = None
```

### 3.3. ScanEngine Execution Algorithm (`argus/scanning/engine.py`)

```python
class ScanEngine:
    def __init__(
        self,
        tool_registry: Optional[ToolRegistry] = None,
        plugin_adapter: Optional[PluginExecutorAdapter] = None,
        report_generator: Optional[ReportGenerator] = None,
        output_dir: Optional[str] = None,
        max_workers: int = 1,
    ):
        ...

    def run_mission(self, mission: Mission) -> ScanResult:
        """
        Executes full scanning DAG on the given Mission:
        1. State: CREATED -> READY -> RUNNING
        2. Resolve DAG tasks from _RECON_TEMPLATES
        3. Topologically sort tasks based on dependencies
        4. State: COLLECTING_EVIDENCE
        5. For each task in topological order:
           a. Check dependency satisfaction (if required parent task failed completely and no assets exist, skip or run with fallback)
           b. Instantiate collector via ToolRegistry / PluginExecutorAdapter or direct collector mapping
           c. Call collector.collect(mission)
           d. Ingest returned Evidence into mission.evidence, update mission.vulnerabilities, update attack_surface_graph
           e. Handle exceptions gracefully: log error, record task failure, continue to next independent task
        6. State: CORRELATING
           a. Consolidate AttackSurfaceGraph nodes & edges (HAS_SUBDOMAIN, RESOLVES_TO, HAS_ENDPOINT, HAS_VULNERABILITY)
        7. Generate reports via ReportGenerator.generate_and_save(mission, output_dir)
        8. State: COMPLETED (or FAILED if catastrophic)
        9. Construct and return ScanResult
        """
```

### 3.4. Resilient Error Handling & Skipping Rules

1. **Task Isolation:** A failure in any single collector (e.g. `ssti` throwing an unhandled network error or `subfinder` missing binary) must NOT crash the scan engine. It is caught, logged, recorded in `CollectorResult(status="FAILED", error=...)`, and the scan proceeds.
2. **Dependency & Asset Fallback:** If upstream recon produces 0 subdomains or 0 endpoints, downstream collectors use the `mission.target` fallback (e.g., probing `https://{target}`) rather than crashing.
3. **Graph Integrity:** If a collector returns evidence without adding graph nodes, `ScanEngine` automatically reconciles all evidence items in `mission.evidence` into the `AttackSurfaceGraph` before generating reports.

---

## 4. Test Suite Requirements

1. **Zero Regression:** All 1,678+ existing unit/integration tests must pass.
2. **Unit Tests (`tests/scanning/test_scan_engine.py`):**
   - DAG resolution and topological sorting.
   - Sequential execution across recon -> collector pipeline.
   - Lifecycle transitions (`CREATED` -> `READY` -> `RUNNING` -> `COLLECTING_EVIDENCE` -> `CORRELATING` -> `COMPLETED`).
   - Evidence aggregation into `EvidenceStore`.
   - `AttackSurfaceGraph` snapshotting (`HAS_ENDPOINT`, `HAS_VULNERABILITY`).
   - `ReportGenerator` integration (Markdown + JSON files generated and registered).
   - `ScanResult` schema, metrics, and duration calculation.
3. **Adversarial & Edge Case Tests (`tests/scanning/test_scan_engine_adversarial.py`):**
   - Collector throwing runtime exception / unhandled error -> engine continues gracefully.
   - Missing / broken dependencies in DAG -> handled gracefully without infinite loop or crash.
   - Empty mission assets (no subdomains, no live hosts, no endpoints) -> runs safely with fallback or skips.
   - Report generator failure during scan -> logged, scan completes with error warning.
   - Concurrency / re-entrancy safety.
   - Cyclic dependency detection in DAG.

---

## 5. Next Steps for Orchestrator

1. Review and approve the implementation plan.
2. Delegate implementation of `argus/scanning/` to the implementation subagent.
3. Delegate comprehensive unit & adversarial test suite creation (`tests/scanning/`) to the test specialist.
4. Run full victory audit and regression verification.
