# Sprint 24 Codebase Survey & Architectural Analysis: Scan Orchestration Engine

**Target Engine**: `ScanEngine` in `argus/scanning/engine.py`  
**Date**: 2026-09-01  
**Author**: Explorer 1 (`.agents/explorer_survey_1`)  
**Baseline Test Status**: 1,678 passed, 0 failures (pytest)

---

## 1. Executive Summary

Sprint 24 delivers the **Scan Orchestration Engine** (`ScanEngine` in `argus/scanning/engine.py`) for the ARGUS platform. Currently, previous iterations used simulated step execution in `argus/orchestration/orchestrator.py` and mock agent steps in `argus/execution/engine.py`.

The new `ScanEngine` will serve as the real, end-to-end scan runner that:
1. Accepts a `Mission` object targeting a domain/host.
2. Resolves the task DAG from `_RECON_TEMPLATES` in `argus/planning/task_generator.py`.
3. Performs deterministic topological sorting of the DAG.
4. Drives the `Mission` lifecycle across states (`CREATED` → `READY` → `RUNNING` → `COLLECTING_EVIDENCE` → `CORRELATING` → `COMPLETED`/`FAILED`).
5. Dynamically resolves each task's `metadata.tool_id` to its corresponding collector class via `ToolRegistry` and `PluginExecutorAdapter` fallback mechanisms (no hardcoded collector imports).
6. Dispatches and executes all 3 recon modules and 18 vulnerability detection modules/collectors with resilient error handling (independent tasks proceed if one collector fails).
7. Aggregates all returned `Evidence` objects into `mission.evidence` (`EvidenceStore`) and graph nodes/edges into `mission.attack_surface_graph` (`KnowledgeGraph`).
8. Triggers `ReportGenerator` to produce consolidated Markdown and JSON reports in `.argus/reports/`.
9. Returns a comprehensive `ScanResult` dataclass with per-collector results, execution durations, error logs, aggregate vulnerability counts by severity, and report file paths.

---

## 2. Codebase Architecture Review

### 2.1 `argus/scanning/`
- **Current State**: The directory `argus/scanning/` does NOT exist yet.
- **Required Files**:
  - `argus/scanning/__init__.py`: Exports `ScanEngine`, `ScanResult`, `CollectorResult`, etc.
  - `argus/scanning/engine.py`: Contains `ScanEngine` core orchestration logic.
  - `argus/scanning/models.py` (or within `engine.py`): Data models for `ScanResult`, `CollectorStatus`, `CollectorResult`, etc.

### 2.2 `argus/planning/task_generator.py` & the `_RECON_TEMPLATES` DAG
The source of truth for the scan task DAG is `_RECON_TEMPLATES` (lines 13–266 in `argus/planning/task_generator.py`).
It defines 21 tasks:

| # | Template Key | Task Title | Category | Dependencies | Tool ID (`metadata.tool_id`) |
|---|---|---|---|---|---|
| 1 | `subfinder` | Discover Subdomains | TECHNOLOGY_DISCOVERY | `[]` | `subfinder` |
| 2 | `httpx` | Fingerprint Live Hosts | TECHNOLOGY_DISCOVERY | `["Discover Subdomains"]` | `httpx` |
| 3 | `katana_crawler` | Discover API Endpoints | API_DISCOVERY | `["Fingerprint Live Hosts"]` | `katana_crawler` |
| 4 | `nuclei` | Scan Live Hosts | EVIDENCE_CORRELATION | `["Fingerprint Live Hosts"]` | `nuclei` |
| 5 | `info_disclosure` | Probe Information Disclosure | EVIDENCE_CORRELATION | `["Fingerprint Live Hosts"]` | `info_disclosure` |
| 6 | `access_control` | Analyze Access Control & IDOR | AUTHORIZATION_ANALYSIS | `["Discover API Endpoints"]` | `access_control` |
| 7 | `path_traversal` | Fuzz Path & Directory Traversal | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `path_traversal` |
| 8 | `sql_injection` | Fuzz SQL Injection | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `sql_injection` |
| 9 | `xss` | Fuzz Cross-Site Scripting (XSS) | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `xss` |
| 10 | `command_injection` | Fuzz OS Command Injection | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `command_injection` |
| 11 | `ssrf` | Fuzz Server-Side Request Forgery (SSRF) | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `ssrf` |
| 12 | `oauth` | Analyze OAuth & OIDC Authentication | AUTHORIZATION_ANALYSIS | `["Discover API Endpoints"]` | `oauth` |
| 13 | `xml_parser_validation` | Validate XML Parser Security | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `xml_parser_validation` |
| 14 | `deserialization` | Validate Insecure Deserialization | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `deserialization` |
| 15 | `graphql_security` | Validate GraphQL Security | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `graphql_security` |
| 16 | `websocket_security` | Validate WebSocket Security | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `websocket_security` |
| 17 | `request_smuggling` | Validate HTTP Request Smuggling | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `request_smuggling` |
| 18 | `race_conditions` | Validate Race Conditions & Concurrency | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `race_conditions` |
| 19 | `business_logic` | Validate Business Logic & State Machine Security | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `business_logic` |
| 20 | `ssti` | Validate Server-Side Template Injection (SSTI) | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `ssti` |
| 21 | `cache_security` | Validate Web Cache Security & Cache Deception | EVIDENCE_CORRELATION | `["Discover API Endpoints"]` | `cache_security` |

#### DAG Dependency Structure:
1. **Root**: `Discover Subdomains` (`subfinder`)
2. **Level 1**: `Fingerprint Live Hosts` (`httpx`) depends on `Discover Subdomains`
3. **Level 2**:
   - `Discover API Endpoints` (`katana_crawler`) depends on `Fingerprint Live Hosts`
   - `Scan Live Hosts` (`nuclei`) depends on `Fingerprint Live Hosts`
   - `Probe Information Disclosure` (`info_disclosure`) depends on `Fingerprint Live Hosts`
4. **Level 3**: All remaining 16 vulnerability detection modules depend on `Discover API Endpoints`.

---

### 2.3 `ToolRegistry` & `PluginExecutorAdapter`

#### `ToolRegistry` (`argus/runtime/registry.py`)
- Registered tools include all CLI tools (`subfinder`, `httpx`, `katana_crawler`, `nuclei`, `dnsx`) and internal collectors (`info_disclosure`, `access_control`, `path_traversal`, `sql_injection`, `xss`, `command_injection`, `ssrf`, `oauth`, `xml_parser_validation`, `deserialization`, `graphql_security`, `websocket_security`, `request_smuggling`, `race_conditions`, `business_logic`, `ssti`, `cache_security`).
- `registry.get(key)` supports extensive aliases (e.g. `sqli` -> `sql_injection`, `xxe` -> `xml_parser_validation`, `cswsh` -> `websocket_security`, `deser` -> `deserialization`, etc.).
- Returns `Tool` object containing metadata, safety requirements, and capabilities.

#### `PluginExecutorAdapter` (`argus/runtime/plugins.py`)
- Implements `_instantiate_specialist_fallback(plugin_id)`:
  - Dynamically imports and instantiates collector classes without hardcoding collector dependencies in the caller.
  - Supports all vulnerability detection plugins.
  - Implements `execute_plugin(plugin_id, mission)` which wraps the mission in a `ControlledMission` and invokes `execute()` or `discover()`.

#### Collector Resolution Strategy for `ScanEngine`:
To satisfy R2 ("Each template's metadata.tool_id must map to the corresponding collector class via ToolRegistry.get() and the PluginExecutorAdapter fallback in argus/runtime/plugins.py"):
1. Query `ToolRegistry.get(tool_id)` to resolve alias / validate tool existence.
2. Resolve the collector instance via `PluginExecutorAdapter._instantiate_specialist_fallback(tool_id)` or mapping `tool_id` to the collector class in `argus.collectors`.
3. If tool is an external recon tool (like `subfinder`, `httpx`, `katana_crawler`, `nuclei`), instantiate its corresponding collector class (`SubfinderCollector`, `HttpxCollector`, `KatanaCollector`, `NucleiCollector` from `argus.collectors`).
4. Execute `collector.collect(mission)`.

---

### 2.4 Vulnerability Detection Collectors (16 Modules + Recon)

All collectors inherit from `BaseCollector` in `argus/collectors/base.py`:
```python
class BaseCollector(ABC):
    @abstractmethod
    def collect(self, mission):
        """Collect information and update the mission."""
        pass
```

#### Detailed Collector Inventory:

| Collector Class | File Path | Tool ID | Input Mission Attributes | Output Attributes / Evidence |
|---|---|---|---|---|
| `SubfinderCollector` | `argus/collectors/subfinder.py` | `subfinder` | `mission.target` | `mission.subdomains` |
| `HttpxCollector` | `argus/collectors/httpx.py` | `httpx` | `mission.subdomains` | `mission.live_hosts`, `mission.technologies` |
| `KatanaCollector` | `argus/collectors/katana.py` | `katana_crawler` | `mission.live_hosts` | `mission.endpoints` |
| `NucleiCollector` | `argus/collectors/nuclei.py` | `nuclei` | `mission.live_hosts` | `mission.notes` |
| `InformationDisclosureCollector` | `argus/collectors/information_disclosure.py` | `info_disclosure` | `mission.live_hosts`, `mission.endpoints` | `Evidence(category="information_disclosure")`, `mission.vulnerabilities`, `mission.subdomains`, graph nodes & edges |
| `AccessControlCollector` | `argus/collectors/access_control.py` | `access_control` | `mission.endpoints`, `mission.test_identities` | `Evidence(category="broken_access_control")`, `mission.vulnerabilities`, graph edges |
| `PathTraversalCollector` | `argus/collectors/path_traversal.py` | `path_traversal` | `mission.endpoints` | `Evidence(category="path_traversal")`, `mission.vulnerabilities`, graph edges |
| `SQLInjectionCollector` | `argus/collectors/sql_injection.py` | `sql_injection` | `mission.endpoints` | `Evidence(category="sql_injection")`, `mission.vulnerabilities`, graph edges |
| `XSSCollector` | `argus/collectors/xss.py` | `xss` | `mission.endpoints` | `Evidence(category="xss")`, `mission.vulnerabilities`, graph edges |
| `CommandInjectionCollector` | `argus/collectors/command_injection.py` | `command_injection` | `mission.endpoints` | `Evidence(category="command_injection")`, `mission.vulnerabilities`, graph edges |
| `SSRFCollector` | `argus/collectors/ssrf.py` | `ssrf` | `mission.endpoints` | `Evidence(category="ssrf")`, `mission.vulnerabilities`, graph edges |
| `OAuthCollector` | `argus/collectors/oauth.py` | `oauth` | `mission.endpoints` | `Evidence(category="oauth_oidc")`, `mission.vulnerabilities`, graph edges |
| `XMLParserSecurityCollector` | `argus/collectors/xml_parser.py` | `xml_parser_validation` | `mission.endpoints` | `Evidence(category="xml_parser_vulnerability")`, `mission.vulnerabilities`, graph edges |
| `DeserializationCollector` | `argus/collectors/deserialization.py` | `deserialization` | `mission.endpoints` | `Evidence(category="deserialization")`, `mission.vulnerabilities`, graph edges |
| `GraphQLSecurityCollector` | `argus/collectors/graphql.py` | `graphql_security` | `mission.endpoints` | `Evidence(category="graphql_vulnerability")`, `mission.vulnerabilities`, graph edges |
| `WebSocketSecurityCollector` | `argus/collectors/websocket.py` | `websocket_security` | `mission.endpoints` | `Evidence(category="websocket_vulnerability")`, `mission.vulnerabilities`, graph edges |
| `HTTPRequestSmugglingCollector` | `argus/collectors/request_smuggling.py` | `request_smuggling` | `mission.endpoints` | `Evidence(category="request_smuggling")`, `mission.vulnerabilities`, graph edges |
| `RaceConditionsCollector` | `argus/collectors/race_conditions.py` | `race_conditions` | `mission.endpoints` | `Evidence(category="race_conditions")`, `mission.vulnerabilities`, graph edges |
| `BusinessLogicCollector` | `argus/collectors/business_logic.py` | `business_logic` | `mission.endpoints` | `Evidence(category="business_logic")`, `mission.vulnerabilities`, graph edges |
| `SSTICollector` | `argus/collectors/ssti.py` | `ssti` | `mission.endpoints` | `Evidence(category="ssti")`, `mission.vulnerabilities`, graph edges |
| `CacheSecurityCollector` | `argus/collectors/cache_security.py` | `cache_security` | `mission.endpoints` | `Evidence(category="cache_security")`, `mission.vulnerabilities`, graph edges |

---

### 2.5 Evidence Aggregation & Graph Construction

1. **`EvidenceStore` (`argus/evidence/store.py`)**:
   - Initialized at `mission.evidence = EvidenceStore()`.
   - Methods: `add(evidence: Evidence)`, `all() -> list[Evidence]`, `count() -> int`, `filter(category)`.
   - When collectors return `List[Evidence]`, `ScanEngine` aggregates any evidence not already present into `mission.evidence`.

2. **`AttackSurfaceGraph` (`argus/graph/graph.py`)**:
   - Initialized at `mission.attack_surface_graph = KnowledgeGraph()`.
   - Collectors add nodes (`live_host`, `endpoint`, `vulnerability`, `subdomain`, `secret`) and connect them with directional edges (`HAS_ENDPOINT`, `HAS_VULNERABILITY`, `EXPOSES_SECRET`, `DISCLOSED_SUBDOMAIN`, `RESOLVES_TO`).
   - `ScanEngine` builds a graph snapshot summarizing `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges.

---

### 2.6 Report Generation Integration

- **`ReportGenerator` (`argus/reporting/generator.py`)**:
  - Method: `generate_and_save(mission: Mission, output_dir: Optional[str] = None) -> list[str]`
  - Processes `mission.evidence` (and `mission.vulnerabilities`).
  - Outputs HackerOne-style Markdown report (`.md`) and machine-readable JSON report (`.json`) in `.argus/reports/`.
  - Automatically appends report paths to `mission.reports`.
  - `ScanResult.report_paths` captures these file paths.

---

### 2.7 Mission Lifecycle & State Machine Transitions

`MissionState` (`argus/runtime/mission.py`):
```
CREATED -> READY -> RUNNING -> COLLECTING_EVIDENCE -> CORRELATING -> COMPLETED / FAILED
```
Timestamps and transition history must be recorded in `mission.state_transitions` with the schema:
```python
{
    "from": "<state_from>",
    "to": "<state_to>",
    "reason": "<reason_string>",
    "timestamp": "<iso8601_timestamp>"
}
```

---

## 3. Existing Simulated/Mock Orchestrators to Supersede

1. **`argus/orchestration/orchestrator.py` (`ResearchWorkflowOrchestrator`)**:
   - Generates mock step executions (`step.tool_execution.result = {"status": "success", "data": f"Output from {tool.name}"}`).
2. **`argus/execution/engine.py` (`ExecutionEngine`)**:
   - Sequential step execution designed for agent recommendations rather than dynamic DAG security assessment.
3. **`argus/runtime/executor.py` (`RemoteWorkerExecutor`)**:
   - Simulated sleep-based mock execution.

`ScanEngine` (`argus/scanning/engine.py`) provides the production-grade, end-to-end DAG orchestrator that directly drives real collectors and aggregates verified evidence.

---

## 4. Proposed Design for `ScanEngine` & `ScanResult`

### 4.1 `ScanResult` Dataclass Model
```python
@dataclass
class CollectorResult:
    name: str
    tool_id: str
    status: str  # "completed", "failed", "skipped"
    evidence_count: int = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None

@dataclass
class ScanResult:
    scan_id: str
    target: str
    start_time: str
    end_time: str
    status: str  # "COMPLETED", "FAILED"
    state_transitions: List[Dict[str, Any]]
    collector_results: Dict[str, CollectorResult]
    aggregate_statistics: Dict[str, Any]  # total_evidence, total_vulnerabilities, severity_breakdown, collectors_run, collectors_skipped, collectors_failed
    report_paths: List[str]
    graph_summary: Dict[str, Any]  # nodes, edges, vulnerabilities, endpoints
```

### 4.2 `ScanEngine` Core Logic
```python
class ScanEngine:
    def __init__(self, tool_registry: Optional[ToolRegistry] = None, output_dir: Optional[str] = None):
        self.registry = tool_registry or registry
        self.adapter = PluginExecutorAdapter()
        self.report_generator = ReportGenerator(output_dir=output_dir)

    def resolve_dag(self) -> List[Dict[str, Any]]:
        # Returns topologically sorted task templates from _RECON_TEMPLATES

    def run(self, mission: Mission) -> ScanResult:
        # 1. State transition CREATED -> READY -> RUNNING
        # 2. Topologically sort DAG
        # 3. State transition RUNNING -> COLLECTING_EVIDENCE
        # 4. For each task in DAG:
        #    - Check if dependencies succeeded; if not, mark skipped
        #    - Resolve collector via ToolRegistry and PluginExecutorAdapter / collectors package
        #    - Run collector.collect(mission) with duration tracking and try/except
        #    - Ingest returned Evidence into mission.evidence and update graph
        # 5. State transition COLLECTING_EVIDENCE -> CORRELATING
        # 6. Generate reports via ReportGenerator.generate_and_save(mission)
        # 7. State transition CORRELATING -> COMPLETED
        # 8. Return populated ScanResult
```

---

## 5. Risk Assessment & Verification Plan

1. **Circular Import Protection**:
   - Keep `ScanEngine` dependencies clean; use dynamic imports for collectors and adapters where appropriate.
2. **Backward Compatibility**:
   - Ensure `mission.status` and `mission.state_transitions` remain compatible with existing tests (1,678 existing tests).
3. **Graceful Error Isolation**:
   - When a collector raises an exception, the scan must not crash; the failed task must be recorded in `ScanResult`, and independent downstream tasks must continue.
4. **Targeted Testing Requirements (R5)**:
   - At least 25 new tests in `tests/scanning/test_scan_engine.py` and `tests/scanning/test_scan_engine_adversarial.py`.
   - Verify topological sort correctness, dependency skipping, mock failure resilience, state transitions, evidence accumulation, and report generation.
