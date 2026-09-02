# Exploration Report: DAG Scheduling, Tool Registry, Context Flow & Collector Configuration

**Target Location**: `/home/varun/argus/.agents/explorer_2/handoff.md`  
**Explorer**: `explorer_2`  
**Date**: 2026-09-01T22:31:30+05:30  
**Target Module**: CORS Misconfiguration & HTTP Security Header Audit Module (`Sprint 25`)

---

## 1. Observation

### 1.1 TaskGenerator & DAG Scheduling Architecture
- **Task Templates**: `argus/planning/task_generator.py` defines `_RECON_TEMPLATES` (lines 13–266) containing task definitions for recon tools and active vulnerability scanners.
  - Reconnaissance tools: `subfinder` (priority 0.95), `httpx` (priority 0.90, depends on `Discover Subdomains`), `katana_crawler` (priority 0.85, depends on `Fingerprint Live Hosts`), `nuclei` (priority 0.80, depends on `Fingerprint Live Hosts`), `info_disclosure` (priority 0.82, depends on `Fingerprint Live Hosts`).
  - Active vulnerability tools: `access_control`, `path_traversal`, `sql_injection`, `xss`, `command_injection`, `ssrf`, `oauth`, `xml_parser_validation`, `deserialization`, `graphql_security`, `websocket_security`, `request_smuggling`, `race_conditions`, `business_logic`, `ssti`, `cache_security` (all have priority 0.81–0.82, depend on `["Discover API Endpoints"]`, take `required_inputs=["endpoints"]`, and produce `["vulnerabilities", "observations", "evidence"]`).
- **Gap Resolution**: `TaskGenerator._resolve_template_for_gap` (lines 484–763) matches `CoverageGap.area` and `CoverageGap.description` strings to corresponding templates in `_RECON_TEMPLATES`.
- **Input Resolution**: `TaskGenerator.from_gaps` (lines 787–800) checks `tool_id in (...)` and automatically extracts input strings from `mission.endpoints` (first 10 items), falling back to `mission.live_hosts` and `mission.target`.
- **ScanDAG Topological Scheduling**: `argus/scanning/dag.py` (lines 54–86) dynamically imports `_RECON_TEMPLATES` from `argus.planning.task_generator`, instantiates `ScanTask` instances, classifies phases (`phase="recon"` for recon tools, `phase="vulnerability"` for others), and uses Kahn's algorithm in `ScanDAG.get_execution_order()` (lines 120–191) to compute deterministic topological ordering with priority descending.
- **Scan Engine Invocation**: `argus/scanning/engine.py` (lines 53–136, 198–350) runs tasks in topological order, dynamically resolving collector instances via `collector_factory`, `PluginExecutorAdapter._instantiate_specialist_fallback`, `collector_class_map` (lines 76–106), and `ToolRegistry`.

### 1.2 Tool Registry & Plugin Infrastructure
- **ToolRegistry Definition**: `argus/runtime/registry.py` (lines 5–201) defines `ToolRegistry` and instantiates the global singleton `registry` (line 204).
- **Tool Model**: `argus/runtime/models.py` (lines 141–166) defines `Tool` with fields:
  - `id: str`: unique identifier (e.g. `"cors_headers"` or `"cors_security"`)
  - `name: str`: display title
  - `version: str`: semver string (e.g. `"1.0.0"`)
  - `capability: str`: primary capability tag
  - `description: str`: full functional summary
  - `supported_tasks: List[str]`: task category / task name strings for capability matching
  - `required_inputs: List[str]`: input types expected (e.g. `["endpoints"]`)
  - `produced_outputs: List[str]`: output types produced (e.g. `["vulnerabilities", "observations", "evidence"]`)
  - `capabilities: List[str]`: array of capability tags / aliases
  - `safety_requirements: Dict[str, Any]`: e.g. `{"type": "internal", "permissions": ["network", "db_read", "db_write"]}`
  - `timeout: float`: tool execution timeout (default 300.0s)
  - `priority: int`: registry match priority (default 95 for vulnerability collectors, 100 for recon)
- **Alias Lookup**: `ToolRegistry.get(key)` (lines 15–187) contains a comprehensive alias dictionary mapping ~170 tool nicknames, synonyms, and variants to their canonical tool IDs.
- **Plugin Dynamic Loading**: `argus/runtime/plugins.py` (`PluginExecutorAdapter`, lines 10–213) handles plugin execution and provides `_instantiate_specialist_fallback(plugin_id)` (lines 65–211), dynamically importing and instantiating collector classes from `argus.collectors`.
- **Dispatcher & Orchestrator**: `argus/runtime/dispatcher.py` (lines 10–92) and `argus/runtime/orchestrator.py` (lines 22–130) resolve `ResearchTask` to `Tool`, perform safety checks via `SafetyValidator`, wrap context into `ToolExecutionContext`, and dispatch via `InternalPluginExecutor` (`argus/runtime/executor.py`, lines 155–190).

### 1.3 Context Passing & Data Flow
- **Collector Invocation Interface**: Collectors inherit from `BaseCollector` (`argus/collectors/base.py`) and implement:
  - `collect(self, mission: Any) -> List[Evidence]`
  - `execute(self, mission: Any) -> List[Evidence]` (alias for `collect`)
- **Target Discovery**: Established pattern (observed in `argus/collectors/cache_security.py:1334-1382`, `argus/collectors/ssti.py:1550-1598`, `argus/collectors/business_logic.py:1440-1490`):
  1. Unwraps raw mission: `raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))`
  2. Ingests `raw_mission.endpoints` (extracting `ep.get("url")` or `ep.get("path")` or `str(ep)`)
  3. Ingests `raw_mission.live_hosts` (extracting `lh.get("url")` or `str(lh)`)
  4. Ingests `raw_mission.target` (ensures `https://` prefix if missing)
  5. Ingests URLs from `raw_mission.evidence` metadata
- **HTTP Dispatch & Probing**: Collectors use `AuthenticatedHttpClient` (`argus/http/client.py:300-508`), which enforces `ScopeResolver` boundary checks and `authorization_gate` checks, injects session headers/cookies from `TestIdentity`, executes retry backoff, sanitizes sensitive data, and creates request/response evidence. Prober classes (e.g. `CORSProber` / `HeaderAuditor`) accept optional `AuthenticatedHttpClient` or `http_client` instances for unit-test mockability.
- **Quadruple State Mutation on Confirmed Findings**:
  1. `mission.evidence.add(ev)`: Creates `Evidence` with `category="cors"` or `"security_headers"`, `status="CONFIRMED"`, `confidence`, `severity`, provenance data, tags, and detailed metadata (`url`, `host`, `technique`, `cwe_id`, `cvss_score`, etc.).
  2. `mission.vulnerabilities.append({...})`: Appends structured vulnerability record to `mission.vulnerabilities`.
  3. `mission.attack_surface_graph`: Adds nodes (`live_host`, `endpoint`, `vulnerability`) and connects them via `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges (handled in collector and synchronized by `AttackSurfaceGraphBuilder` in `argus/graph/attack_surface.py:1208-1260`).
  4. `ControlledMission.publish_finding(...)`: Notifies mission wrapper if present.

### 1.4 Configuration, Settings, CVSS/CWE Mappings & CLI Flags
- **CLI Commands**: `argus/cli/tools_cli.py` exposes:
  - `argus tools list`: lists all registered tools, supported tasks, capabilities, and safety types.
  - `argus tools run <tool_id> <task_id> --mission-id <id>`: runs a tool on a task.
  - `argus tools status <run_id>` and `argus tools history`: inspects execution telemetry in `.argus/tool_history.json`.
- **Collector Construction Parameters**:
  - `prober: Optional[CORSProber] = None`
  - `timeout: float = 10.0` (per-HTTP-request timeout)
  - `http_client: Optional[AuthenticatedHttpClient] = None`
- **CVSS & CWE Mappings (`argus/reporting/cvss.py`)**:
  - `CWE_DATABASE` currently maps `"cors"` to `CWEInfo("CWE-942", "Permissive Cross-origin Resource Sharing Policy")` (line 114).
  - Missing in `CWE_DATABASE`: `CWE-693` ("Protection Mechanism Failure") and `CWE-1021` ("Improper Restriction of Rendered UI Layers or Frames ('Clickjacking')") for security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
  - Preset CVSS vector mapping (`_get_preset_vector`, lines 372–444) has calibrated severity bands: Critical (9.0–10.0), High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9). Severity mapping needs to include `"cors"` in High/Critical bands (reflected with credentials = High 8.2, wildcard with credentials = Critical 9.8) and security headers in Medium/Low bands (missing CSP = Medium 5.3, missing X-Content-Type-Options / Referrer-Policy = Low 2.7).

---

## 2. Logic Chain

1. **Scheduling Chain**:
   - `_RECON_TEMPLATES` in `argus/planning/task_generator.py` is the single source of truth for task templates.
   - `ScanDAG` in `argus/scanning/dag.py` automatically reads `_RECON_TEMPLATES`. Adding `"cors_headers"` (or `"cors_security"`) to `_RECON_TEMPLATES` with `dependencies: ["Discover API Endpoints"]` guarantees it will execute immediately after Katana crawling in both `ScanDAG` and `ResearchPlanner`.
   - `TaskGenerator._resolve_template_for_gap` must map `"cors"`, `"cors security"`, `"cors misconfiguration"`, `"security headers"`, `"http security headers"`, `"csp"`, `"hsts"` to the new template.
   - `TaskGenerator.from_gaps` must include `"cors_headers"` in the `tool_id in (...)` tuple on line 792 to automatically supply endpoint inputs from `mission.endpoints`.

2. **Registration Chain**:
   - `argus/runtime/registry.py` must register `Tool(id="cors_headers", ...)` with `supported_tasks`, `capabilities`, `safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]}`.
   - Aliases such as `"cors"`, `"cors_security"`, `"cors_collector"`, `"cors_detector"`, `"security_headers"`, `"http_headers"`, `"header_audit"` must map to `"cors_headers"`.
   - `argus/runtime/plugins.py` (`_instantiate_specialist_fallback`) must add conditional matching for `"cors"` and `"security_header"` returning `CORSSecurityCollector()`.
   - `argus/scanning/engine.py` must add `"cors_headers": "CORSSecurityCollector"` (and aliases) to `collector_class_map`.

3. **Context & Execution Chain**:
   - `CORSSecurityCollector` inheriting `BaseCollector` must expose both `collect(mission)` and `execute(mission)`.
   - Candidate endpoints must be harvested from `mission.endpoints`, `mission.live_hosts`, `mission.target`, and `mission.evidence`.
   - Probing must utilize `AuthenticatedHttpClient` with custom `Origin`, `Access-Control-Request-Method`, and `Access-Control-Request-Headers` headers and `OPTIONS`/`GET` methods.
   - Confirmed findings must perform Quadruple State Mutation: updating `mission.evidence`, `mission.vulnerabilities`, `mission.attack_surface_graph` (creating `live_host`, `endpoint`, `vulnerability` nodes and connecting `HAS_ENDPOINT` + `HAS_VULNERABILITY` edges), and invoking `ControlledMission.publish_finding`.

4. **Reporting & CVSS Chain**:
   - `argus/reporting/cvss.py` must update `CWE_DATABASE` with `CWE-693` (for general security headers / CSP / HSTS / nosniff) and `CWE-1021` (for X-Frame-Options / frame-ancestors / clickjacking).
   - `_get_preset_vector` must support CORS and Security Header categories across Critical, High, Medium, and Low severity bands.

---

## 3. Caveats

- **No Caveats on Architecture**: The architecture across `TaskGenerator`, `ScanDAG`, `ToolRegistry`, `PluginExecutorAdapter`, `AuthenticatedHttpClient`, `AttackSurfaceGraphBuilder`, and `CVSSCalculator` is uniform and consistent across all 20+ existing collectors in the repository.
- **Benchmark Integrity Mode**: Implementation must avoid introducing any external third-party scanning libraries (must use standard Python library + existing project modules like `httpx`, `urllib.parse`, `json`, `uuid`, etc.).
- **Read-Only Scope**: This report is purely an exploratory investigation and makes 0 modifications to production files.

---

## 4. Conclusion & Recommended Implementation Plan

To build Sprint 25's CORS Misconfiguration & HTTP Security Header Audit Module with full pipeline connectivity, the implementation should touch the following 9 integration points:

| Integration Point | Target File | Key Additions Required |
|---|---|---|
| **1. Collector Module** | `argus/collectors/cors_headers.py` (new) | `CORSSecurityCollector(BaseCollector)`, `CORSProber`, `CORSAnalyzer`, `HeaderAuditor`, `CORSMutationStrategy`, `CORSVulnerabilityType` |
| **2. Collectors Init** | `argus/collectors/__init__.py` | Import & export `CORSSecurityCollector`, `CORSProber`, `HeaderAuditor`, etc. |
| **3. Tool Registry** | `argus/runtime/registry.py` | Register `Tool(id="cors_headers", ...)` with full metadata, priority 95, and aliases |
| **4. Plugin Adapter** | `argus/runtime/plugins.py` | Add `"cors"` / `"security_header"` fallback branch in `_instantiate_specialist_fallback` |
| **5. Task Generator** | `argus/planning/task_generator.py` | Add `"cors_headers"` to `_RECON_TEMPLATES`, `_resolve_template_for_gap`, and `from_gaps` |
| **6. Gap Analysis** | `argus/planning/gap_analysis.py` | (Optional/recommended) Add gap detection for CORS and header coverage |
| **7. Scan Engine** | `argus/scanning/engine.py` | Add `"cors_headers"` and aliases to `collector_class_map` |
| **8. Graph Builder** | `argus/graph/attack_surface.py` | Ingest evidence categories `"cors"`, `"cors_misconfiguration"`, `"security_headers"`, `"missing_security_headers"` into graph nodes/edges |
| **9. CVSS & CWE** | `argus/reporting/cvss.py` | Add `CWE-693`, `CWE-1021`, and map severity calibrations in `_get_preset_vector` |

---

## 5. Verification Method

To independently verify the architecture and readiness:
1. **Inspect existing pipeline integration**:
   ```bash
   python3 -c "from argus.planning.task_generator import _RECON_TEMPLATES; from argus.scanning.dag import ScanDAG; dag = ScanDAG(); print([t.key for t in dag.get_execution_order()])"
   ```
2. **Inspect tool registry**:
   ```bash
   python3 -c "from argus.runtime.registry import registry; print(len(registry.list()), [t.id for t in registry.list()])"
   ```
3. **Verify full test suite baseline**:
   ```bash
   python3 -m pytest tests/ --ignore=tests/workspace -x -q
   ```
