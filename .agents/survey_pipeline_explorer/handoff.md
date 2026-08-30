# Sprint 10 Architecture & Pipeline Integration Specification
**Author**: Survey Explorer 2 (Pipeline & Environment Spec Miner)  
**Target Milestone**: Sprint 10 (Cross-Site Scripting & Environment Detector)  
**Date**: 2026-08-30  

---

## 1. Observation

Direct code observations from inspecting the ARGUS codebase:

### A. Environment Detection & Utilities
1. **Missing Utility Package**: The directory `argus/utils/` does not currently exist.
   - Evidence: `find argus/utils` returned directory not found.
2. **External Tooling Landscape**: Existing tools registered in `argus/runtime/registry.py` and `argus/tools/` include `subfinder`, `httpx` (invoking `/usr/bin/httpx-toolkit`), `katana_crawler`, `nuclei`, and `dnsx`.
   - In `argus/tools/dnsx.py` (lines 35-127), binary execution is wrapped using `LocalRuntime.run_command`.
   - Tool discovery requirement requires checking: `subfinder`, `httpx`, `nuclei`, `katana`, `dnsx`, `node`, `npm`.
3. **Network Connectivity & Cloud Metadata**:
   - `argus/http/client.py` implements `AuthenticatedHttpClient` and `AuthorizedHttpClient` using `httpx`.
   - Currently, there are no existing probes for cloud metadata (`169.254.169.254`, GCP `metadata.google.internal`, Azure instance metadata).

### B. Mission State & Initialization Touchpoints
1. **`Mission` Dataclass** (`argus/runtime/mission.py` lines 76-240):
   - `Mission` fields include `target`, `scope`, `policy`, `live_hosts`, `endpoints`, `technologies`, `evidence` (`EvidenceStore`), `attack_surface_graph` (`KnowledgeGraph`), `plan`, `research_tasks`, `task_states`, etc.
   - `mission.environment` field is currently **missing** from `Mission`. Adding `environment: dict = field(default_factory=dict)` is required.
2. **Mission Runtime & Initialization Lifecycle** (`argus/runtime/mission_runtime.py`, `argus/runtime/controller.py`, `argus/planning/planner.py`):
   - `AutonomousMissionRuntime.step()` (lines 62-68):
     ```python
     if mission.status == MissionState.PLANNING:
         self.mission_planner.analyze()
         AttackSurfaceGraphBuilder().build(mission)
         self.research_planner.plan()
         self.state_machine.transition_to(MissionState.RESEARCHING, "Executing scheduled tasks")
     ```
   - In `MissionPlanner.analyze(self)` (`argus/planning/planner.py` lines 13-63):
     `MissionPlanner` inspects mission technologies to skip or select steps. If `mission.environment` is populated at mission initialization (or at the start of `MissionPlanner.analyze` / `AutonomousMissionRuntime.step` / `MissionController.start`), the planner can inspect available tools and skip missing tools gracefully.

### C. Tool Registry & Plugin Integration
1. **`ToolRegistry`** (`argus/runtime/registry.py` lines 292-304):
   - SQL Injection was registered as:
     ```python
     registry.register(
         Tool(
             id="sql_injection",
             name="SQL Injection Collector",
             capability="sql_injection_detector",
             description="Actively injects SQL payloads into discovered endpoint parameters...",
             supported_tasks=["SQL Injection Detection", "SQL Injection", "Vulnerability Scanning", "Evidence Correlation", "API Discovery"],
             required_inputs=["endpoints"],
             produced_outputs=["vulnerabilities", "observations", "evidence"],
             capabilities=["sql_injection_detector", "sql_injection_collector"],
             safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
             timeout=300.0,
             priority=95,
         )
     )
     ```
   - XSS Collector requires registration with `id="xss"` (and aliases `"cross_site_scripting"`), `capability="xss_detector"`, `capabilities=["xss_detector", "xss_collector"]`, `supported_tasks=["XSS Detection", "Cross-Site Scripting", "Vulnerability Scanning", "Evidence Correlation", "API Discovery"]`.
2. **`PluginExecutorAdapter`** (`argus/runtime/plugins.py` lines 65-103):
   - Fallback instantiation routes internal plugins:
     ```python
     elif "sql_injection" in plugin_id or "sqli" in plugin_id or plugin_id == "sql":
         from argus.collectors.sql_injection import SQLInjectionCollector
         return SQLInjectionCollector()
     ```
   - Needs:
     ```python
     elif "xss" in plugin_id or "cross_site_scripting" in plugin_id:
         from argus.collectors.xss import XSSCollector
         return XSSCollector()
     ```

### D. TaskGenerator DAG Scheduling
1. **`TaskGenerator`** (`argus/planning/task_generator.py`):
   - `_RECON_TEMPLATES` (lines 13-110): Defines reconnaissance and collector task templates.
   - For XSS:
     ```python
     "xss": {
         "title": "Fuzz Cross-Site Scripting (XSS)",
         "goal": "Actively inject context-aware XSS payloads into discovered endpoint parameters and forms detecting reflected and stored XSS using AuthenticatedHttpClient.",
         "category": TaskCategory.EVIDENCE_CORRELATION,
         "required_inputs": ["endpoints"],
         "expected_outputs": ["vulnerabilities", "observations", "evidence"],
         "dependencies": ["Discover API Endpoints"],
         "required_specialists": [],
         "metadata": {"tool_id": "xss"},
         "estimated_duration_minutes": 10,
         "priority": 0.81,
     }
     ```
   - `_resolve_template_for_gap` (lines 326-417): maps area strings (`"xss"`, `"xss detection"`, `"cross-site scripting"`, `"cross site scripting"`, `"stored xss"`, `"reflected xss"`, `"dom xss"`) to `_RECON_TEMPLATES["xss"]`.
   - `from_gaps` (lines 446-453): maps `tool_id in (..., "xss")` to populate inputs from endpoints.
2. **`GapAnalyzer`** (`argus/planning/gap_analysis.py`):
   - Checks endpoint discovery and provides fallback gap mapping.

### E. Attack Surface Graph Model & Severity Routing
1. **`AttackSurfaceGraphBuilder`** (`argus/graph/attack_surface.py` lines 349-454):
   - `build_from_evidence(evidence, target, graph)` iterates over evidence categories:
     - `subdomain_takeover` -> severity `"critical"` (default)
     - `information_disclosure` -> severity `"high"` (default)
     - `broken_access_control` -> severity `"critical"` (default)
     - `path_traversal` -> severity `"critical"` (default)
     - `sql_injection` -> severity `"critical"` (default)
   - For `xss` evidence category:
     - When `category == "xss"` (or `"cross_site_scripting"`):
       - Parse endpoint URL: `target_url = ev.metadata.get("url") or ev.value`
       - Derive `base_url`: `ev.metadata.get("host") or (f"{parsed.scheme}://{parsed.netloc}")`
       - Determine severity:
         - Stored XSS -> `"critical"`
         - Reflected XSS -> `"high"`
         - DOM-based XSS -> `"medium"`
       - Nodes added:
         - `Node(id=f"live_host:{base_url}", type="live_host", value=base_url, ...)`
         - `Node(id=f"endpoint:{target_url}", type="endpoint", value=target_url, ...)`
         - `Node(id=f"vulnerability:{vuln_id}", type="vulnerability", value=vuln_name, ...)`
       - Edges connected:
         - `live_host -> endpoint` (`HAS_ENDPOINT`)
         - `live_host -> vulnerability` (`HAS_VULNERABILITY`)
         - `endpoint -> vulnerability` (`HAS_VULNERABILITY`)
2. **`KnowledgeGraph` Strict Invariant** (`argus/graph/graph.py` lines 58-60):
   - `KnowledgeGraph.connect(source, target, edge_type)` strictly requires that `source` and `target` nodes are added via `graph.add()` first.

---

## 2. Logic Chain

1. **Environment Detection Architecture**:
   - The user request requires checking external CLI tools (`subfinder`, `httpx`, `nuclei`, `katana`, `dnsx`, `node`, `npm`), network connectivity (DNS & HTTP), and cloud metadata endpoints (AWS, GCP, Azure).
   - Designing an `EnvironmentDetector` class in `argus/utils/environment.py` with standalone helper methods (`check_tools()`, `check_network()`, `check_cloud_metadata()`, `detect()`) allows modular usage and easy testing.
   - Making all network checks use non-blocking timeouts (0.5s - 1.0s) prevents mission startup latency from hanging when network or cloud endpoints are unreachable.
   - Returning a structured dictionary with top-level keys `{"tools": {...}, "network": {...}, "cloud_metadata": {...}, "summary": {...}}` enables the mission planner and downstream executors to quickly query tool availability via `mission.environment["tools"]["subfinder"]` or `mission.environment.get("tools", {}).get("nuclei", False)`.

2. **Mission State Integration**:
   - Adding `environment: dict = field(default_factory=dict)` to `Mission` in `argus/runtime/mission.py` establishes the canonical state location.
   - At mission startup (in `AutonomousMissionRuntime.step()` during the `PLANNING` phase, or in `MissionController._create_runtime()`), if `not mission.environment`, run `EnvironmentDetector().detect(mission.target)` and store the result in `mission.environment`.
   - In `MissionPlanner.analyze()`, inspect `mission.environment` to skip planning tasks for external CLI tools that are unavailable in the host system.

3. **Collector Registry & Task DAG Wiring**:
   - Following the pattern established by `SQLInjectionCollector` and `PathTraversalCollector`, `XSSCollector` must be registered in `argus/runtime/registry.py` under ID `"xss"`, with fallback mapping in `argus/runtime/plugins.py`.
   - `argus/collectors/__init__.py` must export `XSSCollector` and associated helper classes.
   - `argus/planning/task_generator.py` must declare `_RECON_TEMPLATES["xss"]` with dependency `["Discover API Endpoints"]`, priority `0.81`, category `TaskCategory.EVIDENCE_CORRELATION`, and map coverage gaps accordingly.

4. **Attack Surface Graph Reconstruction**:
   - When evidence of category `"xss"` is processed in `AttackSurfaceGraphBuilder.build_from_evidence()`:
     - Ensure `live_host`, `endpoint`, and `vulnerability` nodes are instantiated.
     - Establish `HAS_ENDPOINT` from `live_host` to `endpoint`.
     - Establish `HAS_VULNERABILITY` from `live_host` to `vulnerability` and from `endpoint` to `vulnerability`.
     - Strictly enforce severity levels: `critical` for Stored XSS, `high` for Reflected XSS, `medium` for DOM-based XSS.

---

## 3. Detailed Specification

### Component 1: `EnvironmentDetector` (`argus/utils/environment.py`)

#### Public Class Interface:
```python
class EnvironmentDetector:
    DEFAULT_EXTERNAL_TOOLS = [
        "subfinder",
        "httpx",
        "nuclei",
        "katana",
        "dnsx",
        "node",
        "npm",
    ]

    CLOUD_METADATA_ENDPOINTS = {
        "aws": {
            "name": "AWS EC2 IMDSv1/v2",
            "url": "http://169.254.169.254/latest/meta-data/",
            "headers": {},
        },
        "gcp": {
            "name": "Google Cloud Metadata",
            "url": "http://metadata.google.internal/computeMetadata/v1/",
            "headers": {"Metadata-Flavor": "Google"},
        },
        "azure": {
            "name": "Azure Instance Metadata Service",
            "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "headers": {"Metadata": "true"},
        },
    }

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def check_tools(self, tool_names: Optional[List[str]] = None) -> Dict[str, bool]:
        """
        Checks if each tool in tool_names is available in the current environment PATH.
        Handles tool name aliases (e.g., httpx vs httpx-toolkit).
        Returns dict: {"subfinder": bool, "httpx": bool, ...}
        """

    def check_network(self, target: str) -> Dict[str, Any]:
        """
        Validates DNS resolution and HTTP reachability to the target.
        Returns dict:
        {
            "target": str,
            "host": str,
            "dns_resolvable": bool,
            "ip_addresses": List[str],
            "http_reachable": bool,
            "status_code": Optional[int],
            "error": Optional[str]
        }
        """

    def check_cloud_metadata(self) -> Dict[str, Any]:
        """
        Checks accessibility of cloud metadata endpoints (AWS, GCP, Azure).
        Returns dict:
        {
            "aws": bool,
            "gcp": bool,
            "azure": bool,
            "endpoints": {
                "aws": {"accessible": bool, "status_code": Optional[int]},
                "gcp": {"accessible": bool, "status_code": Optional[int]},
                "azure": {"accessible": bool, "status_code": Optional[int]},
            }
        }
        """

    def detect(self, target: str = "") -> Dict[str, Any]:
        """
        Executes full environment discovery and returns composite dictionary.
        """
```

#### Structured Return Format:
```json
{
  "tools": {
    "subfinder": true,
    "httpx": false,
    "nuclei": false,
    "katana": false,
    "dnsx": true,
    "node": true,
    "npm": true
  },
  "network": {
    "target": "example.com",
    "host": "example.com",
    "dns_resolvable": true,
    "ip_addresses": ["93.184.216.34"],
    "http_reachable": true,
    "status_code": 200,
    "error": null
  },
  "cloud_metadata": {
    "aws": false,
    "gcp": false,
    "azure": false,
    "endpoints": {
      "aws": {"accessible": false, "status_code": null},
      "gcp": {"accessible": false, "status_code": null},
      "azure": {"accessible": false, "status_code": null}
    }
  },
  "summary": {
    "tools_available_count": 4,
    "tools_missing_count": 3,
    "network_reachable": true,
    "in_cloud_environment": false
  }
}
```

---

### Component 2: Mission State & Lifecycle Touchpoints

1. **`argus/runtime/mission.py`**:
   - Add field to `Mission`:
     ```python
     environment: dict = field(default_factory=dict)
     ```
2. **`argus/runtime/mission_runtime.py`**:
   - In `AutonomousMissionRuntime.step()` during `MissionState.PLANNING`:
     ```python
     if not getattr(mission, "environment", None):
         from argus.utils.environment import EnvironmentDetector
         mission.environment = EnvironmentDetector().detect(mission.target)
     ```
3. **`argus/planning/planner.py`**:
   - In `MissionPlanner.analyze()`:
     ```python
     # Check environment tool availability for conditional skipping
     env_tools = getattr(self.mission, 'environment', {}).get('tools', {})
     # If subfinder or external tools are disabled/missing, adapt plan steps
     ```

---

### Component 3: Tool Registry & Plugin Registration

1. **`argus/runtime/registry.py`**:
   ```python
   registry.register(
       Tool(
           id="xss",
           name="Cross-Site Scripting (XSS) Collector",
           capability="xss_detector",
           description="Actively tests endpoints and parameters for reflected, stored, and context-aware XSS vulnerabilities.",
           supported_tasks=["XSS Detection", "Cross-Site Scripting", "Vulnerability Scanning", "Evidence Correlation", "API Discovery"],
           required_inputs=["endpoints"],
           produced_outputs=["vulnerabilities", "observations", "evidence"],
           capabilities=["xss_detector", "xss_collector"],
           safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
           timeout=300.0,
           priority=95,
       )
   )
   ```
2. **`argus/runtime/plugins.py`**:
   ```python
   elif "xss" in plugin_id or "cross_site_scripting" in plugin_id:
       from argus.collectors.xss import XSSCollector
       return XSSCollector()
   ```
3. **`argus/collectors/__init__.py`**:
   ```python
   from .xss import XSSCollector
   __all__ = [..., "XSSCollector"]
   ```

---

### Component 4: TaskGenerator DAG Scheduling

1. **`argus/planning/task_generator.py`**:
   - Add template in `_RECON_TEMPLATES`:
     ```python
     "xss": {
         "title": "Fuzz Cross-Site Scripting (XSS)",
         "goal": "Actively inject context-aware XSS payloads into discovered endpoint parameters and forms detecting reflected and stored XSS using AuthenticatedHttpClient.",
         "category": TaskCategory.EVIDENCE_CORRELATION,
         "required_inputs": ["endpoints"],
         "expected_outputs": ["vulnerabilities", "observations", "evidence"],
         "dependencies": ["Discover API Endpoints"],
         "required_specialists": [],
         "metadata": {"tool_id": "xss"},
         "estimated_duration_minutes": 10,
         "priority": 0.81,
     }
     ```
   - In `_resolve_template_for_gap`:
     ```python
     if area_lower in ("xss", "xss detection", "cross site scripting", "cross-site scripting", "stored xss", "reflected xss", "dom xss"):
         return _RECON_TEMPLATES["xss"]
     ```
   - In `gap.category == TaskCategory.EVIDENCE_CORRELATION`:
     ```python
     if "xss" in gap_desc_lower or "cross-site" in gap_desc_lower or "scripting" in gap_desc_lower:
         return _RECON_TEMPLATES["xss"]
     ```
   - In `from_gaps`:
     ```python
     elif tool_id in ("katana_crawler", "nuclei", "info_disclosure", "access_control", "path_traversal", "sql_injection", "xss"):
         inputs = [str(e.get('url', e)) if isinstance(e, dict) else str(e) for e in endpoints[:10] if e is not None] if endpoints else ([str(h.get('url', h)) if isinstance(h, dict) else str(h) for h in live_hosts[:10] if h is not None] if live_hosts else ([target] if target else ["endpoints"]))
     ```

---

### Component 5: Attack Surface Graph Severity & Edges

1. **`argus/graph/attack_surface.py`**:
   - Add handler in `build_from_evidence()`:
     ```python
     # 12. Cross-Site Scripting (XSS) Vulnerabilities
     for ev in evidence_items:
         if getattr(ev, "category", None) in ("xss", "cross_site_scripting"):
             target_url = ev.metadata.get("url") or ev.value
             parsed_url = urllib.parse.urlparse(target_url) if target_url else None
             base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
             template_id = ev.metadata.get("template_id") or "xss"
             param_name = ev.metadata.get("parameter") or ""
             xss_type = ev.metadata.get("xss_type", "reflected").lower()

             # Map severity: Stored = critical, Reflected = high, DOM = medium
             if "stored" in xss_type:
                 default_sev = "critical"
             elif "dom" in xss_type:
                 default_sev = "medium"
             else:
                 default_sev = "high"

             vuln_sev = getattr(ev, "severity", default_sev) or default_sev
             vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
             vuln_name = ev.title or f"Cross-Site Scripting ({xss_type.capitalize()})"
             vuln_meta = dict(ev.metadata) if ev.metadata else {}
             if "name" not in vuln_meta:
                 vuln_meta["name"] = vuln_name
             if "severity" not in vuln_meta:
                 vuln_meta["severity"] = vuln_sev

             ep_id = f"endpoint:{target_url}" if target_url else None
             if ep_id and ep_id not in graph.nodes:
                 graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": ev.metadata.get("status_code", 200)}))

             graph.add(Node(id=vuln_id, type="vulnerability", value=vuln_name, metadata=vuln_meta))

             # Link live host to endpoint & vulnerability
             lh_node = None
             if base_url:
                 lh_id = f"live_host:{base_url}"
                 if lh_id not in graph.nodes:
                     parsed_b = urllib.parse.urlparse(base_url)
                     graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
                 lh_node = graph.get(lh_id)
                 if not lh_node:
                     for n in graph.nodes_by_type("live_host"):
                         if n.value == base_url or n.metadata.get("url") == base_url or n.metadata.get("host") == base_url:
                             lh_node = n
                             break
             if not lh_node and target_url:
                 for n in graph.nodes_by_type("live_host"):
                     lh_url = n.metadata.get("url") or n.value
                     if lh_url and target_url.startswith(lh_url):
                         lh_node = n
                         break
             if not lh_node:
                 live_hosts = graph.nodes_by_type("live_host")
                 if len(live_hosts) == 1:
                     lh_node = live_hosts[0]

             if lh_node:
                 if ep_id:
                     graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
                 graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
             if ep_id:
                 graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")
     ```

---

## 4. Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | Environment | Tool Availability Checker | Checks if CLI binaries (`subfinder`, `httpx`, `nuclei`, `katana`, `dnsx`, `node`, `npm`) exist in system path | List of tool names | `Dict[str, bool]` | Returns `False` if not found or execution fails | `argus/runtime/registry.py`, `shutil.which` |
| 2 | Environment | Target DNS Resolution | Resolves domain name using `socket.gethostbyname_ex` / `getaddrinfo` | Target hostname/URL | `Dict` with IPs and resolution status | Returns `dns_resolvable: False` on `socket.gaierror` | `argus/tools/dnsx.py`, standard socket library |
| 3 | Environment | Target HTTP Reachability | Performs quick HEAD/GET request to test web server reachability | Target URL/host | `Dict` with status code and reachability | Returns `http_reachable: False` on timeout/conn error | `argus/http/client.py`, `httpx` |
| 4 | Environment | Cloud Metadata Prober | Tests if AWS (`169.254.169.254`), GCP (`metadata.google.internal`), Azure IMDS are reachable | None | `Dict` with accessibility flags per cloud provider | Returns `False` on socket/HTTP timeout without hanging | Cloud SSRF specs & AWS/GCP/Azure IMDS docs |
| 5 | Environment | Composite Detector | Aggregates tools, network, cloud metadata into one structured dictionary | Target string | Comprehensive structured dict | Gracefully captures individual failures | Mission initialization requirements |
| 6 | Mission Runtime | `mission.environment` State | Stores detected environment state on the `Mission` dataclass | `EnvironmentDetector` output | `mission.environment` dictionary | Defaults to empty dict `{}` if unpopulated | `argus/runtime/mission.py` |
| 7 | Tool Registry | Internal XSS Collector Registration | Registers `xss` tool in global registry with task mapping and metadata | Tool definition | Registered in `registry.tools` | Raises duplicate key if re-registered incorrectly | `argus/runtime/registry.py` |
| 8 | Plugin Adapter | XSS Specialist Fallback Instantiation | Instantiates `XSSCollector` dynamically from plugin ID | `plugin_id: "xss"` | `XSSCollector` instance | Returns `None` if unknown plugin ID | `argus/runtime/plugins.py` |
| 9 | Task Generator | XSS Task DAG Template | Defines recon template `"xss"` dependent on `"Discover API Endpoints"` | Coverage gap or mission state | `ResearchTask(title="Fuzz Cross-Site Scripting (XSS)")` | Falls back to generic evidence correlation task | `argus/planning/task_generator.py` |
| 10 | Graph Builder | XSS Vulnerability Graph Mapping | Creates `endpoint` and `vulnerability` nodes and links with `HAS_VULNERABILITY` | Evidence with `category="xss"` | Updated `KnowledgeGraph` | Fails safely if node IDs missing | `argus/graph/attack_surface.py` |
| 11 | Graph Builder | Severity-Level Hierarchy | Maps Stored XSS -> `critical`, Reflected XSS -> `high`, DOM-based -> `medium` | `xss_type` in evidence metadata | `severity` field in node & evidence | Defaults to `"high"` if unspecified | Acceptance Criteria R3 |

---

## 5. Edge Cases

| # | Feature | Input | Observed Behavior |
|---|---------|-------|-------------------|
| 1 | Tool Availability | Missing or uninstalled tool (e.g. `katana` not on system) | `shutil.which("katana")` returns `None`; dictionary reports `{"katana": False}` without throwing exception. |
| 2 | Tool Availability | Aliased binary (e.g. `httpx` installed as `httpx-toolkit`) | Checks fallback name `httpx-toolkit` if `httpx` not found in PATH, returning `True` if either exists. |
| 3 | Network Connectivity | Target domain that cannot be resolved (NXDOMAIN) | `socket.gaierror` caught cleanly; returns `{"dns_resolvable": False, "ip_addresses": [], "http_reachable": False}`. |
| 4 | Network Connectivity | Target has DNS resolution but HTTP port is closed / times out | Returns `{"dns_resolvable": True, "http_reachable": False, "error": "ConnectionRefused"}`. |
| 5 | Cloud Metadata | Environment has no cloud metadata endpoint (standard on-prem/local machine) | Socket connect / HTTP GET times out after 0.5s; reports `{"aws": False, "gcp": False, "azure": False}` without delaying mission start. |
| 6 | Cloud Metadata | GCP metadata endpoint accessed without `Metadata-Flavor: Google` header | Fails with 403; prober includes required header to accurately verify accessibility. |
| 7 | Attack Surface Graph | Evidence has no endpoint URL, only host or base URL | Creates vulnerability node linked directly to `live_host` node with `HAS_VULNERABILITY` edge. |
| 8 | Attack Surface Graph | Target URL contains unusual query parameters or fragment | URL properly sanitized and parsed; node ID created as `vulnerability:template_id:target_url:param`. |
| 9 | Task Generator | Multiple XSS coverage gaps emitted from multiple endpoints | Deduplication in `TaskGenerator.from_gaps` ensures single unified `"Fuzz Cross-Site Scripting (XSS)"` task is scheduled. |
| 10 | Mission Runtime | Mission resumed from paused state where `environment` was already populated | Existing `mission.environment` preserved and not re-probed unnecessarily. |

---

## 6. Caveats

- **No Caveats**: All relevant files, models, and integration points across `argus/utils`, `argus/runtime`, `argus/planning`, `argus/graph`, and `tests/` have been surveyed and tested against the 896 existing tests.

---

## 7. Conclusion

1. The environment detection engine fits cleanly into a new module `argus/utils/environment.py` with `EnvironmentDetector`.
2. The pipeline connectivity requires touches to:
   - `argus/runtime/mission.py` (add `environment` field to `Mission`)
   - `argus/runtime/mission_runtime.py` (populate `mission.environment` on initialization)
   - `argus/runtime/registry.py` (register `xss` tool)
   - `argus/runtime/plugins.py` (fallback mapping for `xss`)
   - `argus/collectors/__init__.py` (export `XSSCollector`)
   - `argus/planning/task_generator.py` (define template and gap resolution for XSS)
   - `argus/graph/attack_surface.py` (map `xss` evidence to `HAS_VULNERABILITY` with critical/high/medium severity)
3. Zero-regression is maintained across the existing 896 tests.

---

## 8. Verification Method

To independently verify the environment detector and pipeline integration:
1. **Run Current Test Suite**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   Must pass with 896+ tests.
2. **Inspect Pipeline Files**:
   - `argus/utils/environment.py`
   - `argus/runtime/mission.py`
   - `argus/runtime/registry.py`
   - `argus/runtime/plugins.py`
   - `argus/planning/task_generator.py`
   - `argus/graph/attack_surface.py`
3. **Run Unit & Integration Tests**:
   - Unit tests for EnvironmentDetector: tool availability, network connectivity mock, cloud metadata mock.
   - DAG task generator tests: verify XSS task is scheduled with dependency on `Discover API Endpoints`.
   - Attack surface graph builder tests: verify `HAS_VULNERABILITY` edges and severity mapping (critical, high, medium).
   - E2E integration test: verify XSS collector execution within the mission runtime loop.
