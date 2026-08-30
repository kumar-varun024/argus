# Explorer 2 Survey Report: Pipeline Connectivity, TaskGenerator DAG, Tool Registry, and Graph Schema

## 1. Observation

### 1.1 TaskGenerator & DAG Orchestration
- **File**: `argus/planning/task_generator.py`
  - **Class**: `TaskGenerator` (lines 245–527)
  - **Recon Templates Dictionary**: `_RECON_TEMPLATES` (lines 13–146)
    - Downstream vulnerability templates (`access_control`, `path_traversal`, `sql_injection`, `xss`, `command_injection`, `ssrf`) all declare:
      ```python
      "dependencies": ["Discover API Endpoints"],
      "required_inputs": ["endpoints"],
      "expected_outputs": ["vulnerabilities", "observations", "evidence"],
      "category": TaskCategory.EVIDENCE_CORRELATION, # (or AUTHORIZATION_ANALYSIS for access_control)
      "priority": 0.81,
      ```
    - Upstream reconnaissance chain:
      1. `subfinder` ("Discover Subdomains") -> `dependencies: []`
      2. `httpx` ("Fingerprint Live Hosts") -> `dependencies: ["Discover Subdomains"]`
      3. `katana_crawler` ("Discover API Endpoints") -> `dependencies: ["Fingerprint Live Hosts"]`
      4. `nuclei` ("Scan Live Hosts") -> `dependencies: ["Fingerprint Live Hosts"]`
      5. `info_disclosure` ("Probe Information Disclosure") -> `dependencies: ["Fingerprint Live Hosts"]`
  - **Gap Resolution**: `_resolve_template_for_gap(self, gap: CoverageGap) -> Dict[str, Any]` (lines 363–469)
    - Matches gap `area` string (case-insensitive) and keywords in `gap.description` / `gap.category` to select the template from `_RECON_TEMPLATES` or `_SPECIALIST_TEMPLATES`.
  - **Task Instantiation from Gaps**: `from_gaps(self, gaps: List[CoverageGap]) -> List[ResearchTask]` (lines 470–527)
    - Extracts inputs for endpoint-dependent tools:
      ```python
      elif tool_id in ("katana_crawler", "nuclei", "info_disclosure", "access_control", "path_traversal", "sql_injection", "xss", "command_injection", "ssrf"):
          inputs = [str(e.get('url', e)) if isinstance(e, dict) else str(e) for e in endpoints[:10] if e is not None] if endpoints else ([str(h.get('url', h)) if isinstance(h, dict) else str(h) for h in live_hosts[:10] if h is not None] if live_hosts else ([target] if target else ["endpoints"]))
      ```
    - Creates `ResearchTask` with `dependencies=list(template.get("dependencies", []))` and `metadata=dict(template.get("metadata", {}))`.

- **Associated Planning & Dependency Files**:
  - `argus/planning/models.py`: `ResearchTask`, `CoverageGap`, `CoverageReport`, `TaskCategory`, `PlanStep`, `PlanDependency`.
  - `argus/planning/dependencies.py`: `DependencyResolver` (lines 4–53) builds formal `PlanDependency` objects and performs `topological_sort()`.
  - `argus/planning/decision_engine.py`: `DecisionEngine` (lines 11–63) prioritizes tasks using composite scoring (`priority * 0.4 + (1 - coverage) * 0.3 - 0.1 * len(dependencies) + confidence * 0.1`) and filters against `mission.policy`.
  - `argus/planning/research_planner.py`: `ResearchPlanner` (lines 25–156) coordinates coverage tracker, gap analyzer, task generator, knowledge base enrichment, and decision engine.

### 1.2 Tool Registry & Plugin Dispatch
- **File**: `argus/runtime/registry.py`
  - **Class**: `ToolRegistry` (lines 5–54) & global singleton `registry = ToolRegistry()` (line 56).
  - **Data Model**: `Tool` in `argus/runtime/models.py` (fields: `id`, `name`, `capability`, `description`, `supported_tasks`, `required_inputs`, `produced_outputs`, `capabilities`, `safety_requirements`, `timeout`, `priority`).
  - **Lookup & Aliasing**: `ToolRegistry.get(key: str)` (lines 15–39) resolves tool ID, followed by `aliases` dictionary (lines 19–30), followed by fallback to `tool.capability` or `tool.capabilities`.
  - **Registered Collectors**:
    - `access_control` (lines 273–287, priority 95, safety internal)
    - `path_traversal` (lines 289–303, priority 95, safety internal)
    - `sql_injection` (lines 305–319, priority 95, safety internal)
    - `xss` (lines 321–335, priority 95, safety internal)
    - `command_injection` (lines 337–351, priority 95, safety internal)
    - `ssrf` (lines 353–367, priority 95, safety internal)
    - `info_disclosure` (lines 257–271, priority 95, safety internal)

- **Plugin Adapter & Runtime Execution**:
  - `argus/runtime/orchestrator.py`: `ToolOrchestrator.execute_task(mission, task)` (lines 39–130) routes task to `ToolDispatcher`.
  - `argus/runtime/dispatcher.py`: `ToolDispatcher.resolve_tool(task)` (lines 16–64) checks `task.metadata["tool_id"]`, `task.required_specialists`, or `find_compatible_tools(category)`. `ToolDispatcher.dispatch(tool, context)` (lines 65–92) routes `tool_type == ToolType.INTERNAL` to `InternalPluginExecutor`.
  - `argus/runtime/executor.py`: `InternalPluginExecutor.execute(tool, context)` (lines 155–190) creates `PluginExecutorAdapter()` and invokes `adapter.execute_plugin(tool.id, context.mission)`.
  - `argus/runtime/plugins.py`: `PluginExecutorAdapter` (lines 10–115):
    - `execute_plugin(plugin_id, mission)` loads plugin from `self.manager.registry.get_plugin(plugin_id)` or calls `_instantiate_specialist_fallback(plugin_id)`.
    - Wraps `mission` in `ControlledMission(mission)` and executes `plugin.execute(controlled_mission)` (or `plugin.discover()`).
    - `_instantiate_specialist_fallback(plugin_id)` (lines 65–114) maps string IDs (`"ssrf"`, `"sql_injection"`, `"xss"`, `"command_injection"`, `"path_traversal"`, `"access_control"`, `"info_disclosure"`, etc.) directly to instantiated collector classes.

### 1.3 Attack Surface Graph Implementation
- **Core Graph Engine**:
  - `argus/graph/node.py`: `Node` dataclass (`id: str`, `type: str`, `value: str`, `metadata: dict[str, Any]`).
  - `argus/graph/edge.py`: `Edge` dataclass (`source: str`, `target: str`, `type: str`, `metadata: dict[str, Any]`).
  - `argus/graph/graph.py`: `KnowledgeGraph` class:
    - In-memory indices: `self.nodes: dict[str, Node]`, `self.edges: list[Edge]`.
    - Core methods: `add(node)`, `get(node_id)`, `connect(source, target, edge_type, metadata)`, `nodes_by_type(node_type)`, `edges_from(node)`, `edges_to(node)`, `neighbors(node)`, `get_hosts_without_endpoints()`, `get_hosts_without_vulnerabilities()`.
- **Node Types**:
  - `target` (`id="target:{target}"`)
  - `subdomain` (`id="subdomain:{hostname}"`)
  - `live_host` (`id="live_host:{url}"`)
  - `endpoint` (`id="endpoint:{url}"`)
  - `technology` (`id="technology:{name}"`)
  - `vulnerability` (`id="vulnerability:{template_id}:{target_url}:{param}"` or `id="vulnerability:{template_id}"`)
  - `secret` (`id="secret:{type}:{idx}:{url}"`)
  - `cname` (`id="cname:{cname}"`)
- **Edge Types**:
  - `RESOLVES_TO`: `target -> subdomain`
  - `HOSTS`: `subdomain -> live_host` (or `target -> live_host`)
  - `RUNS_TECHNOLOGY`: `live_host -> technology`
  - `HAS_ENDPOINT`: `live_host -> endpoint`
  - `HAS_VULNERABILITY`:
    - `live_host -> vulnerability`
    - `endpoint -> vulnerability`
    - `subdomain -> vulnerability` (subdomain takeover)
  - `POINTS_TO_CNAME`: `subdomain -> cname`
  - `EXPOSES_SECRET`: `vulnerability -> secret`
  - `DISCLOSED_SUBDOMAIN`: `vulnerability -> subdomain`

### 1.4 Evidence Conversion into Graph Nodes & `HAS_VULNERABILITY` Edges
- **Direct Collector Runtime Expansion**:
  - In each collector's `_create_evidence_and_update_state(mission, target_url, base_url, param, ...)` (e.g. `argus/collectors/ssrf.py:1537–1661`, `argus/collectors/sql_injection.py:1061–1177`, `argus/collectors/xss.py:961–1071`):
    1. Creates `Evidence` model: `category=...`, `status="CONFIRMED"`, `severity=...`, `metadata={...}`.
    2. Stores in `mission.evidence.add(ev)` and `mission.vulnerabilities.append({...})`.
    3. Expands graph attached to `mission.attack_surface_graph` / `mission.graph`:
       ```python
       lh_id = f"live_host:{base_url}"
       ep_id = f"endpoint:{target_url}"
       vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

       graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
       graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
       graph.add(Node(id=vuln_id, type="vulnerability", value=f"Vulnerability Title", metadata=ev.metadata))

       graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
       graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
       graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")
       ```
- **Batch Reconstruction via `AttackSurfaceGraphBuilder`**:
  - `argus/graph/attack_surface.py`: `AttackSurfaceGraphBuilder.build_from_evidence(evidence, target, graph)`
    - Iterates over all evidence items in `evidence.all()`.
    - Section per vulnerability category (Sections 6–14 currently exist: General Vulns, Takeover, Info Disclosure, Access Control, Path Traversal, SQLi, XSS, CMDi, SSRF).
    - For each vulnerability evidence item:
      - Resolves/creates `live_host` node and `endpoint` node.
      - Creates `vulnerability` node.
      - Creates directional edges: `live_host -> endpoint` (`HAS_ENDPOINT`), `live_host -> vulnerability` (`HAS_VULNERABILITY`), and `endpoint -> vulnerability` (`HAS_VULNERABILITY`).
  - `AttackSurfaceGraphBuilder.build(mission)` (lines 637–816):
    - Calls `build_from_evidence()` if `mission.evidence` is present.
    - Also parses raw mission attributes (`mission.subdomains`, `mission.live_hosts`, `mission.endpoints`, `mission.vulnerabilities`) and ensures `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges are created.
    - Attaches populated graph to `mission.attack_surface_graph` and `mission.graph`.

---

## 2. Logic Chain

1. **DAG Scheduling Flow**:
   - Reconnaissance progresses from `subfinder` (subdomains) -> `httpx` (live hosts) -> `katana_crawler` (endpoints).
   - Once endpoints are discovered, `GapAnalyzer` detects gaps in vulnerability coverage or specific gap analysis triggers.
   - `TaskGenerator` matches the gap via `_resolve_template_for_gap()` to a template in `_RECON_TEMPLATES`.
   - The template defines `"dependencies": ["Discover API Endpoints"]`, ensuring the DAG scheduler orders the collector after endpoint discovery.
   - `TaskGenerator.from_gaps()` populates `required_inputs` with discovered endpoint URLs from `mission.endpoints`.

2. **Tool Selection & Execution Flow**:
   - `AutonomousMissionRuntime` steps through `PLANNING` -> `RESEARCHING`.
   - `TaskScheduler` queues ready tasks and passes them to `ToolOrchestrator.execute_task()`.
   - `ToolDispatcher.resolve_tool()` looks up `task.metadata["tool_id"]` in `ToolRegistry`.
   - `ToolDispatcher.dispatch()` identifies the tool safety requirement as `type: internal`, directing it to `InternalPluginExecutor`.
   - `InternalPluginExecutor` calls `PluginExecutorAdapter.execute_plugin()`, which falls back to `_instantiate_specialist_fallback()` to instantiate the collector.
   - `ControlledMission(mission)` is passed to `collector.execute()`, which runs the fuzzing/validation routines.

3. **Graph Construction & Invariant Flow**:
   - When the collector identifies a confirmed finding, `_create_evidence_and_update_state()` emits `Evidence(category=..., status="CONFIRMED")`, appends to `mission.vulnerabilities`, and directly updates the in-memory `KnowledgeGraph`.
   - When `AttackSurfaceGraphBuilder.build(mission)` or `build_from_evidence()` is invoked (e.g. during mission correlation, checkpointing, or report generation), the graph is reconstructed idempotently.
   - Tripartite graph connectivity is maintained: `live_host` node -> `endpoint` node via `HAS_ENDPOINT`, `live_host` node -> `vulnerability` node via `HAS_VULNERABILITY`, and `endpoint` node -> `vulnerability` node via `HAS_VULNERABILITY`.

---

## 3. Caveats

- In `argus/planning/task_generator.py`, `_RECON_TEMPLATES` currently supports 11 templates (`subfinder`, `httpx`, `katana_crawler`, `nuclei`, `info_disclosure`, `access_control`, `path_traversal`, `sql_injection`, `xss`, `command_injection`, `ssrf`). Sprint 13 requires adding the 12th template for OAuth/OIDC.
- In `argus/runtime/registry.py`, aliases and tool registration must be updated to register `oauth` / `oauth_oidc` as an internal plugin with priority 95.
- In `argus/runtime/plugins.py`, `_instantiate_specialist_fallback` must be updated to map `"oauth"` and `"oidc"` to the new `OAuthCollector` class.
- In `argus/graph/attack_surface.py`, a dedicated Section 15 must be added to `build_from_evidence()` to parse `category in ("oauth", "oidc", "oauth_oidc", "authentication")` and create the `endpoint` and `vulnerability` nodes and `HAS_VULNERABILITY` edges.

---

## 4. Conclusion & Required Integration Changes for Sprint 13

To satisfy R4 (Pipeline Connectivity) and Acceptance Criteria for Sprint 13 (OAuth/OIDC Token & Stateful Authentication Validation Collector), the following specific additions must be made across 4 core pipeline files:

### Summary Table of Target Files & Changes

| Subsystem | File Path | Class / Section | Required Change |
|---|---|---|---|
| **DAG Scheduling** | `argus/planning/task_generator.py` | `_RECON_TEMPLATES` (lines 13–146) | Add `"oauth"` (or `"oauth_oidc"`) template with `dependencies: ["Discover API Endpoints"]`, `required_inputs: ["endpoints"]`, `category: TaskCategory.AUTHORIZATION_ANALYSIS` (or `TaskCategory.EVIDENCE_CORRELATION`), `priority: 0.81`. |
| **Gap Resolution** | `argus/planning/task_generator.py` | `_resolve_template_for_gap` (lines 363–469) | Add matching for `"oauth"`, `"oidc"`, `"oauth/oidc"`, `"oauth2"`, `"openid"`, `"token validation"`, `"session fixation"`. |
| **Input Extraction** | `argus/planning/task_generator.py` | `from_gaps` (lines 470–527) | Include `"oauth"` in `tool_id` list for pulling `mission.endpoints`. |
| **Tool Registry** | `argus/runtime/registry.py` | `ToolRegistry.get` aliases (lines 19–30) | Add aliases: `"oauth_collector": "oauth"`, `"oidc": "oauth"`, `"oidc_collector": "oauth"`, `"oauth_oidc": "oauth"`. |
| **Tool Registration** | `argus/runtime/registry.py` | Module root (lines 58–368) | Register `Tool(id="oauth", name="OAuth/OIDC Authentication Collector", capability="oauth_oidc_detector", supported_tasks=[...], capabilities=[...], safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]}, priority=95)`. |
| **Plugin Fallback** | `argus/runtime/plugins.py` | `PluginExecutorAdapter._instantiate_specialist_fallback` (lines 65–114) | Add `elif "oauth" in plugin_id or "oidc" in plugin_id: from argus.collectors.oauth import OAuthCollector; return OAuthCollector()`. |
| **Graph Reconstruction** | `argus/graph/attack_surface.py` | `AttackSurfaceGraphBuilder.build_from_evidence` (lines 18–632) | Add Section 15 for `category in ("oauth", "oidc", "oauth_oidc", "authentication")` creating `live_host -> vulnerability` (`HAS_VULNERABILITY`) and `endpoint -> vulnerability` (`HAS_VULNERABILITY`) edges. |
| **Collector Graph Creation** | `argus/collectors/oauth.py` | `OAuthCollector._create_evidence_and_update_state` | Emit `Evidence(category="oauth", ...)`, update `mission.vulnerabilities`, add `live_host`, `endpoint`, `vulnerability` nodes to `mission.attack_surface_graph`, connect `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges. |

---

## 5. Verification Method

### 5.1 Verification Commands

1. **DAG & TaskGenerator Verification**:
   ```bash
   python -c "from argus.planning.task_generator import _RECON_TEMPLATES, TaskGenerator; assert 'oauth' in _RECON_TEMPLATES; print('TaskGenerator OK')"
   ```
2. **Tool Registry & Aliases Verification**:
   ```bash
   python -c "from argus.runtime.registry import registry; assert registry.get('oauth') is not None; assert registry.get('oauth_oidc') is not None; print('ToolRegistry OK')"
   ```
3. **Plugin Fallback Instantiation Verification**:
   ```bash
   python -c "from argus.runtime.plugins import PluginExecutorAdapter; adapter = PluginExecutorAdapter(); assert adapter._instantiate_specialist_fallback('oauth') is not None; print('Plugin adapter OK')"
   ```
4. **Attack Surface Graph & HAS_VULNERABILITY Edges Verification**:
   ```bash
   python -c "from argus.evidence.model import Evidence; from argus.graph.attack_surface import AttackSurfaceGraphBuilder; ev = Evidence(category='oauth', value='https://example.com/oauth/callback', metadata={'url': 'https://example.com/oauth/callback', 'host': 'https://example.com', 'template_id': 'oauth-redirect-uri-bypass'}); g = AttackSurfaceGraphBuilder().build_from_evidence([ev], target='example.com'); assert any(e.type == 'HAS_VULNERABILITY' for e in g.edges); print('Graph Builder OK')"
   ```
5. **Full Regression Suite**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   (Baseline: 1127 passed, 0 failures).

### 5.2 Invalidation Conditions
- Any failure in `_RECON_TEMPLATES` missing `"dependencies": ["Discover API Endpoints"]`.
- `registry.get("oauth")` returning `None`.
- `PluginExecutorAdapter._instantiate_specialist_fallback("oauth")` returning `None` or raising `ImportError`.
- Absence of `HAS_VULNERABILITY` edges between `live_host -> vulnerability` and `endpoint -> vulnerability` in the KnowledgeGraph.
- Regression in the 1127 baseline tests.
