# Handoff Report: Pipeline, Tool Registry, Graph Model, and SQLInjectionCollector Integration Survey

**Author**: `survey_explorer_2` (Pipeline & Graph Explorer)  
**Date**: 2026-08-29  
**Target Milestone**: Sprint 9 — SQL Injection Detection Engine  

---

## 1. Observation

Direct code observations from the ARGUS codebase across the five surveyed topics:

### 1.1 TaskGenerator & Recon DAG Wiring
- **File**: `argus/planning/task_generator.py` (lines 12–98, 202–312, 314–400, 401–457)
  - `_RECON_TEMPLATES` (lines 13–98) defines recon task configurations:
    - `"subfinder"`: Category `TECHNOLOGY_DISCOVERY`, dependencies `[]`, priority `0.95`, metadata `{"tool_id": "subfinder"}`
    - `"httpx"`: Category `TECHNOLOGY_DISCOVERY`, dependencies `["Discover Subdomains"]`, priority `0.90`, metadata `{"tool_id": "httpx"}`
    - `"katana_crawler"`: Category `API_DISCOVERY`, dependencies `["Fingerprint Live Hosts"]`, priority `0.85`, metadata `{"tool_id": "katana_crawler"}`
    - `"nuclei"`: Category `EVIDENCE_CORRELATION`, dependencies `["Fingerprint Live Hosts"]`, priority `0.80`, metadata `{"tool_id": "nuclei"}`
    - `"info_disclosure"`: Category `EVIDENCE_CORRELATION`, dependencies `["Fingerprint Live Hosts"]`, priority `0.82`, metadata `{"tool_id": "info_disclosure"}`
    - `"access_control"`: Category `AUTHORIZATION_ANALYSIS`, dependencies `["Discover API Endpoints"]`, priority `0.81`, metadata `{"tool_id": "access_control"}`
    - `"path_traversal"`: Category `EVIDENCE_CORRELATION`, dependencies `["Discover API Endpoints"]`, priority `0.81`, metadata `{"tool_id": "path_traversal"}`
  - `TaskGenerator.generate_recon_tasks()` (lines 202–312) generates ordered `ResearchTask` chains.
  - `TaskGenerator._resolve_template_for_gap(gap)` (lines 314–400) maps area keywords (e.g. `"path traversal"`, `"access control"`) and category fallbacks into templates.
  - `TaskGenerator.from_gaps(gaps)` (lines 401–457) converts gaps into tasks, pulling candidate endpoint URLs from `mission.endpoints` or `mission.live_hosts` (lines 429–435).

- **File**: `argus/planning/gap_analysis.py` (lines 51–177, 180–314, 327–345)
  - `GapAnalyzer._check_recon_gaps()` checks 5 states: subdomains, live hosts, uncrawled endpoints (`get_hosts_without_endpoints()`), unscanned hosts (`get_hosts_without_vulnerabilities()`), and information disclosure.
  - Suppression helpers (e.g. `_has_vulnerability_scan()`, `_has_information_disclosure_scan()`) check `mission.vulnerabilities`, `mission.evidence`, `mission.tool_runs`, `mission.execution_history`, `mission.research_tasks`, and `mission.task_states`.

- **File**: `argus/planning/research_planner.py` (lines 44–74)
  - Evaluates `CoverageTracker`, runs `GapAnalyzer`, calls `TaskGenerator.generate_recon_tasks()` or `from_gaps(gaps)`, injects knowledge base hints via `KnowledgeManager`, and runs `DecisionEngine.prioritize()`.

- **File**: `argus/runtime/executor.py` (lines 27–140, 155–190)
  - `TaskScheduler.schedule_tasks()` maps `ResearchTask` -> `ScheduledTask` in `ExecutionQueueManager`.
  - Tasks with dependencies (e.g. `"Discover API Endpoints"`) remain blocked until the parent task reports success via `report_success()`.

### 1.2 Tool Registry & Execution Interface
- **File**: `argus/runtime/registry.py` (lines 5–38, 41–288)
  - `ToolRegistry` holds a global singleton `registry`.
  - Tools are registered via `registry.register(Tool(...))` with fields: `id`, `name`, `capability`, `description`, `supported_tasks`, `required_inputs`, `produced_outputs`, `capabilities`, `safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]}`, `timeout`, `priority`.
  - Lookup supports ID (`registry.get("tool_id")`) and capability name.

- **File**: `argus/runtime/dispatcher.py` (lines 10–92)
  - `ToolDispatcher.resolve_tool(task)` checks `task.metadata["tool_id"]`, `task.required_specialists`, and `registry.find_compatible_tools(category_name)`.
  - `ToolDispatcher.dispatch()` checks `tool.safety_requirements["type"]`. When `"internal"`, routes execution to `InternalPluginExecutor`.

- **File**: `argus/runtime/plugins.py` (lines 10–100)
  - `InternalPluginExecutor` calls `PluginExecutorAdapter.execute_plugin(tool.id, context.mission)`.
  - `PluginExecutorAdapter.execute_plugin()` wraps `mission` in `ControlledMission(mission)` and invokes `plugin.execute(controlled_mission)` or `plugin.discover(controlled_mission)`.
  - `PluginExecutorAdapter._instantiate_specialist_fallback(plugin_id)` (lines 65–100) matches plugin IDs and returns collector instances (e.g., `PathTraversalCollector`, `AccessControlCollector`, `InformationDisclosureCollector`).

### 1.3 Attack Surface Graph Model & Wiring
- **File**: `argus/graph/node.py` (lines 4–19)
  - `Node(id: str, type: str, value: str, metadata: dict[str, Any])`
  - Node types in use: `"target"`, `"subdomain"`, `"live_host"`, `"endpoint"`, `"technology"`, `"vulnerability"`, `"secret"`, `"cname"`.

- **File**: `argus/graph/edge.py` (lines 4–19)
  - `Edge(source: str, target: str, type: str, metadata: dict[str, Any])`
  - Edge types in use: `"RESOLVES_TO"`, `"HOSTS"`, `"RUNS_TECHNOLOGY"`, `"HAS_ENDPOINT"`, `"HAS_VULNERABILITY"`, `"POINTS_TO_CNAME"`, `"EXPOSES_SECRET"`, `"DISCLOSED_SUBDOMAIN"`.

- **File**: `argus/graph/graph.py` (lines 6–95, 166–195)
  - `KnowledgeGraph` manages nodes dictionary and edges list.
  - `add(node)` prevents duplicate node IDs.
  - `connect(source, target, edge_type, metadata)` prevents duplicate directed edges.
  - `get_hosts_without_endpoints()` and `get_hosts_without_vulnerabilities()` inspect outgoing `"HAS_ENDPOINT"` and `"HAS_VULNERABILITY"` edges.

- **File**: `argus/graph/attack_surface.py` (lines 11–402, 406–585)
  - `AttackSurfaceGraphBuilder.build_from_evidence(evidence, target, graph)` reconstructs graphs from `EvidenceStore`:
    - Lines 48–59: `"subdomain"` -> `Node(id="subdomain:<host>", type="subdomain")`, Edge `target -> subdomain (RESOLVES_TO)`
    - Lines 61–104: `"live_host"` -> `Node(id="live_host:<url>", type="live_host")`, Edge `subdomain -> live_host (HOSTS)`
    - Lines 135–172: `"endpoint"` -> `Node(id="endpoint:<url>", type="endpoint")`, Edge `live_host -> endpoint (HAS_ENDPOINT)`
    - Lines 298–348: `"broken_access_control"` -> `endpoint`, `vulnerability`, `live_host` nodes, Edges `live_host -> endpoint (HAS_ENDPOINT)`, `live_host -> vuln (HAS_VULNERABILITY)`, `endpoint -> vuln (HAS_VULNERABILITY)`
    - Lines 349–400: `"path_traversal"` -> `endpoint`, `vulnerability`, `live_host` nodes, Edges `live_host -> endpoint (HAS_ENDPOINT)`, `live_host -> vuln (HAS_VULNERABILITY)`, `endpoint -> vuln (HAS_VULNERABILITY)`
  - `AttackSurfaceGraphBuilder.build(mission)` ingests both `mission.evidence` and raw `mission` attributes (`subdomains`, `live_hosts`, `endpoints`, `vulnerabilities`).

### 1.4 Severity Levels Assignment
- **File**: `argus/evidence/model.py` (line 50): `severity: str = "info"`
- **Pattern across collectors**:
  - In `argus/collectors/path_traversal.py` (lines 527, 540, 562): `severity="critical"`
  - In `argus/collectors/access_control.py` (lines 312, 343, 386): Horizontal IDOR & Vertical PrivEsc -> `severity="critical"`, Header bypass -> `severity="high"`
  - In `argus/collectors/information_disclosure.py` (lines 467, 478, 500, 527): Leaked secrets/API keys -> `severity="high"`, internal hosts -> `severity="info"`
- **Requirement for SQLi in `ORIGINAL_REQUEST.md` (lines 25, 35–37)**:
  - Error-based SQLi: `severity="critical"`
  - Time-based blind SQLi: `severity="critical"`
  - Boolean-based blind SQLi: `severity="high"`
- **Propagation points**:
  - `Evidence.severity` (`"critical"` or `"high"`)
  - `mission.vulnerabilities.append({"severity": "critical"|"high", ...})`
  - `Node.metadata["severity"] = "critical"` (or `"high"`)
  - `AttackSurfaceGraphBuilder.build_from_evidence()` copies `ev.severity` into `vuln_meta["severity"]`.

---

## 2. Logic Chain

1. **Scheduling & Execution Lifecycle**:
   - `KatanaCrawler` crawls endpoints and outputs list of endpoint URLs into `mission.endpoints`.
   - `TaskGenerator` receives the mission state during planning. Because `_RECON_TEMPLATES["sql_injection"]` declares dependency `["Discover API Endpoints"]`, the SQLi task is scheduled to run after endpoint crawling.
   - `TaskScheduler` places `ScheduledTask(task_title="Scan & Detect SQL Injection", dependencies=["Discover API Endpoints"])` in `ExecutionQueueManager`.
   - When Katana finishes, `TaskScheduler.report_success()` unlocks the SQLi task.
   - `ToolDispatcher.resolve_tool()` looks up `metadata["tool_id"] = "sql_injection"`, locates `Tool(id="sql_injection")` in `ToolRegistry`, notes `safety_requirements={"type": "internal"}`, and delegates to `InternalPluginExecutor`.
   - `InternalPluginExecutor` calls `PluginExecutorAdapter.execute_plugin("sql_injection", mission)`.
   - `PluginExecutorAdapter` instantiates `SQLInjectionCollector` via `_instantiate_specialist_fallback()` and invokes `SQLInjectionCollector.execute(controlled_mission)`.

2. **Collector Execution & Graph Edge Construction**:
   - `SQLInjectionCollector.collect(mission)` unwraps `mission`, extracts candidate endpoints from `mission.endpoints` and `mission.live_hosts`.
   - It iterates over parameters (query parameters, POST body fields, path segments, and HTTP headers like `Cookie`, `Referer`, `X-Forwarded-For`).
   - Using `AuthenticatedHttpClient`, it injects error-based payloads, boolean-based TRUE/FALSE pairs, and time-based sleep payloads (with WAF bypass mutations).
   - Upon confirming a vulnerability:
     - Emits `Evidence(category="sql_injection", severity="critical"|"high", status="CONFIRMED", confidence=0.95, ...)`
     - Appends evidence to `mission.evidence`
     - Appends vulnerability dictionary to `mission.vulnerabilities`
     - Expands `mission.attack_surface_graph`:
       - `graph.add(Node(id=f"live_host:{base_url}", type="live_host", value=base_url))`
       - `graph.add(Node(id=f"endpoint:{target_url}", type="endpoint", value=target_url))`
       - `graph.add(Node(id=f"vulnerability:{template_id}:{target_url}", type="vulnerability", value=title, metadata=ev.metadata))`
       - `graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")`
       - `graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")`
       - `graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")`

3. **Reconstruction & Resilience**:
   - When missions are serialized or reconstructed from evidence (`AttackSurfaceGraphBuilder.build_from_evidence()`), evidence items with `category == "sql_injection"` will recreate identical nodes and `HAS_ENDPOINT` / `HAS_VULNERABILITY` edges.

---

## 3. Caveats

1. **HTTP Client Wrapper vs Mock Injection**:
   - In live execution, `AuthenticatedHttpClient` is used with `with AuthenticatedHttpClient(...) as client: client.get(mission, url, ...)`.
   - In unit/integration tests, `SQLInjectionCollector` should accept an optional `http_client` constructor parameter to enable fast, deterministic mocking of error signatures, differential boolean sizes, and simulated delays without real network calls.
2. **Endpoint Extraction**:
   - Discovered endpoints in `mission.endpoints` can be strings (e.g. `"https://target.com/search?q=test"`) or dictionaries (e.g. `{"url": "...", "path": "...", "method": "POST"}`). The collector must normalize both formats.
   - If `mission.endpoints` is empty, the collector must fallback to candidate routes on `mission.live_hosts` (e.g. `/`, `/login`, `/search`, `/api/v1/user`).
3. **Dual Execution Hooks**:
   - Both `collect(mission)` and `execute(mission)` must be present on `SQLInjectionCollector` so that both direct programmatic invocation and `PluginExecutorAdapter` / `ControlledMission` function seamlessly.

---

## 4. Conclusion & Concrete Integration Blueprint

Below are the exact files, classes, and registration hooks required to implement `SQLInjectionCollector` in Sprint 9:

### 4.1 New File: `argus/collectors/sql_injection.py`
- **Class `SQLInjectionPayloadGenerator`**:
  - Generates payloads for:
    - Error-based: `' OR 1=1--`, `' UNION SELECT NULL, @@version--`, `1' AND 1=CONVERT(int, (SELECT @@version))--`, `1' AND (SELECT 1 FROM (SELECT(SLEEP(0)))a)--`, `1' AND ctxsys.drithsx.sn(1, (SELECT banner FROM v$version WHERE rownum=1))--`, `1' AND 1=CAST((SELECT sqlite_version()) AS INT)--`
    - Boolean-based: Pairs of TRUE and FALSE queries (e.g., `' AND '1'='1` vs `' AND '1'='2`, `' OR 1=1--` vs `' OR 1=2--`, `1 AND 1=1` vs `1 AND 1=2`)
    - Time-based: `'; WAITFOR DELAY '0:0:5'--`, `' OR SLEEP(5)--`, `1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--`, `1' AND 1=dbms_pipe.receive_message('RDS', 5)--`, `1' AND (SELECT 1 FROM (SELECT(pg_sleep(5)))a)--`
    - WAF Bypass Mutations: Case alternation (`sElEcT`), Comment insertion (`SEL/**/ECT`), URL encoding (`%27%20OR%201%3D1`), Double encoding (`%2527%2520OR%25201%253D1`), Whitespace substitution (`%09`, `%0a`, `+`).
- **Class `SQLInjectionAnalyzer`**:
  - DBMS error regexes for MySQL, PostgreSQL, MSSQL, Oracle, SQLite.
  - Boolean response length/content differential analysis.
  - Time-delay measurement (>=4.0s delay vs baseline).
  - False positive rejection (ignores static occurrences of "error" on baseline pages; ignores non-differential reflections).
- **Class `SQLInjectionCollector(BaseCollector)`**:
  - Implements `.collect(mission)` and `.execute(mission)`
  - Uses `AuthenticatedHttpClient`
  - Injects parameters across query string, POST body fields, path segments, and HTTP headers (`Cookie`, `Referer`, `X-Forwarded-For`).
  - Emits `Evidence(category="sql_injection", severity="critical"|"high", status="CONFIRMED", confidence=0.95)`
  - Updates `mission.evidence`, `mission.vulnerabilities`, and `mission.attack_surface_graph` with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.

### 4.2 Modify: `argus/collectors/__init__.py`
- Export `SQLInjectionCollector`, `SQLInjectionPayloadGenerator`, `SQLInjectionAnalyzer`.

### 4.3 Modify: `argus/planning/task_generator.py`
- In `_RECON_TEMPLATES`:
  ```python
  "sql_injection": {
      "title": "Scan & Detect SQL Injection",
      "goal": "Actively probe and detect error-based, boolean-based, and time-based SQL injection vulnerabilities in discovered endpoint parameters and HTTP headers.",
      "category": TaskCategory.EVIDENCE_CORRELATION,
      "required_inputs": ["endpoints"],
      "expected_outputs": ["vulnerabilities", "observations", "evidence"],
      "dependencies": ["Discover API Endpoints"],
      "required_specialists": [],
      "metadata": {"tool_id": "sql_injection"},
      "estimated_duration_minutes": 10,
      "priority": 0.81,
  },
  ```
- In `_resolve_template_for_gap()`:
  - Add keyword matching: `if area_lower in ("sql injection", "sqli", "sql_injection", "sql vulnerabilities", "database injection", "sqli detection"): return _RECON_TEMPLATES["sql_injection"]`
  - In category fallback for `TaskCategory.EVIDENCE_CORRELATION` / `API_DISCOVERY`: match `"sql"` or `"sqli"` or `"injection"`.
- In `from_gaps()`:
  - Add `"sql_injection"` to `elif tool_id in ("katana_crawler", "nuclei", "info_disclosure", "access_control", "path_traversal", "sql_injection"):`

### 4.4 Modify: `argus/runtime/registry.py`
- Register `sql_injection` tool:
  ```python
  registry.register(
      Tool(
          id="sql_injection",
          name="SQL Injection Collector",
          capability="sql_injection_detector",
          description="Actively injects SQL payloads into discovered endpoint parameters (query, body, headers) detecting error-based, boolean-based, and time-based blind SQLi.",
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

### 4.5 Modify: `argus/runtime/plugins.py`
- In `PluginExecutorAdapter._instantiate_specialist_fallback()`:
  ```python
  elif "sql_injection" in plugin_id or "sqli" in plugin_id or plugin_id == "sql":
      from argus.collectors.sql_injection import SQLInjectionCollector
      return SQLInjectionCollector()
  ```

### 4.6 Modify: `argus/graph/attack_surface.py`
- In `AttackSurfaceGraphBuilder.build_from_evidence()`:
  - Add section for `getattr(ev, "category", None) == "sql_injection"`:
    - Creates `endpoint` node, `vulnerability` node, `live_host` node.
    - Sets `vuln_meta["severity"] = getattr(ev, "severity", "critical")`
    - Connects `live_host -> endpoint` (`HAS_ENDPOINT`)
    - Connects `live_host -> vulnerability` (`HAS_VULNERABILITY`)
    - Connects `endpoint -> vulnerability` (`HAS_VULNERABILITY`)

---

## 5. Verification Method

To independently verify the pipeline integration and test suite compliance:

1. **Verify Baseline Test Suite**:
   ```bash
   python3 -m pytest tests/ --ignore=tests/workspace -q
   ```
   *Expected*: 861+ passed, 0 failures.

2. **Verify Tool Registry**:
   ```python
   from argus.runtime.registry import registry
   tool = registry.get("sql_injection")
   assert tool is not None
   assert tool.capability == "sql_injection_detector"
   assert tool.safety_requirements["type"] == "internal"
   ```

3. **Verify DAG Task Generation**:
   ```python
   from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
   from argus.planning.models import CoverageGap, TaskCategory
   from argus.runtime.mission import Mission

   assert "sql_injection" in _RECON_TEMPLATES
   mission = Mission(target="test.com")
   mission.endpoints = ["https://test.com/items?id=1"]
   gen = TaskGenerator(mission)
   tasks = gen.from_gaps([CoverageGap(area="sql injection", description="Test SQLi", severity=0.81)])
   assert len(tasks) == 1
   assert tasks[0].metadata["tool_id"] == "sql_injection"
   assert "Discover API Endpoints" in tasks[0].dependencies
   ```

4. **Verify Graph Wiring & Builder Reconstruction**:
   ```python
   from argus.graph.attack_surface import AttackSurfaceGraphBuilder
   from argus.evidence.model import Evidence

   ev = Evidence(
       title="SQL Injection on https://test.com/api?id=1",
       category="sql_injection",
       severity="critical",
       value="https://test.com/api?id=1",
       metadata={"url": "https://test.com/api?id=1", "host": "https://test.com", "template_id": "sqli-error-mysql"}
   )
   builder = AttackSurfaceGraphBuilder()
   graph = builder.build_from_evidence([ev], target="test.com")
   assert any(e.type == "HAS_VULNERABILITY" for e in graph.edges)
   assert any(e.type == "HAS_ENDPOINT" for e in graph.edges)
   ```

5. **Verify Plugin Executor Adapter Fallback**:
   ```python
   from argus.runtime.plugins import PluginExecutorAdapter
   from argus.collectors.sql_injection import SQLInjectionCollector

   adapter = PluginExecutorAdapter()
   instance = adapter._instantiate_specialist_fallback("sql_injection")
   assert isinstance(instance, SQLInjectionCollector)
   ```
