# Pipeline Connectivity, DAG Task Generation, Registry, Graph Builders, and Test Architecture Survey

## 1. Observation

Direct code observations across the ARGUS platform architecture:

### 1.1 Tool Registry and Plugin Architecture
- **`argus/runtime/registry.py`**:
  - Contains `ToolRegistry` class with global instance `registry` (lines 46-47).
  - Registry method `get(key: str)` supports tool lookup with alias resolution (lines 15-29):
    ```python
    aliases = {
        "cross_site_scripting": "xss",
        "sqli": "sql_injection",
    }
    ```
  - Registration pattern for internal security collectors (lines 249-326):
    - Example `sql_injection` (lines 297-310):
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
    - Example `xss` (lines 312-326):
      ```python
      registry.register(
          Tool(
              id="xss",
              name="Cross-Site Scripting (XSS) Collector",
              capability="xss_detector",
              description="Actively injects context-aware XSS payloads into discovered endpoint parameters and forms detecting reflected and stored XSS using AuthenticatedHttpClient.",
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
- **`argus/runtime/plugins.py`**:
  - `PluginExecutorAdapter` dispatches execution via `execute_plugin(plugin_id, mission)` (lines 30-64).
  - Invokes `ControlledMission(mission)` wrapper and calls `plugin.execute(controlled_mission)` or `plugin.discover()`.
  - Fallback instantiation `_instantiate_specialist_fallback(plugin_id)` contains dispatch routing by key (lines 65-106):
    - Line 98-100: `elif "sql_injection" in plugin_id or "sqli" in plugin_id or plugin_id == "sql": from argus.collectors.sql_injection import SQLInjectionCollector; return SQLInjectionCollector()`
    - Line 101-103: `elif "xss" in plugin_id or "cross_site_scripting" in plugin_id: from argus.collectors.xss import XSSCollector; return XSSCollector()`
- **`argus/collectors/__init__.py`**:
  - Exports collector classes and analyzers/generators (lines 1-33).

### 1.2 TaskGenerator DAG Architecture
- **`argus/planning/task_generator.py`**:
  - Defines `_RECON_TEMPLATES` mapping tool keys to task templates (lines 13-122).
  - SQLi / XSS template definitions (lines 98-121):
    ```python
    "sql_injection": {
        "title": "Fuzz SQL Injection",
        "goal": "Actively fuzz discovered endpoint parameters and HTTP headers for error-based, boolean-based, and time-based SQL injection vulnerabilities using AuthenticatedHttpClient.",
        "category": TaskCategory.EVIDENCE_CORRELATION,
        "required_inputs": ["endpoints"],
        "expected_outputs": ["vulnerabilities", "observations", "evidence"],
        "dependencies": ["Discover API Endpoints"],
        "required_specialists": [],
        "metadata": {"tool_id": "sql_injection"},
        "estimated_duration_minutes": 10,
        "priority": 0.81,
    }
    ```
  - Gap resolution `_resolve_template_for_gap(gap: CoverageGap)`:
    - Matches `area_lower` strings (lines 343-402).
    - Matches `gap.category == TaskCategory.EVIDENCE_CORRELATION` keyword descriptions (lines 420-432).
  - `from_gaps(gaps)` maps gaps to `ResearchTask` instances, populating `inputs` from `endpoints` when `tool_id in ("katana_crawler", "nuclei", "info_disclosure", "access_control", "path_traversal", "sql_injection", "xss")` (line 463).

### 1.3 Attack Surface Graph Edge Creation
- **`argus/graph/attack_surface.py`**:
  - `AttackSurfaceGraphBuilder.build_from_evidence(evidence, target, graph)` (lines 17-524):
    - Processes evidence categories to build `KnowledgeGraph` nodes and edges.
    - Section 10: Path Traversal (lines 350-400)
    - Section 11: SQL Injection (lines 401-453)
    - Section 12: Cross-Site Scripting (lines 454-522)
  - Node ID conventions:
    - Live Host: `f"live_host:{base_url}"` (`type="live_host"`, `value=base_url`, `metadata={"url": base_url, "host": ...}`)
    - Endpoint: `f"endpoint:{target_url}"` (`type="endpoint"`, `value=target_url`, `metadata={"url": target_url, "status_code": status_code}`)
    - Vulnerability: `f"vulnerability:{template_id}:{target_url}:{param_name}"` (`type="vulnerability"`, `value=vuln_name`, `metadata=vuln_meta`)
  - Edge types and connections:
    - `graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")`
    - `graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")`
    - `graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")`
- Collector internal graph integration:
  - Both `SQLInjectionCollector._create_evidence_and_update_state` (lines 1157-1171 of `sql_injection.py`) and `XSSCollector._create_evidence_and_update_state` (lines 1052-1066 of `xss.py`) mirror this graph expansion directly on `mission.attack_surface_graph` or `mission.graph`.

### 1.4 Test Architecture and Mock Conventions
- **`tests/collectors/test_sql_injection.py` and `tests/collectors/test_xss.py`**:
  - Mock HTTP client pattern: `MockSQLiHttpClient` / `MockXSSHttpClient` implementing `.get()` and `.post()` returning `HttpResponse` objects.
  - Route registry dictionary matching full URLs, injected headers (`f"header:{k}:{v}"`), or payload substring keys (`f"payload:{v}"`).
  - Latency simulation via `HttpResponse.elapsed` float field for time-based blind injection tests.
- **`tests/runtime/test_e2e_sql_injection.py` and `tests/runtime/test_e2e_xss.py`**:
  - Full end-to-end integration tests proving `Mission` -> `TaskGenerator` -> `ControlledMission` -> Collector execution -> `EvidenceStore` -> `KnowledgeGraph` expansion -> `AttackSurfaceGraphBuilder` reconstruction.
- **Test execution**:
  - Command: `python3 -m pytest tests/ --ignore=tests/workspace -q`
  - Current baseline status: `996 passed, 2 warnings in 44.59s` (100% pass rate).

---

## 2. Logic Chain

### 2.1 Tool Registration & Plugin Architecture Requirements for Command Injection
1. **Registry Entry (`argus/runtime/registry.py`)**:
   - Must register `Tool` with ID `"command_injection"` (or `"cmdi"`), `capability="command_injection_detector"`, `supported_tasks=["Command Injection Detection", "Command Injection", "Vulnerability Scanning", "Evidence Correlation", "API Discovery"]`, `required_inputs=["endpoints"]`, `produced_outputs=["vulnerabilities", "observations", "evidence"]`, `capabilities=["command_injection_detector", "command_injection_collector", "cmdi_detector", "cmdi_collector"]`, `safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]}`, `timeout=300.0`, `priority=95`.
   - Must add alias resolution in `ToolRegistry.get`:
     ```python
     aliases = {
         "cross_site_scripting": "xss",
         "sqli": "sql_injection",
         "cmdi": "command_injection",
         "cmd_injection": "command_injection",
         "os_command_injection": "command_injection",
     }
     ```
2. **Plugin Executor Adapter (`argus/runtime/plugins.py`)**:
   - In `PluginExecutorAdapter._instantiate_specialist_fallback`:
     ```python
     elif "command_injection" in plugin_id or "cmdi" in plugin_id or "cmd_injection" in plugin_id or plugin_id == "command":
         from argus.collectors.command_injection import CommandInjectionCollector
         return CommandInjectionCollector()
     ```
3. **Collector Module Export (`argus/collectors/__init__.py`)**:
   - Export `CommandInjectionCollector`, `CommandInjectionAnalyzer`, `CommandInjectionPayloadGenerator`, etc.

### 2.2 TaskGenerator DAG Wiring
1. **Task Template (`argus/planning/task_generator.py`)**:
   ```python
   "command_injection": {
       "title": "Fuzz OS Command Injection",
       "goal": "Actively fuzz discovered endpoint parameters, POST bodies, path segments, and HTTP headers for OS command injection vulnerabilities using AuthenticatedHttpClient.",
       "category": TaskCategory.EVIDENCE_CORRELATION,
       "required_inputs": ["endpoints"],
       "expected_outputs": ["vulnerabilities", "observations", "evidence"],
       "dependencies": ["Discover API Endpoints"],
       "required_specialists": [],
       "metadata": {"tool_id": "command_injection"},
       "estimated_duration_minutes": 10,
       "priority": 0.81,
   }
   ```
2. **Coverage Gap Resolution (`_resolve_template_for_gap`)**:
   - Keyword triggers in `area_lower`:
     ```python
     if area_lower in ("command injection", "cmdi", "command_injection", "cmd_injection", "os command injection", "remote code execution", "rce", "os injection"):
         return _RECON_TEMPLATES["command_injection"]
     ```
   - Category triggers under `TaskCategory.EVIDENCE_CORRELATION`:
     ```python
     if "command" in gap_desc_lower or "cmdi" in gap_desc_lower or "rce" in gap_desc_lower or "os injection" in gap_desc_lower:
         return _RECON_TEMPLATES["command_injection"]
     ```
3. **Inputs Resolution (`from_gaps`)**:
   - Include `"command_injection"` in the endpoint input binding list:
     ```python
     elif tool_id in ("katana_crawler", "nuclei", "info_disclosure", "access_control", "path_traversal", "sql_injection", "xss", "command_injection"):
     ```

### 2.3 Attack Surface Graph Edge Creation
1. **Graph Builder Extension (`argus/graph/attack_surface.py`)**:
   - Add Section 13 for Command Injection evidence:
     ```python
     # 13. Command Injection Vulnerabilities
     for ev in evidence_items:
         if getattr(ev, "category", None) in ("command_injection", "cmdi", "cmd_injection"):
             target_url = ev.metadata.get("url") or ev.value
             parsed_url = urllib.parse.urlparse(target_url) if target_url else None
             base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
             template_id = ev.metadata.get("template_id") or "cmdi"
             param_name = ev.metadata.get("parameter") or ""
             technique = ev.metadata.get("technique") or "result_based"
             vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
             vuln_name = ev.title or f"Command Injection ({technique})"
             vuln_meta = dict(ev.metadata) if ev.metadata else {}
             if "name" not in vuln_meta:
                 vuln_meta["name"] = vuln_name
             if "severity" not in vuln_meta:
                 vuln_meta["severity"] = getattr(ev, "severity", "critical") or "critical"

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
2. **Collector State Integration (`CommandInjectionCollector._create_evidence_and_update_state`)**:
   - Must create `Evidence(category="command_injection", severity="critical" or "high", provenance=ProvenanceData(step_id="command_injection_collector"), ...)`
   - Must append to `raw_mission.evidence` and `raw_mission.vulnerabilities`.
   - Must expand `raw_mission.attack_surface_graph` with `live_host`, `endpoint`, and `vulnerability` nodes and `HAS_ENDPOINT`, `HAS_VULNERABILITY` edges.

### 2.4 Test Suite Strategy
1. **Unit & Module Tests (`tests/collectors/test_command_injection.py`)**:
   - `test_command_injection_generator_base_payloads`: Result-based (`id`, `whoami`, `hostname`), time-based (`sleep 5`, `ping -c 5`, `timeout 5`), error-based.
   - `test_command_injection_generator_mutations`: 5+ distinct mutation/separator strategies (semicolons `;`, pipes `|`, `||`, ampersands `&`, `&&`, backticks `` `cmd` ``, dollar-parens `$(cmd)`, newlines `%0a`, URL encoding).
   - `test_command_injection_analyzer_result_based`: Regex matching for Unix `uid=0(root) gid=0(root)` and Windows `Windows IP Configuration` / `NT AUTHORITY\SYSTEM`.
   - `test_command_injection_analyzer_time_based`: Validates delta >= 4.0s vs baseline generates critical evidence; < 4.0s rejected.
   - `test_command_injection_analyzer_error_based`: Shell error signatures (`sh: command not found`, `syntax error near unexpected token`, `'cmd' is not recognized as an internal or external command`).
   - `test_command_injection_analyzer_false_positive_rejection`: Plain echo of injected commands in HTML search titles or static help text is rejected.
   - `test_command_injection_collector_query_param`: Fuzzing GET query parameters.
   - `test_command_injection_collector_post_body_json_and_form`: Fuzzing JSON and form bodies.
   - `test_command_injection_collector_path_segments`: Fuzzing path parameters.
   - `test_command_injection_collector_headers`: Fuzzing `User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`.
   - `test_command_injection_task_generator_dag_wiring`: Template resolution from CoverageGap.
   - `test_command_injection_tool_registry_and_plugin_adapter`: Tool registration and fallback instantiation.
   - `test_command_injection_attack_surface_graph_reconstruction`: Graph builder reconstruction from EvidenceStore.
2. **E2E Mission Loop Tests (`tests/runtime/test_e2e_command_injection.py`)**:
   - `test_e2e_command_injection_mission_loop_flow`: Full pipeline execution on realistic mock target.
   - `test_e2e_command_injection_multi_technique_mission`: Error-based + result-based + time-based in single mission.
   - `test_e2e_command_injection_gap_analysis_and_replanning`: Gap analysis triggers DAG task creation.

---

## 3. Caveats

- **Scope & Safety**: In accordance with the ARGUS safety architecture, the `CommandInjectionCollector` must only use benign commands (`id`, `whoami`, `hostname`, `sleep 5`, `echo canary`) for verification; destructive commands (e.g. `rm`, `mkfs`, arbitrary write) must never be used.
- **Timing Reliability in Benchmarks**: Time-based blind tests in mock unit suites should use mocked `HttpResponse.elapsed` (e.g., `elapsed=5.1` vs `baseline=0.1`) rather than actual wall-clock `time.sleep()`, ensuring fast and deterministic CI test execution.
- **Read-Only Scope**: This report is purely an exploratory investigation and architectural blueprint. No source code modifications were made.

---

## 4. Conclusion

The pipeline connectivity, DAG task generation, tool registry, attack surface graph builder, and test suite conventions in ARGUS are highly structured, modular, and consistent. Adding Sprint 11 Command Injection requires:
1. Registering `"command_injection"` in `argus/runtime/registry.py` and `argus/runtime/plugins.py`.
2. Adding `"command_injection"` template, gap resolution, and input resolution in `argus/planning/task_generator.py`.
3. Adding category `"command_injection"` handler in `argus/graph/attack_surface.py` to create `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
4. Exporting the new collector in `argus/collectors/__init__.py`.
5. Adding ~20+ unit and E2E tests in `tests/collectors/test_command_injection.py` and `tests/runtime/test_e2e_command_injection.py`.

---

## 5. Verification Method

### Test Suite Execution
Run the full test suite using the standard ARGUS command:
```bash
python3 -m pytest tests/ --ignore=tests/workspace -q
```
**Expected Current Baseline**:
`996 passed, 2 warnings in ~44s`

**Post-Sprint 11 Target**:
`1016+ passed, 0 failures, 0 regressions`

### Files to Inspect
- `argus/runtime/registry.py` (lines 19-30, 297-326)
- `argus/runtime/plugins.py` (lines 65-106)
- `argus/planning/task_generator.py` (lines 98-122, 365-433, 463)
- `argus/graph/attack_surface.py` (lines 350-523)
- `tests/collectors/test_sql_injection.py` & `tests/collectors/test_xss.py` (for test structure reference)
