# Handoff Report: Pipeline Registration, TaskGenerator DAG Wiring, AttackSurfaceGraph Integration, and Testing Patterns Survey

## 1. Observation

### 1.1 Tool Registry Architecture & Plugin Adapter
- **File**: `argus/runtime/registry.py`
  - **Class**: `ToolRegistry` (lines 5–58) maintains a dictionary `self.tools: Dict[str, Tool]`.
  - **Global instance**: `registry = ToolRegistry()` (line 60).
  - **Tool Registration Structure** (lines 309–404 for collectors):
    ```python
    registry.register(
        Tool(
            id="xml_parser_validation",  # or "xxe"
            name="XML Parser Configuration Validation Collector",
            capability="xml_parser_security_validator",
            description="Actively validates XML parser configurations on discovered endpoints, testing for external entity resolution, parameter entities, and recursive entity expansion using AuthenticatedHttpClient.",
            supported_tasks=[
                "XML Parser Validation",
                "XXE Detection",
                "XML External Entity",
                "Vulnerability Scanning",
                "Evidence Correlation",
                "API Discovery",
            ],
            required_inputs=["endpoints"],
            produced_outputs=["vulnerabilities", "observations", "evidence"],
            capabilities=[
                "xml_parser_security_validator",
                "xml_parser_validation_collector",
                "xxe_detector",
                "xxe_collector",
            ],
            safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
            timeout=300.0,
            priority=95,
        )
    )
    ```
  - **Alias Resolution** in `ToolRegistry.get()` (lines 19–34):
    Contains an explicit alias dictionary `aliases = {...}` mapping alternate names (e.g., `"sqli": "sql_injection"`, `"cmdi": "command_injection"`, `"server_side_request_forgery": "ssrf"`, `"oidc": "oauth"`). Needs aliases like:
    ```python
    "xxe": "xml_parser_validation",
    "xxe_collector": "xml_parser_validation",
    "xml_external_entity": "xml_parser_validation",
    "xml_parser_validator": "xml_parser_validation",
    ```
- **File**: `argus/runtime/plugins.py`
  - **Class**: `PluginExecutorAdapter` (lines 10–118) executes internal plugins and specialists.
  - **Fallback Dispatch** in `_instantiate_specialist_fallback(self, plugin_id: str)` (lines 65–116):
    Maps plugin ID substrings to collector instantiations. Required hook:
    ```python
    elif "xml" in plugin_id or "xxe" in plugin_id:
        from argus.collectors.xml_parser import XMLParserValidationCollector
        return XMLParserValidationCollector()
    ```
- **File**: `argus/collectors/__init__.py`
  - Exports collector classes and analyzers (lines 1–71).

---

### 1.2 TaskGenerator DAG Wiring & Dependencies
- **File**: `argus/planning/task_generator.py`
  - **Recon Templates Dictionary**: `_RECON_TEMPLATES` (lines 13–158).
  - All vulnerability collectors depend on `"Discover API Endpoints"` (katana crawler output) and operate on `required_inputs=["endpoints"]`:
    ```python
    "xml_parser_validation": {
        "title": "Validate XML Parser Configuration",
        "goal": "Actively test XML-accepting endpoints for external entity resolution, parameter entity processing, and recursive entity expansion misconfigurations using AuthenticatedHttpClient.",
        "category": TaskCategory.EVIDENCE_CORRELATION,
        "required_inputs": ["endpoints"],
        "expected_outputs": ["vulnerabilities", "observations", "evidence"],
        "dependencies": ["Discover API Endpoints"],
        "required_specialists": [],
        "metadata": {"tool_id": "xml_parser_validation"},
        "estimated_duration_minutes": 10,
        "priority": 0.81,
    },
    ```
  - **CoverageGap Resolution** in `_resolve_template_for_gap(self, gap: CoverageGap)` (lines 375–496):
    - Explicit keyword mapping (lines 380–416):
      ```python
      if area_lower in ("xml parser", "xml_parser", "xml parser validation", "xxe", "xml external entity", "xml_external_entity", "xml injection", "xml"):
          return _RECON_TEMPLATES["xml_parser_validation"]
      ```
    - Category fallback under `TaskCategory.EVIDENCE_CORRELATION` (lines 477–495):
      ```python
      if "xxe" in gap_desc_lower or "xml" in gap_desc_lower or "entity" in gap_desc_lower or "external entity" in gap_desc_lower:
          return _RECON_TEMPLATES["xml_parser_validation"]
      ```
  - **Input Asset Binding** in `from_gaps(self, gaps: List[CoverageGap])` (lines 526–528):
    ```python
    elif tool_id in ("katana_crawler", "nuclei", "info_disclosure", "access_control", "path_traversal", "sql_injection", "xss", "command_injection", "ssrf", "oauth", "xml_parser_validation"):
        inputs = [str(e.get('url', e)) if isinstance(e, dict) else str(e) for e in endpoints[:10] if e is not None] if endpoints else ([str(h.get('url', h)) if isinstance(h, dict) else str(h) for h in live_hosts[:10] if h is not None] if live_hosts else ([target] if target else ["endpoints"]))
    ```

---

### 1.3 AttackSurfaceGraph Integration & HAS_VULNERABILITY Edges
- **Graph Expansion Patterns**:
  Graph edge creation occurs in two complementary locations:

  1. **Direct In-Collector State & Graph Update (`_create_evidence_and_update_state`)**:
     Observed in `argus/collectors/sql_injection.py` (lines 1060–1180), `command_injection.py` (lines 1214–1335), and `oauth.py` (lines 1147–1260):
     - Unwraps `raw_mission = getattr(mission, "_mission", mission)`.
     - Creates `ev = Evidence(category="xml_parser_validation", severity=severity, ...)` and appends to `raw_mission.evidence`.
     - Appends entry to `raw_mission.vulnerabilities`.
     - Expands `KnowledgeGraph`:
       ```python
       graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
       if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
           lh_id = f"live_host:{base_url}"
           ep_id = f"endpoint:{target_url}"
           vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

           graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
           graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
           graph.add(Node(id=vuln_id, type="vulnerability", value=f"XML Parser Misconfiguration ({tech_label})", metadata=ev.metadata))

           graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
           graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
           graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")
       ```
     - Publishes to `ControlledMission` if wrapped: `mission.publish_finding(...)`.

  2. **AttackSurfaceGraphBuilder Reconstruction (`argus/graph/attack_surface.py`)**:
     In `build_from_evidence(evidence, target, graph)` (lines 17–878):
     Iterates over `evidence_items` and contains dedicated handlers for vulnerability categories.
     For XML parser / XXE evidence:
     ```python
     for ev in evidence_items:
         if getattr(ev, "category", None) in ("xml_parser_validation", "xxe", "xml_external_entity", "xml_injection"):
             target_url = ev.metadata.get("url") or ev.value
             parsed_url = urllib.parse.urlparse(target_url) if target_url else None
             base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
             template_id = ev.metadata.get("template_id") or "xxe"
             param_name = ev.metadata.get("parameter") or ""
             vuln_id = f"vulnerability:{template_id}:{target_url}:{param_name}" if (target_url and param_name) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
             vuln_name = ev.title or "XML External Entity / Parser Misconfiguration"
             vuln_meta = dict(ev.metadata) if ev.metadata else {}
             if "name" not in vuln_meta:
                 vuln_meta["name"] = vuln_name
             if "severity" not in vuln_meta:
                 vuln_meta["severity"] = getattr(ev, "severity", "critical") or "critical"

             ep_id = f"endpoint:{target_url}" if target_url else None
             if ep_id and ep_id not in graph.nodes:
                 graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": ev.metadata.get("status_code", 200)}))

             graph.add(Node(id=vuln_id, type="vulnerability", value=vuln_name, metadata=vuln_meta))

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

  3. **CVSS & CWE Mapping (`argus/reporting/cvss.py`)**:
     `CWE_DATABASE` (lines 33–70) currently lacks XML entries. It should be augmented with:
     ```python
     "xxe": CWEInfo("CWE-611", "Improper Restriction of XML External Entity Reference"),
     "xml_external_entity": CWEInfo("CWE-611", "Improper Restriction of XML External Entity Reference"),
     "xml_parser_validation": CWEInfo("CWE-611", "Improper Restriction of XML External Entity Reference"),
     "xml_injection": CWEInfo("CWE-91", "XML Injection (aka Blind XPath Injection)"),
     ```

---

### 1.4 Test Suite & Mocking Patterns Analysis
- **Test Locations**:
  - Unit and integration tests for collectors reside in `tests/collectors/` (e.g. `tests/collectors/test_sql_injection.py`, `tests/collectors/test_command_injection.py`, `tests/collectors/test_oauth.py`, `tests/collectors/test_xss.py`, `tests/collectors/test_ssrf.py`).
  - Adversarial robustness tests are co-located in `tests/collectors/test_*_adversarial.py`.
  - Planning and DAG scheduling tests reside in `tests/planning/` (`test_task_generator.py`, `test_recon_task_generation.py`).
  - Graph integration tests reside in `tests/graph/test_graph_integration.py`.
- **Mock HTTP Testing Pattern**:
  - The test suite uses custom in-memory mock HTTP clients that adhere to the `AuthenticatedHttpClient` / `AuthorizedHttpClient` signature:
    - Route tables: `self.routes: Dict[str, Tuple[int, str, float]]` (mapping URLs, `header:<key>:<val>`, or `payload:<val>` to `(status_code, body, elapsed)`).
    - Exposes `.get(mission_or_url, url=None, **kwargs) -> HttpResponse` and `.post(mission_or_url, url=None, **kwargs) -> HttpResponse`.
    - Handles content-type negotiation (`application/xml`, `text/xml`, `application/soap+xml`), body parsing, parameter inspection, and timing simulation (`elapsed`).
- **Baseline Test Execution**:
  - Command: `venv/bin/pytest tests/ --ignore=tests/workspace -x -q` (or `python -m pytest tests/ --ignore=tests/workspace -x -q`)
  - Output: `1257 passed, 1 skipped, 26647 warnings in 78.29s (0:01:18)`
  - Exit code: `0` (Zero regressions).

---

## 2. Logic Chain

1. **Collector Modular Design**:
   All recent ARGUS vulnerability collectors (`SQLInjectionCollector`, `CommandInjectionCollector`, `SSRFCollector`, `OAuthCollector`, `XSSCollector`) follow a standardized three-component architecture:
   - `<Module>PayloadGenerator`: Generates base payloads and 5+ bypass mutations (e.g., encoding variants, CDATA wrapping, DOCTYPE alterations, namespace injections, XInclude).
   - `<Module>Analyzer`: Analyzes `HttpResponse` bodies and response times for vulnerability indicators and rejects false positives.
   - `<Module>Collector(BaseCollector)`: Coordinates endpoint extraction (from `mission.endpoints` or `mission.live_hosts`), fuzzer dispatch across XML POST bodies and XML parameters, evidence generation, mission state updates, and graph node/edge creation.

2. **Pipeline Integration Chain**:
   - `registry.py` registers the tool capability and safety requirements, ensuring tool discovery by the runtime executor and CLI.
   - `plugins.py` provides lazy/fallback instantiation of the collector via `PluginExecutorAdapter` when executed as an internal plugin.
   - `task_generator.py` defines the recon template with `"dependencies": ["Discover API Endpoints"]`, ensuring the XML validation task is scheduled immediately after crawler/endpoint discovery.
   - `attack_surface.py` and `_create_evidence_and_update_state` ensure confirmed findings generate strongly typed `vulnerability` nodes connected to parent `live_host` and `endpoint` nodes via `HAS_VULNERABILITY` edges.

3. **Verification Harness Consistency**:
   - Unit tests verify payload generator permutations, analyzer signature matching, and false positive rejection.
   - Integration tests verify `collect(mission)` and `execute(ControlledMission)` against mock HTTP endpoints, checking evidence store contents, mission vulnerability lists, and knowledge graph edges (`HAS_ENDPOINT`, `HAS_VULNERABILITY`).
   - Task generator and tool registry tests verify DAG template resolution and fallback instantiation.

---

## 3. Caveats
- No caveats: The pipeline architecture, registry structures, DAG generator, graph model, and mock HTTP testing conventions are completely uniform across all existing collectors and verified against the passing test suite baseline.

---

## 4. Conclusion
The integration points for Sprint 15: XML Parser Configuration Validation (`XMLParserValidationCollector`) are fully identified and mapped:
1. **Module**: `argus/collectors/xml_parser.py` (implementing `XMLParserValidationCollector`, `XMLPayloadGenerator`, `XMLParserAnalyzer`, `XMLValidationResult`, `XMLTechnique`).
2. **Registry**: Register `Tool(id="xml_parser_validation", ...)` in `argus/runtime/registry.py` with aliases (`"xxe"`, `"xml_external_entity"`), export in `argus/collectors/__init__.py`, and hook in `PluginExecutorAdapter._instantiate_specialist_fallback` in `argus/runtime/plugins.py`.
3. **DAG Wiring**: Add `"xml_parser_validation"` template in `argus/planning/task_generator.py` under `_RECON_TEMPLATES` with dependency on `"Discover API Endpoints"`, update `_resolve_template_for_gap` and `from_gaps`.
4. **Graph Integration**: Add category handler in `argus/graph/attack_surface.py` to create `vulnerability` nodes and `HAS_VULNERABILITY` edges, emit in collector's `_create_evidence_and_update_state`, and register CWE-611 in `argus/reporting/cvss.py`.
5. **Testing**: Add comprehensive test suite in `tests/collectors/test_xml_parser.py` (20+ tests covering entity resolution, parameter entities, recursive entity expansion, 5 bypass mutations, false positive rejection, DAG wiring, registry lookup, and graph builder).

---

## 5. Verification Method
1. Verify existing test suite baseline:
   ```bash
   venv/bin/pytest tests/ --ignore=tests/workspace -x -q
   ```
   (Expect 1,257 passed, 1 skipped).
2. Inspect target integration files:
   - `argus/runtime/registry.py`
   - `argus/runtime/plugins.py`
   - `argus/planning/task_generator.py`
   - `argus/graph/attack_surface.py`
   - `argus/reporting/cvss.py`
   - `tests/collectors/`
