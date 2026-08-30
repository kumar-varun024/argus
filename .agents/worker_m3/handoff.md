# Milestone 3 Handoff Report: Pipeline & Graph Integration
**Author**: Worker 3 (Pipeline & Graph Integration Specialist)  
**Milestone**: Sprint 10 Milestone 3  
**Date**: 2026-08-30  

---

## 1. Observation

Direct code observations from inspecting and updating the ARGUS codebase:

1. **`argus/runtime/registry.py`**:
   - `ToolRegistry.get()` originally only checked exact keys in `self.tools` and iterated `tool.capability == key or key in tool.capabilities`.
   - The tool definition for `xss` was missing from `registry.py`.
   - Added alias lookup support in `ToolRegistry.get` for `"cross_site_scripting": "xss"` and `"sqli": "sql_injection"`.
   - Registered the `xss` tool:
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

2. **`argus/runtime/plugins.py`**:
   - In `PluginExecutorAdapter._instantiate_specialist_fallback`:
     Added dynamic fallback instantiation:
     ```python
     elif "xss" in plugin_id or "cross_site_scripting" in plugin_id:
         from argus.collectors.xss import XSSCollector
         return XSSCollector()
     ```

3. **`argus/planning/task_generator.py`**:
   - Added `"xss"` recon template in `_RECON_TEMPLATES`:
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
     - Added explicit area mapping for `area_lower in ("xss", "xss detection", "cross site scripting", "cross-site scripting", "stored xss", "reflected xss", "dom xss")`.
     - In `gap.category == TaskCategory.EVIDENCE_CORRELATION`, mapped descriptions containing `"xss"`, `"cross-site"`, or `"scripting"` to `_RECON_TEMPLATES["xss"]`.
   - In `from_gaps`:
     - Included `"xss"` in the list of tools extracting endpoint inputs (`"katana_crawler", "nuclei", "info_disclosure", "access_control", "path_traversal", "sql_injection", "xss"`).

4. **`argus/graph/attack_surface.py`**:
   - In `AttackSurfaceGraphBuilder.build_from_evidence()`:
     - Added category handler for `getattr(ev, "category", None) in ("xss", "cross_site_scripting")`.
     - Implemented severity mapping: Stored XSS -> `"critical"`, Reflected XSS -> `"high"`, DOM/Header -> `"medium"`. Handled default `ev.severity == "info"` correctly to derive the appropriate severity level from `xss_type`.
     - Created `live_host`, `endpoint`, and `vulnerability` nodes with proper metadata.
     - Connected graph edges:
       - `live_host -> endpoint` (`HAS_ENDPOINT`)
       - `live_host -> vulnerability` (`HAS_VULNERABILITY`)
       - `endpoint -> vulnerability` (`HAS_VULNERABILITY`)

5. **Test Executions**:
   - `python -m pytest tests/graph/test_attack_surface_builder.py tests/planning/test_task_generator.py -v`: 28 passed in 0.34s.
   - `python -m pytest tests/collectors/test_xss.py tests/tools/test_environment_detector.py -v`: 42 passed in 2.74s.
   - `python -m pytest tests/ --ignore=tests/workspace -x -q`: 979 passed in 32.32s with 0 failures.

---

## 2. Logic Chain

1. **Tool Registration & Routing**:
   - When external or internal subsystems query `ToolRegistry.get("xss")` or `ToolRegistry.get("cross_site_scripting")`, resolving either key to the registered XSS `Tool` record enables standard DAG task dispatching and capability checks.
   - Adding `XSSCollector` fallback in `PluginExecutorAdapter` guarantees that when executing `ResearchTask` with `metadata.tool_id == "xss"`, the executor can dynamically instantiate and run `XSSCollector`.

2. **Recon Task DAG Generation**:
   - Recon tasks need proper dependency sequencing. The `"xss"` template explicitly declares dependency on `["Discover API Endpoints"]`, matching other active vulnerability fuzzers (`access_control`, `path_traversal`, `sql_injection`).
   - By mapping coverage gaps referencing XSS (by area or description) to `_RECON_TEMPLATES["xss"]`, the `TaskGenerator` creates concrete `ResearchTask` objects targeted at discovered endpoints with priority `0.81` and category `TaskCategory.EVIDENCE_CORRELATION`.

3. **Attack Surface Graph Construction**:
   - Security findings generated by `XSSCollector` produce `Evidence` records with category `"xss"` or `"cross_site_scripting"`.
   - `AttackSurfaceGraphBuilder.build_from_evidence` ingests these evidence records, extracting the endpoint URL, base URL, parameter, and XSS subtype.
   - Nodes for the `live_host`, `endpoint`, and `vulnerability` are instantiated and added to the `KnowledgeGraph`.
   - Edges `HAS_ENDPOINT` (host -> endpoint) and `HAS_VULNERABILITY` (host -> vuln, endpoint -> vuln) establish the graph topology.
   - Severity is mapped to `critical` for Stored XSS, `high` for Reflected XSS, and `medium` for DOM/header XSS, fulfilling the OWASP attack surface modeling requirements.

---

## 3. Caveats

- No caveats. All 4 owned files were modified according to specifications, and the entire test suite passed with 979 passing tests and zero regressions.

---

## 4. Conclusion

Milestone 3 is 100% complete.
- `argus/runtime/registry.py` registers the `xss` tool and supports alias retrieval.
- `argus/runtime/plugins.py` provides fallback instantiation for `XSSCollector`.
- `argus/planning/task_generator.py` defines the `"xss"` recon template, resolves XSS coverage gaps, and routes endpoint inputs.
- `argus/graph/attack_surface.py` constructs graph nodes and `HAS_VULNERABILITY` edges with accurate severity levels.
- Full test suite passes (979 tests) with 0 regressions.

---

## 5. Verification Method

To independently verify the implementation:

1. **Verify Graph and Planning Integration**:
   ```bash
   python -m pytest tests/graph/test_attack_surface_builder.py tests/planning/test_task_generator.py -v
   ```
   Expected: 28 passed.

2. **Verify Collectors and Environment Detector**:
   ```bash
   python -m pytest tests/collectors/test_xss.py tests/tools/test_environment_detector.py -v
   ```
   Expected: 42 passed.

3. **Verify Zero Regressions Across Full Suite**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   Expected: 979 passed.
