# File Upload Vulnerability Detection Module: Audit & Implementation Blueprint

## 1. Observation

A detailed audit across the ARGUS platform codebase was performed to evaluate the state of the File Upload Vulnerability Detection Module:

### A. `argus/collectors/file_upload.py` (1,231 lines)
- **Tripartite Architecture**:
  - Implements `FileUploadPayloadGenerator` (lines 193-596): Generates executable probes across 6 runtime families (`PHP`, `JSP`, `ASP_ASPX`, `PYTHON`, `RUBY`, `BASH`, `GENERIC`), MIME type bypass probes, double extension probes (11 combinations), polyglot magic byte probes (GIF89a, PNG, JPEG SOI, PDF), path traversal probes (10 traversal encodings/patterns), 7 mutation strategies, and benign baseline probes.
  - Implements `FileUploadProber` (lines 602-756): Executes multipart/form-data upload POST requests and secondary web shell verification GET requests using `AuthenticatedHttpClient`. Extracts storage locations via `Location` header, JSON fields (`url`, `path`, `file_url`, `location`, `filepath`, etc.), regex matches, and predictable `/uploads/` paths.
  - Implements `FileUploadAnalyzer` (lines 761-1014): Evaluates physical path disclosures (`/var/www/`, `C:\inetpub\wwwroot\`, S3, GCS), error disclosures, false positive rejection rules (benign probes, 400/403/415/422 status codes with validation failure messages, safe UUID renames), and calibrates severity/CWE/CVSS.
  - Implements `FileUploadCollector` (lines 1020-1221): Discovers candidate upload endpoints from `mission.inputs["endpoints"]`, `mission.endpoints`, `mission.live_hosts`, `mission.target`, and `mission.evidence`.
- **Quadruple State Publishing**:
  - `raw_mission.evidence.add(ev)` (Evidence store)
  - `raw_mission.vulnerabilities.append({...})` (Vulnerabilities findings list)
  - `graph.add(...)` and `graph.connect(..., edge_type="HAS_VULNERABILITY")` (Attack Surface Knowledge Graph)
  - `mission.publish_finding(ev.evidence_id, ev)` (ControlledMission wrapper)
- **Identified Gaps / Enhancements**:
  - `FileUploadPayloadGenerator` lacks `apply_mutation(self, probe: FileUploadProbe, strategy: FileUploadMutationStrategy) -> FileUploadProbe` to allow dynamic mutation of arbitrary probes on demand (matching `CacheSecurityPayloadGenerator` and `CORSPayloadGenerator`).
  - `FileUploadCollector.__init__` should accept optional `client: Optional[Any] = None`, `prober`, `generator`, `analyzer` parameters for flexible dependency injection and backward compatibility.
  - `FileUploadProber.execute_upload` should handle flexible mock client calling conventions (`client.post(mission=mission, ...)` vs `client.post(url, ...)`).

### B. `argus/reporting/cvss.py`
- `CWE_DATABASE` already includes:
  - `"file_upload"`, `"arbitrary_file_upload"`, `"unrestricted_file_upload"`, `"unrestricted_upload"`, `"null_byte_injection"`, `"web_shell_execution"`, `"cwe-434"`, `"cwe_434"` -> `CWEInfo("CWE-434", "Unrestricted Upload of File with Dangerous Type")`
  - `"mime_type_bypass"`, `"double_extension_bypass"`, `"polyglot_magic_bytes"`, `"polyglot_upload"`, `"interpretation_conflict"`, `"cwe-436"`, `"cwe_436"` -> `CWEInfo("CWE-436", "Interpretation Conflict")`
- `_get_preset_vector` already maps `"upload"` in `ReportSeverity.CRITICAL` to 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) and in `ReportSeverity.HIGH` to 8.2 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`).
- **Status**: Complete; no changes needed in `cvss.py`.

### C. `argus/runtime/registry.py`
- Lines 376-390 currently register a legacy `file_upload_specialist` tool with `supported_tasks=["Coverage Improvement"]`.
- `ToolRegistry.get` alias table (lines 19-197) does NOT have aliases for `file_upload`, `file-upload`, `file_upload_collector`, `file_upload_detector`, `unrestricted_file_upload`, `arbitrary_file_upload`.
- **Status**: Needs alias dictionary additions and modern `file_upload` tool registration with `priority=95`, capability `"file_upload_detector"`, and produced outputs `["vulnerabilities", "observations", "evidence"]`.

### D. `argus/runtime/plugins.py`
- Lines 89-91 contain:
  ```python
  elif "file_upload" in plugin_id:
      from argus.plugins.file_upload.agent import FileUploadSpecialist
      return FileUploadSpecialist()
  ```
- **Status**: Must be updated to import and return `FileUploadCollector` from `argus.collectors.file_upload`.

### E. `argus/planning/task_generator.py`
- `_RECON_TEMPLATES` (lines 13-278) does NOT contain `file_upload`.
- `_resolve_template_for_gap` (lines 496-793) does NOT contain gap area matching or keyword resolution for file upload.
- **Status**: Needs `file_upload` template in `_RECON_TEMPLATES` with dependency `["Discover API Endpoints"]` and area/keyword resolution in `_resolve_template_for_gap`.

### F. `argus/graph/attack_surface.py`
- `build_from_evidence` has sections 1-25 (ending with CORS at line 1042). It does NOT process `file_upload` evidence items into `HAS_VULNERABILITY` and `HAS_ENDPOINT` graph edges.
- **Status**: Needs Section 26 added to `build_from_evidence` for `file_upload` categories.

### G. Test Suite Status
- Baseline `python -m pytest tests/ --ignore=tests/workspace -x -q` run passes 1,784 tests (0 failures).
- `tests/collectors/test_file_upload.py` and `tests/collectors/test_file_upload_adversarial.py` do not exist yet.
- **Status**: Need at least 25 new tests (planned: 22+ unit tests in `test_file_upload.py` and 12+ adversarial tests in `test_file_upload_adversarial.py`, total 34+ tests).

---

## 2. Logic Chain

1. **Architecture Alignment**: ARGUS collectors follow a standardized Tripartite architecture (`Collector`, `PayloadGenerator`, `Analyzer`) and Quadruple state publishing pattern (`evidence_store`, `vulnerabilities`, `attack_surface_graph`, `ControlledMission`). Enhancing `argus/collectors/file_upload.py` with `apply_mutation` and robust kwargs makes it fully compliant with reference collectors (`cache_security.py`, `cors_security.py`).
2. **DAG & Planning Integration**: In the ARGUS autonomous workflow, `TaskGenerator` transforms coverage gaps into `ResearchTask`s. Adding `file_upload` to `_RECON_TEMPLATES` with dependency `["Discover API Endpoints"]` ensures upload scanning is scheduled after endpoints are crawled by Katana.
3. **Runtime Execution Routing**: When `PluginExecutorAdapter` is invoked with `file_upload`, `file_upload_collector`, or `file_upload_detector`, it resolves to `FileUploadCollector` and executes against the target mission.
4. **Graph Edge Construction**: When `AttackSurfaceGraphBuilder.build_from_evidence()` executes, Section 26 will extract file upload findings and create `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges connecting live hosts and endpoints to the vulnerability nodes.
5. **Adversarial & Unit Verification**: Writing comprehensive unit and adversarial tests ensures zero false positives on legitimate images, proper error rejection, WAF/timeout resilience, and verification that all 1,784+ baseline tests continue passing.

---

## 3. Caveats

- **Network-Level Interaction**: `AuthenticatedHttpClient` enforces scope and permission gates. Mock HTTP clients in tests must simulate both `HttpResponse` objects and raw dictionary/tuple responses.
- **Old Plugin Compatibility**: `argus/plugins/file_upload/` contains a legacy intelligence classifier (`FileUploadPlugin`). The collector in `argus/collectors/file_upload.py` is the active security prober. Both can coexist cleanly.

---

## 4. Conclusion & Implementation Blueprint

The remaining work is concrete and self-contained across 6 files:

### File 1: `argus/collectors/file_upload.py`
Add `apply_mutation(self, probe: FileUploadProbe, strategy: FileUploadMutationStrategy) -> FileUploadProbe` to `FileUploadPayloadGenerator`.
```python
    def apply_mutation(
        self,
        probe: FileUploadProbe,
        strategy: Union[FileUploadMutationStrategy, str],
    ) -> FileUploadProbe:
        """Applies a specified evasion/mutation strategy to a given FileUploadProbe."""
        strat = FileUploadMutationStrategy(strategy) if isinstance(strategy, str) else strategy
        mutated = copy.deepcopy(probe)
        mutated.strategy = strat
        base_name, ext = os.path.splitext(probe.filename)

        if strat == FileUploadMutationStrategy.EXTENSION_CASING:
            # Alternating extension casing: .php -> .pHp
            if ext:
                cased_ext = "".join(c.upper() if i % 2 == 1 else c.lower() for i, c in enumerate(ext))
                mutated.filename = f"{base_name}{cased_ext}"

        elif strat == FileUploadMutationStrategy.NULL_BYTE:
            # Append %00.jpg null byte sequence
            mutated.filename = f"{probe.filename}%00.jpg"
            mutated.content_type = "image/jpeg"

        elif strat == FileUploadMutationStrategy.CONTENT_TYPE_MISMATCH:
            mutated.content_type = "image/jpeg"

        elif strat == FileUploadMutationStrategy.MAGIC_BYTES_PREPENDING:
            canary = probe.canary_token or self.generate_canary()
            script_content = self.build_payload_content(probe.target_runtime, canary)
            mutated.content = self.GIF89A_HEADER + b"\n" + script_content.encode("utf-8")
            mutated.content_type = "image/gif"

        elif strat == FileUploadMutationStrategy.FILENAME_ENCODING:
            # URL encode dots or slashes
            mutated.filename = probe.filename.replace(".", "%2e")

        elif strat == FileUploadMutationStrategy.TRAILING_DOTS_SPACES:
            mutated.filename = f"{probe.filename}."

        elif strat == FileUploadMutationStrategy.NTFS_STREAM:
            mutated.filename = f"{probe.filename}::$DATA"

        return mutated
```

In `FileUploadCollector.__init__`:
```python
    def __init__(
        self,
        http_client: Optional[Any] = None,
        prober: Optional[FileUploadProber] = None,
        generator: Optional[FileUploadPayloadGenerator] = None,
        analyzer: Optional[FileUploadAnalyzer] = None,
        timeout: float = 10.0,
        max_probes_per_endpoint: int = 50,
        client: Optional[Any] = None,
    ):
        effective_client = client or http_client or AuthenticatedHttpClient(timeout=timeout)
        self.http_client = effective_client
        self.prober = prober or FileUploadProber(client=self.http_client, timeout=timeout)
        self.generator = generator or FileUploadPayloadGenerator()
        self.analyzer = analyzer or FileUploadAnalyzer()
        self.timeout = timeout
        self.max_probes_per_endpoint = max_probes_per_endpoint
```

In `FileUploadProber.execute_upload`:
Support flexible client post signatures:
```python
        try:
            if hasattr(self.client, "post"):
                import inspect
                sig = inspect.signature(self.client.post)
                if "mission" in sig.parameters:
                    raw_resp = self.client.post(
                        mission=mission,
                        url=target_url,
                        files=files,
                        data=data,
                        timeout=self.timeout,
                        action="file_upload_probe",
                    )
                else:
                    raw_resp = self.client.post(
                        target_url,
                        files=files,
                        data=data,
                        timeout=self.timeout,
                    )
            elif hasattr(self.client, "request"):
                raw_resp = self.client.request(
                    "POST",
                    target_url,
                    files=files,
                    data=data,
                    timeout=self.timeout,
                )
            else:
                raw_resp = None
```

---

### File 2: `argus/runtime/registry.py`
In `ToolRegistry.get()` aliases dict:
```python
            "file_upload": "file_upload",
            "file-upload": "file_upload",
            "file_upload_specialist": "file_upload",
            "file_upload_collector": "file_upload",
            "file_upload_detector": "file_upload",
            "unrestricted_file_upload": "file_upload",
            "arbitrary_file_upload": "file_upload",
            "upload_security": "file_upload",
```

At bottom of `registry.py`, add the modern tool registration:
```python
registry.register(
    Tool(
        id="file_upload",
        name="File Upload Vulnerability Detection Collector",
        capability="file_upload_detector",
        description="Actively discovers and validates file upload vulnerabilities (unrestricted executable uploads, MIME type bypasses, double extension bypasses, polyglots, path traversal in filenames, and web shell execution) using AuthenticatedHttpClient.",
        supported_tasks=[
            "File Upload Security",
            "Unrestricted File Upload",
            "MIME Type Bypass",
            "Double Extension Bypass",
            "Polyglot Upload",
            "Path Traversal in Filename",
            "Web Shell Detection",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "file_upload_detector",
            "file_upload_collector",
            "file_upload_analyzer",
            "unrestricted_file_upload",
            "file_upload_specialist",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)
```

---

### File 3: `argus/runtime/plugins.py`
Update `_instantiate_specialist_fallback`:
```python
            elif (
                "file_upload" in plugin_id
                or "upload" in plugin_id
                or "unrestricted_upload" in plugin_id
                or "arbitrary_upload" in plugin_id
            ):
                from argus.collectors.file_upload import FileUploadCollector
                return FileUploadCollector()
```

---

### File 4: `argus/planning/task_generator.py`
Add to `_RECON_TEMPLATES`:
```python
    "file_upload": {
        "title": "Validate File Upload Security",
        "goal": "Actively test discovered endpoints for unrestricted executable uploads, MIME type bypasses, double extensions, polyglots, and path traversal in filenames using AuthenticatedHttpClient.",
        "category": TaskCategory.EVIDENCE_CORRELATION,
        "required_inputs": ["endpoints"],
        "expected_outputs": ["vulnerabilities", "observations", "evidence"],
        "dependencies": ["Discover API Endpoints"],
        "required_specialists": [],
        "metadata": {"tool_id": "file_upload"},
        "estimated_duration_minutes": 10,
        "priority": 0.81,
    },
```

In `_resolve_template_for_gap`:
```python
        if area_lower in (
            "file upload",
            "file_upload",
            "file upload security",
            "upload security",
            "unrestricted file upload",
            "unrestricted upload",
            "arbitrary file upload",
            "mime type bypass",
            "double extension bypass",
            "polyglot upload",
            "web shell detection",
            "file upload vulnerabilities",
        ):
            return _RECON_TEMPLATES["file_upload"]
```
and under `gap.category == TaskCategory.EVIDENCE_CORRELATION`:
```python
            if any(kw in gap_desc_lower for kw in ("file upload", "upload security", "unrestricted upload", "arbitrary upload", "mime type bypass", "double extension", "polyglot", "web shell", "file upload vulnerability")):
                return _RECON_TEMPLATES["file_upload"]
```

---

### File 5: `argus/graph/attack_surface.py`
Add Section 26 inside `build_from_evidence`:
```python
        # 26. File Upload Vulnerabilities
        for ev in get_items(
                "file_upload",
                "upload_security",
                "unrestricted_upload",
                "unrestricted_file_upload",
                "arbitrary_file_upload",
                "mime_type_bypass",
                "double_extension_bypass",
                "polyglot_magic_bytes",
                "path_traversal_filename",
                "web_shell_execution",
            ):
                target_url = ev.metadata.get("url") or ev.value
                parsed_url = urllib.parse.urlparse(target_url) if target_url else None
                base_url = ev.metadata.get("host") or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url and parsed_url.netloc else target_url)
                template_id = ev.metadata.get("template_id") or "file-upload-finding"
                filename = ev.metadata.get("filename") or ev.metadata.get("parameter") or ""
                vuln_type = ev.metadata.get("vulnerability_type") or ev.metadata.get("technique") or "file_upload"
                vuln_id = f"vulnerability:{template_id}:{target_url}:{filename}" if (target_url and filename) else (f"vulnerability:{template_id}:{target_url}" if target_url else f"vulnerability:{template_id}")
                vuln_name = ev.title or f"File Upload Vulnerability ({vuln_type})"
                vuln_meta = dict(ev.metadata) if ev.metadata else {}
                if "name" not in vuln_meta:
                    vuln_meta["name"] = vuln_name
                if "severity" not in vuln_meta:
                    vuln_meta["severity"] = getattr(ev, "severity", "high") or "high"

                ep_id = f"endpoint:{target_url}" if target_url else None
                if ep_id and ep_id not in graph.nodes:
                    graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": ev.metadata.get("status_code", 200)}))

                graph.add(Node(id=vuln_id, type="vulnerability", value=vuln_name, metadata=vuln_meta))

                # Link live host to endpoint & vulnerability
                lh_node = resolve_lh(target_url_val=target_url, host_val=base_url)
                if not lh_node and base_url:
                    lh_id = f"live_host:{base_url}"
                    if lh_id not in graph.nodes:
                        parsed_b = urllib.parse.urlparse(base_url)
                        graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
                    lh_node = graph.get(lh_id)

                if lh_node:
                    if ep_id:
                        graph.connect(lh_node.id, ep_id, edge_type="HAS_ENDPOINT")
                    graph.connect(lh_node.id, vuln_id, edge_type="HAS_VULNERABILITY")
                if ep_id:
                    graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")
```

---

### File 6: Test Suites
Create `tests/collectors/test_file_upload.py` (22+ unit tests):
1. `test_file_upload_severity_enums_and_aliases`
2. `test_file_upload_technique_enums_and_aliases`
3. `test_file_upload_mutation_strategy_enums_and_aliases`
4. `test_file_upload_result_properties`
5. `test_payload_generator_unrestricted_probes`
6. `test_payload_generator_mime_bypass_probes`
7. `test_payload_generator_double_extension_probes`
8. `test_payload_generator_polyglot_probes`
9. `test_payload_generator_path_traversal_probes`
10. `test_payload_generator_evasion_mutations`
11. `test_payload_generator_benign_probes`
12. `test_payload_generator_apply_mutation`
13. `test_prober_extract_storage_information_location_header`
14. `test_prober_extract_storage_information_json_body`
15. `test_prober_extract_storage_information_html_regex`
16. `test_prober_web_shell_reachability_and_execution_verification`
17. `test_analyzer_detect_storage_path_disclosure`
18. `test_analyzer_detect_error_disclosure`
19. `test_analyzer_false_positive_rejection_benign_probe`
20. `test_analyzer_false_positive_rejection_status_403_and_rejection_keywords`
21. `test_analyzer_false_positive_rejection_uuid_renaming_safe_ext`
22. `test_analyzer_severity_and_cwe_calibration`
23. `test_collector_full_lifecycle_and_quadruple_state_publishing`
24. `test_collector_discover_candidate_endpoints_deduplication`
25. `test_collector_compatibility_aliases`
26. `test_tool_registry_file_upload_registration_and_aliases`
27. `test_plugin_executor_adapter_file_upload_fallback`
28. `test_task_generator_dag_file_upload_template`
29. `test_task_generator_resolve_gap_file_upload`
30. `test_attack_surface_graph_file_upload_evidence_edges`
31. `test_cvss_calculator_cwe_434_and_436_mappings`

Create `tests/collectors/test_file_upload_adversarial.py` (12+ adversarial tests):
1. `test_adversarial_legitimate_upload_proper_validation_no_evidence`
2. `test_adversarial_waf_403_rejection_patterns_no_evidence`
3. `test_adversarial_415_unsupported_media_type_no_evidence`
4. `test_adversarial_error_reflection_without_file_storage_no_upload_finding`
5. `test_adversarial_safe_uuid_rename_and_extension_stripping_no_finding`
6. `test_adversarial_network_timeout_and_connection_drop_resilience`
7. `test_adversarial_malformed_json_upload_response_resilience`
8. `test_adversarial_empty_candidate_endpoints_graceful_exit`
9. `test_adversarial_web_shell_get_404_not_executed`
10. `test_adversarial_web_shell_reflected_source_code_not_executed`
11. `test_adversarial_probe_limit_enforcement`
12. `test_adversarial_controlled_mission_exception_swallowed`

---

## 5. Verification Method

To independently verify the implementation:
1. Run full test suite including new tests:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
2. Run targeted File Upload unit and adversarial tests:
   ```bash
   python -m pytest tests/collectors/test_file_upload.py tests/collectors/test_file_upload_adversarial.py -v
   ```
3. Invalidation Conditions:
   - If any baseline test fails (regression < 1,784 tests passing)
   - If `file_upload` task cannot be scheduled from TaskGenerator
   - If `HAS_VULNERABILITY` graph edges are not created from `file_upload` evidence
