## 2026-09-02T02:22:00Z
You are an Explorer subagent tasked with auditing the partial state and planning the remaining work for the File Upload Vulnerability Detection Module in the ARGUS platform.

Working Directory: /home/varun/argus
Read `/home/varun/argus/.agents/ORIGINAL_REQUEST.md` for full context and requirements.
Your working directory is `.agents/explorer_file_upload_audit/`.

## AUDIT SCOPE:
1. `argus/collectors/file_upload.py`:
   - Inspect the entire file.
   - Verify Tripartite Pattern: `FileUploadCollector` (or similar), `FileUploadPayloadGenerator` (or similar), `FileUploadAnalyzer` (or similar) - compare with `argus/collectors/cache_security.py` and `argus/collectors/cors_security.py`.
   - Verify Quadruple State Publishing Pattern:
     a) publish to EvidenceStore (`self.context.evidence_store.add(...)` or similar)
     b) publish to vulnerabilities list / findings (`self.context.vulnerabilities.append(...)` or `findings`)
     c) publish to Attack Surface Graph (`self.context.attack_surface_graph.add_node/edge(...)` or graph builder)
     d) ControlledMission / MissionContext wrapper compatibility
   - Check all requirements R1, R2.1-R2.6, R3, R4:
     * Unrestricted file upload (executable types)
     * MIME type bypass (Content-Type mismatch)
     * Double extension bypass (>= 3 combinations like shell.php.jpg, payload.asp.png, exploit.jsp.gif)
     * Polyglot file detection (GIF89a, PNG, JPEG headers + executable payload)
     * Path traversal in filenames (../, ..\\, URL-encoded)
     * Web shell accessibility check (HTTP GET/verification at predictable/extracted URL)
     * Response analysis (storage path disclosure, reflection, error info, timing/WAF)
     * 5+ mutation/evasion strategies (casing, null byte, content-type mismatch, magic bytes, filename encoding)
     * Severity calibration (Critical for unrestricted executable, High for MIME bypass, High for double extension, High for path traversal, Medium for missing validation on non-executable)
     * False positive rejection (legitimate image uploads with proper validation do NOT generate evidence)
   - Identify any missing methods, bugs, or incomplete logic in `file_upload.py`.

2. `argus/reporting/cvss.py`:
   - Check if CWE-434 and CWE-436 are mapped in `CWE_CVSS_BASE_SCORES` or similar CVSS mapping dicts.
   - Note exact mappings and scores.

3. `argus/runtime/registry.py`:
   - Check registry entry for `file_upload_specialist` / `file_upload` and verify aliases (`file_upload`, `file-upload`, `file_upload_specialist`).

4. `argus/runtime/plugins.py`:
   - Inspect fallback import logic. Identify what needs to be changed from `argus.plugins.file_upload.agent` to `argus.collectors.file_upload`.

5. `argus/planning/task_generator.py`:
   - Inspect `_RECON_TEMPLATES` and `_resolve_template_for_gap`.
   - Check if `file_upload` entry exists with dependency `["Discover API Endpoints"]` and keyword matching.

6. `argus/graph/attack_surface.py`:
   - Inspect graph builder evidence processing.
   - Check if `file_upload` category creates `HAS_VULNERABILITY` edges.

7. Test Suite Status:
   - Check if `tests/collectors/test_file_upload.py` and `tests/collectors/test_file_upload_adversarial.py` exist.
   - Plan exact test cases (at least 15 unit tests in `test_file_upload.py`, at least 10 adversarial tests in `test_file_upload_adversarial.py`, total >= 25 tests).

## OUTPUT REQUIREMENTS:
Write a comprehensive audit and implementation plan to `.agents/explorer_file_upload_audit/handoff.md`.
Send a message back to the caller when done with a summary of findings and specific diffs/instructions needed for the Worker.
