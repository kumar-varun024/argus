## 2026-08-29T15:02:05Z
You are the Lead Implementation Worker (Phase 8: Path & Directory Traversal Engine).
Your working directory is: /home/varun/argus/.agents/worker_impl/

You MUST read the following specifications before starting:
- `/home/varun/argus/.agents/ORIGINAL_REQUEST.md` (under timestamp ## 2026-08-29T14:56:52Z)
- `/home/varun/argus/.agents/PROJECT.md`
- `/home/varun/argus/.agents/orchestrator/implementation_plan.md`
- `/home/varun/argus/.agents/survey_explorer_1/handoff.md`
- `/home/varun/argus/.agents/survey_explorer_2/handoff.md`
- `/home/varun/argus/.agents/survey_explorer_3/handoff.md`

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Mission Objectives:
Implement the complete Path & Directory Traversal Engine according to requirements R1-R5:

1. R1: Path Traversal Collector (`argus/collectors/path_traversal.py` and export in `argus/collectors/__init__.py`):
   - Implement `PathTraversalCollector(BaseCollector)` supporting dependency injection `__init__(self, http_client: Optional[Any] = None, payloads: Optional[List[str]] = None, timeout: float = 5.0)`.
   - Implement `collect(self, mission: Any) -> List[Evidence]` and `execute(self, mission: Any) -> List[Evidence]`.
   - Ingest candidate endpoints from `mission.endpoints`, `mission.live_hosts`, `mission.target`.
   - Support both query parameter fuzzing (e.g. `?file=`, `?path=`, `?page=`, etc.) and path segment fuzzing (e.g. `/download/{payload}`).
   - Fall back to standard probe routes (`/download`, `/file`, `/view`, `/read`, `/image`, `/static`, `/doc`, `/get`, `/include`) when no parameterized endpoints exist.
   - Dispatch requests via `AuthenticatedHttpClient` (or injected `http_client`) with proper scope guarding and timeout.
   - On confirmed vulnerability:
     * Emit `Evidence(category="path_traversal", severity="critical", status="CONFIRMED", confidence=0.95, ...)`
     * Append to `mission.evidence` and `mission.vulnerabilities`
     * Mutate `mission.attack_surface_graph` (or `mission.graph`) by adding `Node(type="live_host")`, `Node(type="endpoint")`, `Node(type="vulnerability")` and wiring `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.

2. R2: Payload Generation Engine:
   - Implement payload wordlists and mutation generators supporting:
     * Standard sequences: `../`, `....//`, `../../../../etc/passwd`, `..\..\..\..\windows\win.ini`
     * Encoded sequences: `%2e%2e%2f`, double URL-encoded `%252e%252e%252f`, overlong UTF-8 `%c0%ae%c0%ae%c0%af`
     * Absolute paths: `/etc/passwd`, `c:\windows\win.ini`, `c:/windows/win.ini`, `/etc/shadow`, `c:\boot.ini`
     * Null byte bypasses: `/etc/passwd%00`, `../../../../etc/passwd%00.jpg`, `c:/windows/win.ini%00.png`
     * Path parameter bypasses: `..;/`

3. R3: Vulnerability Detection & False Positive Prevention:
   - Implement signature matching for:
     * Linux: `root:x:0:0:`, `root:*:0:0:`, `daemon:x:`, `/bin/bash`, shadow entries, environ variables
     * Windows: `[extensions]`, `boot loader`, `[fonts]`, `[mci extensions]`, `for 16-bit app support`
   - Prevent false positives:
     * Require HTTP status code in 2xx range (reject 404, 500, 403)
     * Reflection filter: If the response simply echoes the injected payload string without genuine OS file contents, discard as reflection
     * Discard HTML error bodies or generic responses without OS file layout

4. R4: Pipeline Connectivity & Graph Wiring:
   - `argus/planning/task_generator.py`: Add `"path_traversal"` recon template (category `TaskCategory.EVIDENCE_CORRELATION`, dependencies `["Discover API Endpoints"]`, priority `0.81`, metadata `{"tool_id": "path_traversal"}`), gap resolver routing for path traversal keywords, and endpoint binding in `from_gaps`.
   - `argus/runtime/registry.py`: Register `Tool(id="path_traversal", name="Path Traversal Collector", capability="path_traversal_detector", ...)` as internal tool.
   - `argus/runtime/plugins.py`: Add fallback in `_instantiate_specialist_fallback` to return `PathTraversalCollector()`.
   - `argus/graph/attack_surface.py`: Handle `category == "path_traversal"` in `build_from_evidence` to wire `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges.

5. R5: Unit & Integration Tests (`tests/collectors/test_path_traversal.py`):
   - Programmatic mock test verifying `Evidence(category="path_traversal", severity="critical")` when an endpoint returns `root:x:0:0:root:/root:/bin/bash`.
   - Comprehensive test suite covering:
     * Standard, encoded, double-encoded, absolute, and null-byte payload mutations
     * Linux signature matches (`/etc/passwd`, `/etc/shadow`, `/proc/self/environ`)
     * Windows signature matches (`win.ini`, `boot.ini`)
     * False positive rejection (echoes, 404s, 500s, generic HTML)
     * DAG generation & scheduling
     * Registry registration & plugin fallback
     * Attack surface graph `HAS_VULNERABILITY` edges
     * ControlledMission & Mission loop execution
   - At least 15 new tests.

6. Victory Audit:
   - Run `python -m pytest tests/ --ignore=tests/workspace -x -q`
   - Ensure 100% pass with 0 regressions across all 749+ existing tests + new tests.
   - Write your complete handoff report to `/home/varun/argus/.agents/worker_impl/handoff.md`.
   - Send completion message when done.
