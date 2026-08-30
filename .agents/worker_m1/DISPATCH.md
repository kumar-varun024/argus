## 2026-08-30T07:13:07Z

You are Worker 1 (Environment Specialist) for Sprint 10 Milestone 1.
Your working directory is /home/varun/argus/.agents/worker_m1

You MUST read /home/varun/argus/.agents/ORIGINAL_REQUEST.md and /home/varun/argus/PROJECT.md before doing anything else.
You should also read the architectural specification at /home/varun/argus/.agents/survey_pipeline_explorer/handoff.md.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your Exclusive File Ownership:
- `argus/utils/__init__.py`
- `argus/utils/environment.py`
- `argus/runtime/mission.py`
- `argus/runtime/mission_runtime.py`
- `tests/tools/test_environment_detector.py`

Your Mission:
1. Create `argus/utils/__init__.py` and `argus/utils/environment.py`.
   Implement `EnvironmentDetector`:
   - `DEFAULT_EXTERNAL_TOOLS = ["subfinder", "httpx", "nuclei", "katana", "dnsx", "node", "npm"]`
   - `CLOUD_METADATA_ENDPOINTS = { "aws": ..., "gcp": ..., "azure": ... }`
   - `check_tools(tool_names=None) -> Dict[str, bool]`: checks tool availability via `shutil.which` (handling `httpx` vs `httpx-toolkit`).
   - `check_network(target: str) -> Dict[str, Any]`: checks DNS resolution via `socket.getaddrinfo` / `socket.gethostbyname` and HTTP reachability via `httpx.get` / `httpx.head` with reasonable timeout (e.g. 2s), catching socket/connection errors gracefully.
   - `check_cloud_metadata() -> Dict[str, Any]`: checks AWS (`169.254.169.254`), GCP (`metadata.google.internal` with `Metadata-Flavor: Google`), and Azure (`169.254.169.254` with `Metadata: true`) with quick timeout (e.g. 0.5s - 1s).
   - `detect(target: str = "") -> Dict[str, Any]`: aggregates tools, network, and cloud metadata into a structured dictionary with a `summary` key.
2. In `argus/runtime/mission.py`:
   - Add `environment: dict = field(default_factory=dict)` to the `Mission` dataclass.
3. In `argus/runtime/mission_runtime.py`:
   - During mission initialization or the `PLANNING` state transition in `step()`, ensure `mission.environment` is populated if empty using `EnvironmentDetector().detect(mission.target)`.
4. Create comprehensive tests in `tests/tools/test_environment_detector.py`:
   - Unit tests for `check_tools` (mocked present and missing tools).
   - Unit tests for `check_network` (mocked DNS resolution success, DNS failure, HTTP 200, HTTP failure).
   - Unit tests for `check_cloud_metadata` (mocked cloud endpoints available/unavailable).
   - Unit tests for `detect` composite output schema.
   - Integration test for `Mission` dataclass initialization and runtime environment population.
5. Run tests and verify zero regression:
   - `python -m pytest tests/tools/test_environment_detector.py -v`
   - `python -m pytest tests/ --ignore=tests/workspace -x -q`
6. Write your handoff report to `/home/varun/argus/.agents/worker_m1/handoff.md`.
7. Update `/home/varun/argus/.agents/worker_m1/progress.md`.
8. When complete, send a final message to the orchestrator referencing your handoff report.
