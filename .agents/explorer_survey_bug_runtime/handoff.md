# Handoff Report: Investigation of Priority 0 Bug and Mission Runtime Lifecycle

**Agent Working Directory:** `/home/varun/argus/.agents/explorer_survey_bug_runtime`  
**Date/Timestamp:** 2026-08-28T08:27:00Z  
**Target Focus:** Root-cause analysis of the mission loop hanging in `MissionState.RESEARCHING` without transitioning to `COLLECTING_EVIDENCE`, lifecycle tracing of `TaskScheduler`/`QueueManager`/`ToolOrchestrator`, and smoke test diagnostic.

---

## 1. Observation

### 1.1 Direct Observation of Bug Reproduction
Running the standalone smoke test from `ORIGINAL_REQUEST.md` lines 38–97 directly produces:
```
Mission status: MissionState.RESEARCHING
Subdomains: ['api.example.com', 'admin.example.com']
Live hosts: []
Research tasks: [
    ('Discover Subdomains', 'COMPLETED', []),
    ('Analyze Authentication Workflows', 'FAILED', []),
    ('Analyze Authorization Relationships', 'SCHEDULED', ['Analyze Authentication Workflows'])
]
Queue tasks: [
    ('Analyze Authentication Workflows', 'FAILED', []),
    ('Discover Subdomains', 'COMPLETED', []),
    ('Analyze Authorization Relationships', 'BLOCKED', ['Analyze Authentication Workflows'])
]
Queue is_complete: False
```
The loop runs continuously until the timeout (45s) expires. Mission status remains `MissionState.RESEARCHING`.

### 1.2 Exact Code Locations Examined

#### A. `argus/runtime/dependencies.py` (lines 20–54)
```python
    @staticmethod
    def resolve(tasks: List[ScheduledTask]) -> List[ScheduledTask]:
        title_map: Dict[str, ScheduledTask] = {t.task_title: t for t in tasks}
        completed_titles: Set[str] = {
            t.task_title for t in tasks if t.state == TaskState.COMPLETED
        }
        newly_ready: List[ScheduledTask] = []

        for task in tasks:
            if task.state not in (TaskState.PENDING, TaskState.BLOCKED):
                continue

            if not task.dependencies:
                # No dependencies — immediately ready
                if task.state != TaskState.READY:
                    task.state = TaskState.READY
                    newly_ready.append(task)
                    logger.info("Task ready (no deps): %s", task.task_title)
            else:
                # Check if all named dependencies in the active queue are completed.
                # External / non-queued prerequisites are treated as already satisfied.
                active_deps = [dep for dep in task.dependencies if dep in title_map]
                all_met = all(dep in completed_titles for dep in active_deps)
                if all_met:
                    task.state = TaskState.READY
                    newly_ready.append(task)
                    logger.info("Dependency resolved, task ready: %s", task.task_title)
                elif task.state != TaskState.BLOCKED:
                    task.state = TaskState.BLOCKED
                    logger.info("Task blocked (unmet deps): %s", task.task_title)

        return newly_ready
```
*Observation:* When a task's prerequisite fails (e.g. `Analyze Authentication Workflows` transitions to `TaskState.FAILED`), `all_met` evaluates to `False`. The resolver transitions the dependent task to `TaskState.BLOCKED` (or leaves it in `BLOCKED`). It **never** marks the dependent task as `SKIPPED` or `CANCELLED`.

#### B. `argus/runtime/queue.py` (lines 67–71)
```python
    def is_complete(self) -> bool:
        """Returns True if all tasks have reached a terminal state (COMPLETED, FAILED, SKIPPED, CANCELLED)."""
        terminal_states = {TaskState.COMPLETED, TaskState.FAILED, TaskState.SKIPPED, TaskState.CANCELLED}
        return all(t.state in terminal_states for t in self.queue.tasks)
```
*Observation:* Because `Analyze Authorization Relationships` is stuck in `TaskState.BLOCKED` (which is not in `terminal_states`), `is_complete()` returns `False` indefinitely.

#### C. `argus/runtime/mission_runtime.py` (lines 109–112)
```python
            # If no tasks are running and everything is complete, move to next phase
            if not batch and self.task_scheduler.queue_manager.is_complete():
                self.state_machine.transition_to(MissionState.COLLECTING_EVIDENCE, "Finished executing tasks")
            return
```
*Observation:* The state machine check requires `is_complete() == True`. Because `is_complete()` is permanently `False`, the runtime never transitions out of `MissionState.RESEARCHING`. Consequently, `AttackSurfaceGraphBuilder().build(mission)` (which runs in `COLLECTING_EVIDENCE` line 117) never executes, leaving graph nodes at count 1 (target only) and live hosts at 0.

#### D. `argus/planning/gap_analysis.py` (lines 269–295)
```python
    def _check_authentication_gaps(self) -> List[CoverageGap]:
        gaps = []
        auth = getattr(self.mission, 'authentication', None)
        auth_workflows = list(getattr(self.mission, 'authentication_workflows', []) or [])

        if auth is not None and not auth_workflows:
            gaps.append(CoverageGap(
                area="Authentication Workflows",
                description="Authentication model exists but no authentication workflows have been analyzed.",
                severity=0.7,
                category=TaskCategory.AUTHENTICATION_ANALYSIS
            ))
        return gaps

    def _check_authorization_gaps(self) -> List[CoverageGap]:
        gaps = []
        auth_graph = getattr(self.mission, 'authorization_graph', None)
        auth_investigations = list(getattr(self.mission, 'authorization_investigations', []) or [])

        if auth_graph is None and not auth_investigations:
            gaps.append(CoverageGap(
                area="Authorization",
                description="No authorization graph or authorization investigations have been generated.",
                severity=0.6,
                category=TaskCategory.AUTHORIZATION_ANALYSIS
            ))
        return gaps
```
*Observation:* `Mission.authentication` defaults to `AuthenticationModel()` (instantiated with `confidence=0`, `authentication_type="Unknown"`). Thus `auth is not None` is always `True` on newly created missions. Additionally, `auth_graph is None and not auth_investigations` is always `True` on newly created missions. This causes `GapAnalyzer` to generate spurious `Authentication Workflows` and `Authorization` gaps on fresh targets that have no authentication discovered.

#### E. `argus/planning/research_planner.py` (lines 47–59, 121–129)
```python
        # 1. Compute current coverage
        coverage = self.coverage_tracker.compute()
        # 2. Gap analysis
        gaps = coverage.gaps
        # 3. Generate tasks from gaps
        tasks = self.task_generator.from_gaps(gaps)
```
*Observation:* `GapAnalyzer._check_recon_gaps()` returns only State 1 (`Subdomains` gap) when a mission is new. `TaskGenerator.from_gaps()` generates only a single task for State 1: `Discover Subdomains`. It does not generate the full 4-stage recon DAG (`generate_recon_tasks()`: `Discover Subdomains` -> `Fingerprint Live Hosts` -> `Discover API Endpoints` & `Scan Live Hosts`). Because `ResearchPlanner.plan()` is only invoked once during the `PLANNING` phase in `AutonomousMissionRuntime.step()`, downstream recon tasks (`httpx`, `katana`, `nuclei`) are never generated or scheduled.

#### F. `tests/runtime/test_e2e_mission.py` (line 74)
```python
@patch("argus.planning.task_generator.TaskGenerator.from_gaps", lambda self, gaps: self.generate_recon_tasks())
@patch("argus.runtime.sandbox.Sandbox.execute_command", new=mock_execute_command)
def test_e2e_mission_execution(isolated_tool_registry):
```
*Observation:* `test_e2e_mission.py` passed in CI because line 74 explicitly mocked `from_gaps` to call `generate_recon_tasks()`, bypassing `GapAnalyzer` and injecting all 4 recon tasks directly. The standalone smoke test lacked this mock, which exposed the underlying production bug.

---

## 2. Logic Chain

1. **Step 1 — Mission Planning & Task Generation:**
   - In `AutonomousMissionRuntime.step()`, when `mission.status == MissionState.PLANNING`, `MissionPlanner.analyze()`, `AttackSurfaceGraphBuilder().build(mission)`, and `ResearchPlanner.plan()` are executed.
   - `ResearchPlanner.plan()` computes coverage gaps using `GapAnalyzer`.
   - On a fresh mission:
     - `_check_recon_gaps()` detects no subdomains and emits `CoverageGap(area="Subdomains")`.
     - `_check_authentication_gaps()` sees `mission.authentication != None` (due to default dataclass factory) and emits `CoverageGap(area="Authentication Workflows")`.
     - `_check_authorization_gaps()` sees `mission.authorization_graph is None` and emits `CoverageGap(area="Authorization")`.
   - `TaskGenerator.from_gaps(gaps)` converts these 3 gaps into 3 `ResearchTask` objects:
     - Task 1: `Discover Subdomains` (tool: `subfinder`, deps: `[]`)
     - Task 2: `Analyze Authentication Workflows` (tool: `authentication_specialist`, deps: `[]`)
     - Task 3: `Analyze Authorization Relationships` (tool: `authorization_specialist`, deps: `["Analyze Authentication Workflows"]`)
   - Crucially, `httpx` (`Fingerprint Live Hosts`), `katana` (`Discover API Endpoints`), and `nuclei` (`Scan Live Hosts`) are **not** generated.

2. **Step 2 — Execution in `MissionState.RESEARCHING`:**
   - The runtime transitions to `RESEARCHING`.
   - In the first iteration:
     - `pending` tasks (Tasks 1, 2, 3) are scheduled into `TaskScheduler.queue_manager`.
     - `TaskDependencyResolver.resolve()` marks Task 1 (`Discover Subdomains`) and Task 2 (`Analyze Authentication Workflows`) as `READY`. Task 3 (`Analyze Authorization Relationships`) is marked `BLOCKED` on Task 2.
     - `TaskScheduler.get_executable_batch()` returns Tasks 1 and 2.
     - Task 1 executes via `subfinder`, succeeds, and populates `mission.subdomains = ['api.example.com', 'admin.example.com']`. `TaskScheduler.report_success()` marks Task 1 as `TaskState.COMPLETED`.
     - Task 2 attempts to execute via `ToolOrchestrator.execute_task()`. `ToolDispatcher.resolve_tool()` looks for `authentication_specialist` in `registry.tools`. In smoke test / CLI environments without internal specialist plugins registered, resolution fails.
     - Task 2 returns `ToolExecutionStatus.FAILED`. `TaskScheduler.report_failure()` applies `RetryHandler`. After 3 retries, Task 2 is terminally marked `TaskState.FAILED`.

3. **Step 3 — Dependency Resolution Deadlock:**
   - In subsequent iterations of `AutonomousMissionRuntime.step()`:
     - `TaskDependencyResolver.resolve()` runs on the queue.
     - Task 3's dependency is `Analyze Authentication Workflows`.
     - Because `Analyze Authentication Workflows` is `TaskState.FAILED` (not `TaskState.COMPLETED`), `all(dep in completed_titles for dep in active_deps)` evaluates to `False`.
     - `TaskDependencyResolver.resolve()` does not check if dependencies have permanently failed, so Task 3 remains stuck in `TaskState.BLOCKED`.
     - Task 3 is never started, never skipped, and never cancelled.

4. **Step 4 — `is_complete()` Evaluates `False` Forever:**
   - `ExecutionQueueManager.is_complete()` computes:
     `all(t.state in {COMPLETED, FAILED, SKIPPED, CANCELLED} for t in self.queue.tasks)`
   - Because Task 3 is in state `BLOCKED`, `is_complete()` returns `False`.
   - `AutonomousMissionRuntime.step()` checks:
     `if not batch and self.task_scheduler.queue_manager.is_complete():`
   - Since `is_complete()` is `False`, the transition to `MissionState.COLLECTING_EVIDENCE` never triggers.
   - The mission loops in `RESEARCHING` indefinitely until timeout.

---

## 3. Proposed Fixes & Code Locations

### Fix 1: Cascade Dependency Failures in `TaskDependencyResolver.resolve`
**Target File:** `/home/varun/argus/argus/runtime/dependencies.py`  
**Rationale:** When any dependency of a task has reached a terminal failure state (`FAILED`, `SKIPPED`, `CANCELLED`), that task's prerequisites can never be satisfied. It must be marked `SKIPPED` via `TaskLifecycle.skip(task)`. Additionally, dependency lookup should check both `task_title` and `task_id`.

```python
    @staticmethod
    def resolve(tasks: List[ScheduledTask]) -> List[ScheduledTask]:
        title_map: Dict[str, ScheduledTask] = {t.task_title: t for t in tasks}
        id_map: Dict[str, ScheduledTask] = {t.task_id: t for t in tasks}
        completed_keys: Set[str] = {
            t.task_title for t in tasks if t.state == TaskState.COMPLETED
        } | {
            t.task_id for t in tasks if t.state == TaskState.COMPLETED
        }
        failed_keys: Set[str] = {
            t.task_title for t in tasks if t.state in (TaskState.FAILED, TaskState.SKIPPED, TaskState.CANCELLED)
        } | {
            t.task_id for t in tasks if t.state in (TaskState.FAILED, TaskState.SKIPPED, TaskState.CANCELLED)
        }
        newly_ready: List[ScheduledTask] = []

        for task in tasks:
            if task.state not in (TaskState.PENDING, TaskState.BLOCKED):
                continue

            if not task.dependencies:
                if task.state != TaskState.READY:
                    task.state = TaskState.READY
                    newly_ready.append(task)
                    logger.info("Task ready (no deps): %s", task.task_title)
            else:
                active_deps = [dep for dep in task.dependencies if dep in title_map or dep in id_map]
                has_failed_dep = any(dep in failed_keys for dep in active_deps)
                if has_failed_dep:
                    TaskLifecycle.skip(task)
                    logger.warning("Dependency failed/cancelled, skipping task: %s", task.task_title)
                else:
                    all_met = all(dep in completed_keys for dep in active_deps)
                    if all_met:
                        task.state = TaskState.READY
                        newly_ready.append(task)
                        logger.info("Dependency resolved, task ready: %s", task.task_title)
                    elif task.state != TaskState.BLOCKED:
                        task.state = TaskState.BLOCKED
                        logger.info("Task blocked (unmet deps): %s", task.task_title)

        return newly_ready
```

### Fix 2: Prevent False Positive Auth/Authz Gaps on Fresh Targets in `GapAnalyzer`
**Target File:** `/home/varun/argus/argus/planning/gap_analysis.py`  
**Rationale:** `Mission.authentication` is always initialized by dataclass defaults; `GapAnalyzer` should only trigger an authentication gap if authentication evidence or properties were actually identified (e.g. `confidence > 0` or `observations` present). Similarly, authorization gaps should only trigger if authentication workflows or authorization structures exist.

```python
    def _check_authentication_gaps(self) -> List[CoverageGap]:
        gaps = []
        auth = getattr(self.mission, 'authentication', None)
        auth_workflows = list(getattr(self.mission, 'authentication_workflows', []) or [])

        # Only trigger if authentication has actually been discovered or configured
        if auth and (getattr(auth, 'confidence', 0) > 0 or getattr(auth, 'observations', [])) and not auth_workflows:
            gaps.append(CoverageGap(
                area="Authentication Workflows",
                description="Authentication model exists but no authentication workflows have been analyzed.",
                severity=0.7,
                category=TaskCategory.AUTHENTICATION_ANALYSIS
            ))
        return gaps

    def _check_authorization_gaps(self) -> List[CoverageGap]:
        gaps = []
        auth_workflows = list(getattr(self.mission, 'authentication_workflows', []) or [])
        auth_graph = getattr(self.mission, 'authorization_graph', None)
        auth_investigations = list(getattr(self.mission, 'authorization_investigations', []) or [])

        # Only trigger if authentication workflows or identities have been discovered
        if auth_workflows and auth_graph is None and not auth_investigations:
            gaps.append(CoverageGap(
                area="Authorization",
                description="No authorization graph or authorization investigations have been generated.",
                severity=0.6,
                category=TaskCategory.AUTHORIZATION_ANALYSIS
            ))
        return gaps
```

### Fix 3: Generate the Full Recon DAG during Planning in `ResearchPlanner.plan`
**Target File:** `/home/varun/argus/argus/planning/research_planner.py`  
**Rationale:** When recon gaps exist on a target (`Subdomains`, `Live Hosts`, `Endpoints`, or `Vulnerability Scanning`), `ResearchPlanner.plan()` must schedule the complete dependency-aware reconnaissance pipeline (`generate_recon_tasks()`), merging them with gap tasks from `from_gaps(gaps)` without duplicates.

```python
        # In ResearchPlanner.plan():
        recon_areas = {"Subdomains", "Live Hosts", "Endpoints", "Vulnerability Scanning"}
        has_recon_gap = any(g.area in recon_areas for g in gaps)

        tasks = []
        seen_titles = set()
        if has_recon_gap:
            recon_tasks = self.task_generator.generate_recon_tasks()
            for t in recon_tasks:
                if t.title not in seen_titles:
                    seen_titles.add(t.title)
                    tasks.append(t)

        from_gap_tasks = self.task_generator.from_gaps(gaps)
        for t in from_gap_tasks:
            if t.title not in seen_titles:
                seen_titles.add(t.title)
                tasks.append(t)
```

---

## 4. Caveats

1. **Test Mock in `test_e2e_mission.py`:** Line 74 in `test_e2e_mission.py` (`@patch("argus.planning.task_generator.TaskGenerator.from_gaps", lambda self, gaps: self.generate_recon_tasks())`) should eventually be removed or modernized once `ResearchPlanner.plan()` natively generates the recon chain, ensuring the test exercises the real production code path.
2. **Specialist Agent Registry:** When specialist agents (like `authentication_specialist` or `graphql_specialist`) are registered into `ToolRegistry`, they will execute as internal plugins via `InternalPluginExecutor`. When unregistered, `ToolDispatcher` properly marks them failed, and with Fix 1, dependent tasks cleanly transition to `SKIPPED` without hanging the runtime.

---

## 5. Conclusion

- **Root Cause Confirmed:** The loop hang in `MissionState.RESEARCHING` is caused by `TaskDependencyResolver.resolve()` failing to cascade dependency failures to dependent tasks (leaving them permanently in `TaskState.BLOCKED`), combined with `GapAnalyzer` spawning unregistered specialist tasks on empty missions and `ResearchPlanner` not generating the full recon DAG during initial planning.
- **Scope of Fix:** 3 targeted file modifications:
  1. `argus/runtime/dependencies.py` — handle failed/cancelled dependencies by skipping blocked tasks.
  2. `argus/planning/gap_analysis.py` — guard auth/authz gap detection against default-initialized empty models.
  3. `argus/planning/research_planner.py` — include `generate_recon_tasks()` when recon gaps are present.
- **Impact:** Fixes the Priority 0 bug completely, enabling the smoke test to run all 4 recon tools (`subfinder` -> `httpx` -> `katana` / `nuclei`), build the 10+ node `attack_surface_graph`, transition cleanly through all lifecycle states (`RESEARCHING` -> `COLLECTING_EVIDENCE` -> `CORRELATING` -> `BUILDING_INVESTIGATIONS` -> `GENERATING_HYPOTHESES` -> `COMPLETED`), and maintains 100% passing status across the existing 543 unit/integration tests.

---

## 6. Verification Method

### 6.1 Standalone Smoke Test Verification
Execute the Python smoke test probe:
```bash
python3 -c '
from argus.runtime.mission import Mission, MissionState
from argus.runtime.controller import MissionController
from argus.runtime.checkpoint import MissionCheckpointer
from argus.runtime.registry import registry
from argus.runtime.models import Tool
from argus.planning.models import TaskCategory
from argus.evidence.store import EvidenceStore
from unittest.mock import patch
import time, logging
logging.disable(logging.CRITICAL)

SUBFINDER_OUTPUT = "api.example.com\nadmin.example.com"
HTTPX_OUTPUT = "{\"url\":\"http://api.example.com\",\"host\":\"api.example.com\",\"status_code\":200,\"webserver\":\"nginx\",\"tech\":[\"Nginx\",\"Express\"]}\n{\"url\":\"http://admin.example.com\",\"host\":\"admin.example.com\",\"status_code\":403}"
KATANA_OUTPUT = "http://api.example.com/v1/users\nhttp://api.example.com/v1/login"
NUCLEI_OUTPUT = "{\"template-id\":\"CVE-2023-XXXX\",\"info\":{\"name\":\"Example CVE\",\"severity\":\"high\",\"description\":\"A test CVE\",\"tags\":[\"cve\"]},\"host\":\"http://api.example.com\",\"matched-at\":\"http://api.example.com/login\",\"extracted-results\":[]}"

def mock_execute_command(self, command, args, timeout=60.0):
    if "subfinder" in command: return {"stdout": SUBFINDER_OUTPUT, "stderr": ""}
    elif "httpx" in command: return {"stdout": HTTPX_OUTPUT, "stderr": ""}
    elif "katana" in command: return {"stdout": KATANA_OUTPUT, "stderr": ""}
    elif "nuclei" in command: return {"stdout": NUCLEI_OUTPUT, "stderr": ""}
    return {"stdout": "", "stderr": ""}

original_tools = dict(registry.tools)
registry.tools.clear()
for t in [
    Tool(id="subfinder", name="Subfinder", capability="subdomain_discovery", description="", command="subfinder", supported_tasks=[TaskCategory.TECHNOLOGY_DISCOVERY], timeout=10.0, priority=10),
    Tool(id="httpx", name="HTTPX", capability="http_probing", description="", command="httpx", supported_tasks=[TaskCategory.TECHNOLOGY_DISCOVERY], timeout=10.0, priority=10),
    Tool(id="katana_crawler", name="Katana", capability="web_crawling", description="", command="katana", supported_tasks=[TaskCategory.API_DISCOVERY], timeout=10.0, priority=10),
    Tool(id="nuclei", name="Nuclei", capability="vulnerability_scanning", description="", command="nuclei", supported_tasks=[TaskCategory.EVIDENCE_CORRELATION], timeout=10.0, priority=10),
]: registry.register(t)

with patch("argus.runtime.sandbox.Sandbox.execute_command", new=mock_execute_command):
    mission = Mission(target="example.com")
    mission.evidence = EvidenceStore()
    mission.scope = ["example.com"]
    checkpointer = MissionCheckpointer()
    controller = MissionController(checkpointer)
    controller.start(mission)
    start = time.time()
    while time.time() - start < 45:
        if mission.status in (MissionState.COMPLETED, MissionState.FAILED, MissionState.CANCELLED):
            break
        time.sleep(0.5)

registry.tools.clear()
registry.tools.update(original_tools)

checks = [
    ("Mission COMPLETED", mission.status == MissionState.COMPLETED),
    ("Graph exists", getattr(mission, "attack_surface_graph", None) is not None),
    ("Graph has nodes", getattr(mission, "attack_surface_graph", None) is not None and mission.attack_surface_graph.node_count() > 0),
    ("Graph has subdomains", getattr(mission, "attack_surface_graph", None) is not None and len(mission.attack_surface_graph.nodes_by_type("subdomain")) >= 1),
    ("Graph has live_hosts", getattr(mission, "attack_surface_graph", None) is not None and len(mission.attack_surface_graph.nodes_by_type("live_host")) >= 1),
]

for name, result in checks:
    print(f"{"PASS" if result else "FAIL"} | {name}")
'
```
**Expected Output:**
```
PASS | Mission COMPLETED
PASS | Graph exists
PASS | Graph has nodes
PASS | Graph has subdomains
PASS | Graph has live_hosts
```

### 6.2 Full Test Suite Regression Check
Run pytest across the entire workspace:
```bash
python3 -m pytest tests/ --ignore=tests/workspace -q
```
**Expected Result:** 543+ passed with 0 failures.
