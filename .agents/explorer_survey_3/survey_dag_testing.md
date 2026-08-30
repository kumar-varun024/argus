# Sprint 5 Architecture & Testing Survey: DAG Orchestration, Task Execution, and Test Suite Conventions

**Survey Date**: 2026-08-28  
**Surveyed By**: Explorer Subagent (explorer_survey_3)  
**Target Milestone**: Sprint 5 — Information Disclosure Engine (Phase 6 Roadmap)  

---

## 1. Executive Summary

This survey provides a comprehensive architectural analysis of the ARGUS planning subsystem (`argus/planning/`), runtime execution engine (`argus/runtime/`), attack surface graph (`argus/graph/`), and test suite conventions (`tests/`). 

### Core Findings:
1. **DAG Orchestration (`argus/planning/task_generator.py`)**:
   - Recon tasks are generated via `TaskGenerator.generate_recon_tasks()` and `TaskGenerator.from_gaps()`.
   - The current recon chain executes in 4 stages: `subfinder` (Priority 0.95) $\to$ `httpx` (Priority 0.90, depends on Subdomains) $\to$ `katana_crawler` (Priority 0.85, depends on Live Hosts) & `nuclei` (Priority 0.80, depends on Live Hosts).
   - The new **Information Disclosure vulnerability discovery task** should be slotted right after live host fingerprinting and endpoint discovery with priority **0.82** (or **0.78**), depending on `["Fingerprint Live Hosts"]` (and optionally consuming discovered endpoints).
2. **Task Execution Engine (`argus/runtime/`)**:
   - `AutonomousMissionRuntime.step()` manages the loop in `MissionState.RESEARCHING`.
   - `TaskScheduler` (`argus/runtime/executor.py`) determines topological readiness (`READY` batch) using `ExecutionQueueManager`.
   - `ToolOrchestrator` (`argus/runtime/orchestrator.py`) dispatches tasks via `ToolDispatcher` (`argus/runtime/dispatcher.py`), resolving `task.metadata["tool_id"]` from `ToolRegistry` (`argus/runtime/registry.py`).
   - Internal collectors execute via `InternalPluginExecutor` / `PluginExecutorAdapter` (or direct collector invocation) using `AuthenticatedHttpClient` (`argus/http/client.py`).
3. **Test Suite Conventions (`tests/`)**:
   - There is **no root `tests/conftest.py`** file (only `tests/workspace/conftest.py`, which is ignored during core runs).
   - Test files declare custom modular fixtures locally (e.g. lightweight local `HTTPServer` on dynamic sockets `find_free_port()`, mock mission instances, isolated tool registries).
   - Collector tests (e.g., `tests/test_subdomain_takeover.py`) follow a clean pattern: mock I/O, execute `collector.collect(mission)`, and assert on returned `Evidence`, `mission.evidence`, `mission.vulnerabilities`, and `mission.attack_surface_graph`.
4. **Baseline Verification**:
   - Command: `python -m pytest tests/ --ignore=tests/workspace -x -q`
   - Test count: **646 passed** across 113 test files (0 failures, 12,531 deprecation warnings, execution time ~16.8s).

---

## 2. Focus Area 1: Planning & DAG Orchestration Subsystem

### 2.1 Task Creation, Prioritization, and Dependencies in `argus/planning/`

The planning subsystem is divided into two primary planners:
- **`MissionPlanner` (`argus/planning/planner.py:7-63`)**: Generates the static, high-level `ResearchPlan` at mission creation based on detected technologies. Uses builders from `argus/planning/steps.py`.
- **`ResearchPlanner` (`argus/planning/research_planner.py:25-156`)**: The dynamic, state-aware planner that continuously evaluates coverage and gaps during mission execution, converting `CoverageGap` instances into prioritized `ResearchTask` objects via `TaskGenerator`.

#### Current Recon Task Templates in `argus/planning/task_generator.py:13-62`:
```python
_RECON_TEMPLATES = {
    "subfinder": {
        "title": "Discover Subdomains",
        "goal": "Enumerate all subdomains in scope for the target.",
        "category": TaskCategory.TECHNOLOGY_DISCOVERY,
        "required_inputs": ["target"],
        "expected_outputs": ["subdomains"],
        "dependencies": [],
        "required_specialists": [],
        "metadata": {"tool_id": "subfinder"},
        "estimated_duration_minutes": 5,
        "priority": 0.95,
    },
    "httpx": {
        "title": "Fingerprint Live Hosts",
        "goal": "Probe subdomains to discover live HTTP/HTTPS hosts and fingerprint technologies.",
        "category": TaskCategory.TECHNOLOGY_DISCOVERY,
        "required_inputs": ["subdomains"],
        "expected_outputs": ["live_hosts", "technologies"],
        "dependencies": ["Discover Subdomains"],
        "required_specialists": [],
        "metadata": {"tool_id": "httpx"},
        "estimated_duration_minutes": 5,
        "priority": 0.90,
    },
    "katana_crawler": {
        "title": "Discover API Endpoints",
        "goal": "Enumerate and crawl endpoints on live hosts.",
        "category": TaskCategory.API_DISCOVERY,
        "required_inputs": ["live_hosts"],
        "expected_outputs": ["endpoints"],
        "dependencies": ["Fingerprint Live Hosts"],
        "required_specialists": [],
        "metadata": {"tool_id": "katana_crawler"},
        "estimated_duration_minutes": 10,
        "priority": 0.85,
    },
    "nuclei": {
        "title": "Scan Live Hosts",
        "goal": "Run automated vulnerability templates against live hosts.",
        "category": TaskCategory.EVIDENCE_CORRELATION,
        "required_inputs": ["live_hosts"],
        "expected_outputs": ["vulnerabilities", "observations"],
        "dependencies": ["Fingerprint Live Hosts"],
        "required_specialists": [],
        "metadata": {"tool_id": "nuclei"},
        "estimated_duration_minutes": 15,
        "priority": 0.80,
    },
}
```

### 2.2 Where to Insert the Information Disclosure Task

The Information Disclosure task fits squarely in the active vulnerability discovery stage following live host identification.

#### Recommended Task Specification:
- **Template Key**: `"info_disclosure"` or `"information_disclosure"`
- **Title**: `"Scan Information Disclosure"` (or `"Discover Exposed Sensitive Files"`)
- **Goal**: `"Probe live hosts and discovered endpoints for exposed sensitive files, credentials, configurations, and internal infrastructure hostnames."`
- **Category**: `TaskCategory.EVIDENCE_CORRELATION` (or `TaskCategory.TECHNOLOGY_DISCOVERY` / `TaskCategory.API_DISCOVERY`)
- **Required Inputs**: `["live_hosts"]` (with fallback to `["endpoints"]` / `["target"]`)
- **Expected Outputs**: `["exposed_files", "secrets", "vulnerabilities", "observations"]`
- **Dependencies**: `["Fingerprint Live Hosts"]`
- **Priority**: `0.82` (Higher than general template scanning `nuclei` at 0.80, parallel with endpoint crawling `katana_crawler` at 0.85)
- **Metadata**: `{"tool_id": "info_disclosure"}`

#### Modifications Needed in Planning Modules:
1. **`argus/planning/task_generator.py`**:
   - Add `"info_disclosure"` to `_RECON_TEMPLATES`.
   - Update `generate_recon_tasks()` to instantiate and append the `ResearchTask` for Information Disclosure.
   - Update `_resolve_template_for_gap()` to handle `area_lower in ("information disclosure", "exposed files", "sensitive files", "secrets")`.
   - Update `from_gaps()` to wire `host_inputs` when `tool_id == "info_disclosure"`.
2. **`argus/planning/gap_analysis.py`**:
   - In `_check_recon_gaps()`: When live hosts exist, check if an information disclosure scan has been conducted.
   - Add `_has_information_disclosure_scan()` helper (checking `mission.vulnerabilities`, `mission.evidence` where `category == "information_disclosure"`, `mission.tool_runs`, `mission.execution_history`, and task states).
   - If not scanned, emit `CoverageGap(area="Information Disclosure", description="Live hosts discovered but sensitive files and information disclosure probing has not been performed.", severity=0.82, category=TaskCategory.EVIDENCE_CORRELATION, related_assets=host_assets)`.
3. **`argus/planning/steps.py` & `argus/planning/planner.py`** (Static Mission Plan):
   - Add `build_probe_information_disclosure_step()` in `steps.py` with `dependencies=["Discover Technologies"]` (or `["Discover APIs"]`).
   - Add to `ALL_STEPS_BUILDERS` so it participates in the initial static plan DAG.

---

## 3. Focus Area 2: Runtime Execution Engine & Orchestration

### 3.1 End-to-End Execution Flow for Tasks

When `AutonomousMissionRuntime` (`argus/runtime/mission_runtime.py:23-259`) runs:
1. **Scheduling**:
   - `AutonomousMissionRuntime.step()` inspects `mission.research_tasks`.
   - Any `ResearchTask` with `status == "PENDING"` is passed to `task_scheduler.schedule_tasks(pending)`.
   - `TaskScheduler` (`argus/runtime/executor.py:27-140`) converts them to `ScheduledTask` instances and queues them in `ExecutionQueueManager` (`argus/runtime/queue.py`).
2. **Topological Batch Retrieval**:
   - `task_scheduler.get_executable_batch()` inspects dependency graphs.
   - Tasks whose dependencies are satisfied transition to `TaskState.READY`, are marked `TaskState.RUNNING`, and returned as an execution batch.
3. **Tool Dispatch & Execution**:
   - For each scheduled task in the batch, `tool_orchestrator.execute_task(mission, rt)` is called (`argus/runtime/orchestrator.py:39-130`).
   - `ToolDispatcher.resolve_tool(task)` (`argus/runtime/dispatcher.py:16-64`):
     1. Checks `task.metadata.get("tool_id")` first $\to$ matches `"info_disclosure"` in `registry`.
     2. Checks `task.required_specialists`.
     3. Fallback: `registry.find_compatible_tools(category)`.
   - `ToolExecutionContext` is assembled with `mission`, `scope`, `policy`, `task`, `evidence_store`, etc.
   - `ToolDispatcher.dispatch(tool, context)` validates safety via `SafetyValidator.validate(tool, context)` and selects executor.
4. **Tool Registration in `argus/runtime/registry.py`**:
   - Register `Tool`:
     ```python
     registry.register(
         Tool(
             id="info_disclosure",
             name="Information Disclosure Collector",
             capability="information_disclosure_detector",
             description="Actively probes live hosts and endpoints for exposed sensitive files (.git, .env, actuator, phpinfo, source maps) and extracts secrets and internal hostnames.",
             supported_tasks=["Information Disclosure", "Evidence Correlation", "API Discovery", "Technology Discovery"],
             required_inputs=["live_hosts"],
             produced_outputs=["vulnerabilities", "observations", "evidence"],
             capabilities=["information_disclosure_detector"],
             safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
             timeout=300.0,
             priority=95,
         )
     )
     ```
5. **Collector Integration Options**:
   - **Option A (Internal Plugin / Specialist)**: `PluginExecutorAdapter` (`argus/runtime/plugins.py:65-92`) invokes `InformationDisclosureCollector` when `tool.id == "info_disclosure"`.
   - **Option B (Direct Collector Invocation in Executor Adapter)**: Adapt `InternalPluginExecutor` / `PluginExecutorAdapter` to run `InformationDisclosureCollector().collect(mission)`.
   - When executed, `InformationDisclosureCollector` uses `AuthenticatedHttpClient` (`argus/http/client.py`) to perform HTTP GET requests against high-value target paths.

### 3.2 Graph Connectivity and Attack Surface Feedback Loop

A crucial requirement is feeding extracted internal hostnames back into the platform:
1. When `InformationDisclosureCollector` discovers an exposed `.env`, `.git/config`, or `/actuator/env`, it parses response bodies with regex/parsers:
   - **API Keys / Secrets**: AWS (`AKIA...`), Slack (`xoxb-...`), GitHub (`ghp_...`), JWTs, database passwords (`DB_PASSWORD=...`), etc.
   - **Internal Hostnames / Domains**: Extracts matches like `*.internal`, `*.corp.local`, `*.staging.example.com`, `http://db-internal:5432`, `redis://cache.prod.internal:6379`.
2. **Graph and Mission Population**:
   - Add new subdomains to `mission.subdomains`:
     ```python
     if internal_domain not in mission.subdomains:
         mission.subdomains.append(internal_domain)
     ```
   - Connect in `KnowledgeGraph` (`mission.attack_surface_graph` / `mission.graph`):
     ```python
     sub_id = f"subdomain:{internal_domain}"
     vuln_id = f"vulnerability:info-disclosure:{target_host}:{file_path}"
     graph.add(Node(id=sub_id, type="subdomain", value=internal_domain, metadata={"source": "info_disclosure", "discovered_from": file_path}))
     graph.add(Node(id=vuln_id, type="vulnerability", value="Information Disclosure", metadata=ev.metadata))
     graph.connect(f"live_host:{target_host}", vuln_id, edge_type="HAS_VULNERABILITY")
     graph.connect(vuln_id, sub_id, edge_type="REVEALS_HOST")
     ```
   - On the next planning iteration, `GapAnalyzer` detects newly added subdomains and triggers subsequent reconnaissance on those discovered internal assets!

---

## 4. Focus Area 3: Test Suite Architecture, Conventions & Fixtures

### 4.1 Survey of Existing Collector and Integration Tests

The test suite in `tests/` contains high-standard unit and integration tests across multiple domains. Key examples:

#### 1. Collector Unit Tests: `tests/test_subdomain_takeover.py:1-215`
- Pattern:
  - Instantiates `mission = Mission(target="example.com")`
  - Populates `mission.subdomains = ["pages.example.com"]`
  - Injects mock tools/dependencies (e.g. `mock_dns = MagicMock(spec=DNSXTool)`, `collector._probe_http = MagicMock(...)`)
  - Calls `evidence = collector.collect(mission)`
  - Asserts on `len(evidence)`, `evidence[0].category == "subdomain_takeover"`, `evidence[0].severity == "critical"`, `mission.vulnerabilities`, and graph nodes/edges.

#### 2. HTTP Client Tests: `tests/http/test_authenticated_http_client.py:1-246`
- Pattern:
  - Uses `MockAuthHttpHandler` on a dynamic background `HTTPServer` (`find_free_port()`).
  - Tests `AuthenticatedHttpClient` with context managers:
    ```python
    with AuthenticatedHttpClient(identity=ident) as client:
        resp = client.get(auth_mission, f"{mock_auth_server}/protected")
    ```
  - Validates scope boundaries (`ScopeState.IN_SCOPE` vs `ScopeState.OUT_OF_SCOPE`), automatic bearer/API-key/cookie injection, and automated login flows.

#### 3. Planning & Recon DAG Tests: `tests/planning/test_recon_task_generation.py:1-475`
- Pattern:
  - `TestExplicitDispatcherRouting`: Validates `ToolDispatcher.resolve_tool()` resolves each `tool_id` deterministically.
  - `TestReconStateGapAnalyzer`: Sets up mission states (no subdomains, subdomains without live hosts, live hosts without endpoints, completed recon) and tests emitted `CoverageGap` areas.
  - `TestConcreteReconTaskGeneration`: Validates `TaskGenerator.generate_recon_tasks()` and `from_gaps()`.
  - `TestReconTaskExecutionOrder`: Simulates `TaskScheduler` execution batches (`batch1` $\to$ report success $\to$ `batch2` $\to$ report success $\to$ `batch3`).

#### 4. End-to-End Mission Tests: `tests/runtime/test_e2e_mission.py:1-182`
- Pattern:
  - Patches `Sandbox.execute_command` with mock tool stdout outputs (`SUBFINDER_OUTPUT`, `HTTPX_OUTPUT`, `KATANA_OUTPUT`, `NUCLEI_OUTPUT`).
  - Launches `MissionController(checkpointer).start(mission)`.
  - Waits for `MissionState.COMPLETED`.
  - Asserts structured evidence categories, attack surface graph nodes (`subdomain`, `live_host`), correlations, investigations, and hypotheses.

### 4.2 Fixture Audit in `tests/conftest.py`

- **Global `tests/conftest.py`**: **Does NOT exist** at the root of `tests/`.
- **`tests/workspace/conftest.py`**: Exists but is scoped strictly to workspace API tests and ignored via `--ignore=tests/workspace`. It sets `ARGUS_LLM_PROVIDER="mock"` and isolates workspace directory to `tmp_path`.
- **Modularity Convention**: Test modules define their own pytest fixtures locally at module level (using `@pytest.fixture` or `@pytest.fixture(scope="module")`), e.g.:
  - `mock_auth_server` in `tests/http/test_authenticated_http_client.py`
  - `auth_mission` in `tests/http/test_authenticated_http_client.py`
  - `isolated_tool_registry` in `tests/runtime/test_e2e_mission.py`
  - `bare_mission`, `partial_mission`, `mission_with_observations` in `tests/planning/test_research_planner.py`

### 4.3 Target Test Plan for Sprint 5 (Minimum 10 New Tests)

To satisfy Sprint 5 Acceptance Criteria, the following tests should be implemented:

| Test File | Test Case | Scope & Verification |
|---|---|---|
| `tests/collectors/test_information_disclosure.py` | `test_collector_dotenv_file_discovered_and_secrets_extracted` | Probes `/.env`, receives 200 with `DB_PASSWORD=secret123`, `AWS_SECRET_KEY=...`, emits `Evidence(category="information_disclosure", severity="high")`. |
| `tests/collectors/test_information_disclosure.py` | `test_collector_git_config_discovered` | Probes `/.git/config`, extracts remote repository URLs and internal hostnames. |
| `tests/collectors/test_information_disclosure.py` | `test_collector_actuator_env_discovered` | Probes `/actuator/env` and `/actuator/heapdump`, extracts sensitive environment properties. |
| `tests/collectors/test_information_disclosure.py` | `test_collector_phpinfo_discovered` | Probes `/phpinfo.php`, extracts server version, internal paths, and environment vars. |
| `tests/collectors/test_information_disclosure.py` | `test_collector_source_map_discovered` | Probes `/.js.map` files, extracts internal route structures and source references. |
| `tests/collectors/test_information_disclosure.py` | `test_collector_ignores_404_and_non_200_responses` | Returns 404/403/500, verifies zero false positive evidence emitted. |
| `tests/collectors/test_information_disclosure.py` | `test_secret_extractor_regex_patterns` | Unit test verifying regex extraction for API keys, AWS tokens, JWTs, DB connection strings, and passwords. |
| `tests/collectors/test_information_disclosure.py` | `test_internal_hostname_extraction_and_subdomain_expansion` | Verifies discovered hostnames (e.g. `db.internal.corp`) are appended to `mission.subdomains` and graph. |
| `tests/planning/test_info_disclosure_task_generation.py` | `test_dag_task_generator_creates_info_disclosure_task` | Verifies `TaskGenerator.generate_recon_tasks()` and `from_gaps()` include information disclosure task with priority 0.82 and `tool_id="info_disclosure"`. |
| `tests/planning/test_info_disclosure_task_generation.py` | `test_gap_analyzer_emits_info_disclosure_gap` | Verifies `GapAnalyzer` emits Information Disclosure gap when live hosts exist without prior scan. |
| `tests/runtime/test_e2e_info_disclosure.py` | `test_e2e_information_disclosure_flow_with_graph_loop` | E2E integration test: Mock HTTP responses for `.env`, verify collector execution, Evidence generation, and graph feedback loop expansion. |

---

## 5. Focus Area 4: Test Suite Baseline & Category Inventory

### 5.1 Pytest Execution Baseline
- **Command**: `python -m pytest tests/ --ignore=tests/workspace -x -q`
- **Result**:
  ```
  646 passed, 12531 warnings in 16.81s
  ```
- **Exit Code**: `0` (Clean pass across the entire workspace)
- **Deprecation Warnings**: 12,531 warnings primarily related to `datetime.datetime.utcnow()` deprecation in Python 3.13 and Pydantic V2 `ConfigDict` migrations.

### 5.2 Category Breakdown of Existing Tests

| Category / Directory | Test File Count | Key Components Tested |
|---|---|---|
| `tests/authorization/` | 2 | Authorization gate (`can_execute_action`), Scope resolver (`check_scope`) |
| `tests/benchmark/` | 21 | Benchmark datasets, ground truth engine, leaderboard comparisons, scoring, pipeline runner |
| `tests/correlation/` | 16 | Observation correlation engine, evidence deduplication, fusion engine, correlation graph, scoring rules |
| `tests/evidence/` | 1 | Evidence models, EvidenceStore CRUD, provenance tracking |
| `tests/explain/` | 1 | Explainability engine, reasoning chains, explanation graph |
| `tests/graph/` | 7 | AttackSurfaceGraphBuilder, KnowledgeGraph, graph queries, takeover graph, diffing |
| `tests/http/` | 3 | AuthenticatedHttpClient, AuthorizedHttpClient, scope enforcement, session cookies |
| `tests/hypothesis/` | 9 | HypothesisEngine, lifecycle, generator, ranking, confidence scoring |
| `tests/investigation/` | 6 | InvestigationBuilder, PriorityEngine, manual validation, graph investigations |
| `tests/learning/` | 9 | LearningEngine, feedback loop, recommendations, pattern extraction |
| `tests/orchestration/` | 1 | ToolOrchestrator, event bus, workflow execution |
| `tests/performance/` | 1 | Object cache, latency benchmarks |
| `tests/planning/` | 3 | MissionPlanner, ResearchPlanner, TaskGenerator, recon task generation |
| `tests/plugins/` | 10 | GraphQL plugin, JavaScript plugin, schema analyzer, HTTP plugin integration |
| `tests/runtime/` | 7 | Recon parsers (Subfinder, HTTPX, Katana, Nuclei), TaskScheduler, MissionRuntime, E2E mission |
| Root test files (`tests/test_*.py`) | 19 | Subdomain takeover collector, agents, runtime lifecycle, knowledge manager, test identity, DNSX |
| `tests/workspace/` (Ignored) | 21 | Workspace API, copilot, project repos (ignored by project convention) |
| **Total Active** | **113 files** | **646 passing unit and integration tests** |

---

## 6. Implementation Recommendations & Blueprint for Sprint 5

### 6.1 Component Architecture

```
                               ┌─────────────────────────────────────────┐
                               │       TaskGenerator / GapAnalyzer       │
                               │  - Generates "Scan Information Discl."  │
                               │  - Priority: 0.82 | tool_id: info_discl.│
                               └────────────────────┬────────────────────┘
                                                    │
                                                    ▼
                               ┌─────────────────────────────────────────┐
                               │            TaskScheduler                │
                               │  - Orders after "Fingerprint Live Hosts"│
                               └────────────────────┬────────────────────┘
                                                    │
                                                    ▼
                               ┌─────────────────────────────────────────┐
                               │           ToolOrchestrator              │
                               │  - Resolves to InformationDisclosure-   │
                               │    Collector via ToolRegistry           │
                               └────────────────────┬────────────────────┘
                                                    │
                                                    ▼
                        ┌───────────────────────────────────────────────────────┐
                        │            InformationDisclosureCollector             │
                        │  - Ingests live_hosts & endpoints                     │
                        │  - Probes Wordlist (.git/config, .env, phpinfo, etc.) │
                        │  - Uses AuthenticatedHttpClient (in-scope only)       │
                        └───────────────┬───────────────────────┬───────────────┘
                                        │                       │
                                        ▼ (HTTP 200)            ▼ (Discovered Hostnames)
             ┌─────────────────────────────────────────┐   ┌────────────────────────────────┐
             │       Secret & Artifact Extractor       │   │     Attack Surface Expansion   │
             │  - Extracts API keys, DB credentials    │   │  - Appends to mission.subdomain│
             │  - Emits Evidence(category="information_│   │  - Connects Node in Graph:     │
             │    disclosure", severity="high")        │   │    live_host -> HAS_VULN ->    │
             │  - Appends to mission.vulnerabilities   │   │    REVEALS_HOST -> subdomain   │
             └─────────────────────────────────────────┘   └────────────────────────────────┘
```

### 6.2 Wordlist & Target Signatures (`argus/recon/disclosure_signatures.py` or `argus/collectors/disclosure.py`)
- `.env`, `.env.local`, `.env.production`, `.env.bak`
- `.git/config`, `.git/HEAD`
- `phpinfo.php`, `info.php`
- `.js.map` (Source map references)
- `/actuator/env`, `/actuator/heapdump`, `/actuator/configprops`
- `docker-compose.yml`, `config.json`, `web.config`

### 6.3 Secret & Hostname Extraction Patterns
- Regex patterns for API keys (AWS `AKIA...`, Google `AIza...`, Stripe `sk_live_...`, GitHub `ghp_...`, Slack `xoxb-...`)
- Regex patterns for passwords/credentials (`(DB_PASSWORD|PASSWORD|SECRET_KEY|API_KEY)=([^\s]+)`)
- Regex patterns for internal domains/hostnames (`[a-zA-Z0-9_-]+\.(internal|corp\.local|local|lan|staging\.[a-zA-Z0-9.-]+)`)

### 6.4 Zero-Regression Assurance
- Ensure all existing **646 tests** pass uninterrupted.
- Add comprehensive unit tests in `tests/collectors/test_information_disclosure.py` and `tests/planning/test_info_disclosure_task_generation.py`.
- Add integration E2E test in `tests/runtime/test_e2e_info_disclosure.py`.

