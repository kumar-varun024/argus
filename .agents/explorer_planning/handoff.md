# Handoff Report: Runtime, Planning, and Gap Analysis Integration for Sprint 2

## 1. Observation

### 1.1 Baseline Test Suite Status
- Command: `python3 -m pytest tests/ --ignore=tests/workspace -x -q`
- Result: **493 passed, 2848 warnings in 13.64s** (Exit code 0).
- Zero existing regressions currently in the codebase.

### 1.2 Mission Definition and Graph Attributes (`argus/runtime/mission.py`)
- `Mission` dataclass is defined at `argus/runtime/mission.py:75-253`.
- `Mission` currently tracks recon state via typed lists and datastores:
  - `subdomains: list[str] = field(default_factory=list)` (line 94)
  - `live_hosts: list[dict] = field(default_factory=list)` (line 95)
  - `technologies: list[str] = field(default_factory=list)` (line 96)
  - `endpoints: list[dict] = field(default_factory=list)` (line 97)
  - `vulnerabilities: list[dict] = field(default_factory=list)` (line 98)
  - `evidence: EvidenceStore = field(default_factory=EvidenceStore)` (line 99)
- Graph attributes currently on `Mission`:
  - `correlation_graph: Any = None` initialized to `CorrelationGraph()` in `__post_init__` (line 128, 159).
  - `authorization_graph: 'AuthorizationGraph' = None` (line 211).
  - `mission.graph` is accessed by `KnowledgeGraphBuilder.build()` (`argus/graph/builder.py:7-10`), `KnowledgeGraphRetriever` (`argus/workspace/context/graph.py:32`), and `ReconAgent` (`argus/agents/recon.py:193`).
  - Currently, `attack_surface_graph` is **not yet explicitly defined** as a field on `Mission`.

### 1.3 Mission Runtime Loop (`argus/runtime/mission_runtime.py`)
- `AutonomousMissionRuntime.step()` (`argus/runtime/mission_runtime.py:57-179`) orchestrates lifecycle phases:
  - `MissionState.PLANNING` (lines 62-66): calls `self.mission_planner.analyze()` and `self.research_planner.plan()`, then transitions to `RESEARCHING`.
  - `MissionState.RESEARCHING` (lines 69-110): schedules pending tasks, executes via `self.tool_orchestrator.execute_task(mission, rt)`. When all tasks complete, transitions to `COLLECTING_EVIDENCE`.
  - `MissionState.COLLECTING_EVIDENCE` (lines 113-115): immediately transitions to `CORRELATING` without executing graph aggregation or synthesis.
  - `MissionState.CORRELATING` (lines 117-149): creates `Observation` instances from `mission.evidence.all()` and calls `self.correlation_engine.process_observation(obs)`.
- Tool execution in `ExternalToolExecutor.execute()` (`argus/runtime/executor.py:195-362`) parses tool outputs via `ReconParser` (`argus/runtime/parser.py`) and populates both typed mission lists (`subdomains`, `live_hosts`, `endpoints`, `vulnerabilities`, `technologies`) and `mission.evidence` (`EvidenceStore`).

### 1.4 KnowledgeGraph Structure and Query Methods (`argus/graph/graph.py`, `node.py`, `edge.py`)
- `KnowledgeGraph` (`argus/graph/graph.py:6-165`) maintains:
  - `nodes: dict[str, Node]`
  - `edges: list[Edge]`
- Existing query and mutation methods:
  - `add(node: Node) -> bool` (deduplicates by `node.id`, returns `False` if already present, line 18)
  - `get(node_id: str) -> Optional[Node]` (line 33)
  - `connect(source: str, target: str, edge_type: str, metadata: Optional[dict]) -> bool` (deduplicates by `source`, `target`, `edge_type`, line 45)
  - `all() -> list[Node]` (line 69)
  - `node_count() -> int` (line 78)
  - `edge_count() -> int` (line 87)
  - `nodes_by_type(node_type: str) -> list[Node]` (line 96)
  - `edges_from(node: Node) -> list[Edge]` (line 108)
  - `edges_to(node: Node) -> list[Edge]` (line 120)
  - `neighbors(node: Node) -> list[Node]` (line 132)
  - `summary() -> dict[str, int]` (line 150) — returns `{"Node Count": ..., "Relationship Count": ..., f"{type} Nodes": ...}`.
- Currently missing on `KnowledgeGraph`:
  - Dedicated asset count query returning counts keyed directly by node type (e.g. `{"subdomain": 2, "live_host": 2, ...}`).
  - Query for hosts with no endpoint coverage (no outgoing `HAS_ENDPOINT` edges).
  - Query for hosts with no vulnerability scan coverage (no outgoing `HAS_VULNERABILITY` edges).

### 1.5 Research Planning and Gap Analysis (`argus/planning/`)
- `ResearchPlanner.plan()` (`argus/planning/research_planner.py:44-130`) executes:
  1. `coverage = self.coverage_tracker.compute()`
  2. `gaps = coverage.gaps` (from `GapAnalyzer(self.mission).analyze()`)
  3. `tasks = self.task_generator.from_gaps(gaps)`
  4. Knowledge retrieval via `KnowledgeManager`
  5. `tasks = self.decision_engine.prioritize(tasks, coverage)`
  6. Persistence to `mission.research_tasks`, `mission.coverage`, etc.
- `GapAnalyzer._check_recon_gaps()` (`argus/planning/gap_analysis.py:51-126`):
  - State 1: No subdomains -> emits `"Subdomains"` gap (subfinder).
  - State 2: Subdomains exist, but no live hosts -> emits `"Live Hosts"` gap (httpx).
  - State 3: Live hosts exist, but no endpoints crawled -> emits `"Endpoints"` gap (katana).
  - State 4: Live hosts exist, but no vulnerability scan -> emits `"Vulnerability Scanning"` gap (nuclei).
  - Currently evaluates `endpoints` as a global list (`if not endpoints:`). It does not inspect individual host-to-endpoint coverage in a relational graph.
- `CoverageTracker.compute()` (`argus/planning/coverage.py:18-80`):
  - Measures total and covered endpoints, business objects, workflows, authentication, authorization, and technologies.

---

## 2. Logic Chain

### 2.1 Integrating `attack_surface_graph` into Mission Lifecycle
1. **Mission Dataclass Definition**:
   - `Mission` in `argus/runtime/mission.py` must have an explicit `attack_surface_graph: KnowledgeGraph = field(default_factory=KnowledgeGraph)` field.
   - In `Mission.__post_init__`, setting `self.attack_surface_graph = KnowledgeGraph()` and aliasing `self.graph = self.attack_surface_graph` ensures both `mission.attack_surface_graph` (Sprint 2 requirement) and `mission.graph` (legacy components like `KnowledgeGraphRetriever` and `ReconAgent`) point to the same graph instance.
   - `KnowledgeGraph`, `Node`, and `Edge` use standard dataclasses/dicts/lists and serialize without issue via `pickle` during `MissionCheckpointer.checkpoint()` and `recover()`.

2. **Graph Population Lifecycle in `AutonomousMissionRuntime`**:
   - When tools execute in `RESEARCHING` phase, `ExternalToolExecutor` inserts structured evidence into `mission.evidence`.
   - In `AutonomousMissionRuntime.step()`:
     - At `MissionState.COLLECTING_EVIDENCE`: invoke `AttackSurfaceGraphBuilder().build(mission)` to populate `mission.attack_surface_graph` from `mission.evidence` before transitioning to `CORRELATING`.
     - At `MissionState.PLANNING` / before `ResearchPlanner.plan()`: invoke `AttackSurfaceGraphBuilder().build(mission)` if `mission.evidence` has records, ensuring the planner always acts on a synchronized graph.
   - Because `KnowledgeGraph.add()` and `KnowledgeGraph.connect()` check for existing node IDs and `(source, target, type)` edges, graph building is strictly **idempotent** (calling `build()` multiple times produces identical node and edge counts).

3. **Node and Relationship Types Mapping**:
   - Node Types (lowercase strings):
     - `target`: `id="target:<target>"`, `type="target"`, `value="<target>"`
     - `subdomain`: `id="subdomain:<hostname>"`, `type="subdomain"`, `value="<hostname>"`
     - `live_host`: `id="live_host:<url>"`, `type="live_host"`, `value="<url>"`, `metadata={"status": ..., "server": ...}`
     - `endpoint`: `id="endpoint:<url>"`, `type="endpoint"`, `value="<url>"`, `metadata={"path": ..., "method": ...}`
     - `technology`: `id="technology:<name>"`, `type="technology"`, `value="<name>"`
     - `vulnerability`: `id="vulnerability:<template_id_or_name>"`, `type="vulnerability"`, `value="<name>"`, `metadata={"severity": ...}`
   - Relationship Types:
     - `RESOLVES_TO`: `target` -> `subdomain`
     - `HOSTS`: `subdomain` -> `live_host`
     - `HAS_ENDPOINT`: `live_host` -> `endpoint`
     - `RUNS_TECHNOLOGY`: `live_host` -> `technology`
     - `HAS_VULNERABILITY`: `live_host` -> `vulnerability`

### 2.2 Graph Queries for Planning and Gap Analysis
1. **Query (a): Hosts with no endpoint coverage**:
   - `live_hosts = graph.nodes_by_type("live_host")`
   - Hosts lacking endpoint coverage are those where `not any(e.type == "HAS_ENDPOINT" for e in graph.edges_from(h))`.
   - Method on `KnowledgeGraph`: `get_hosts_without_endpoints() -> list[Node]`.

2. **Query (b): Hosts with no vulnerability scan coverage**:
   - `live_hosts = graph.nodes_by_type("live_host")`
   - Hosts lacking vulnerability scan coverage are those where `not any(e.type == "HAS_VULNERABILITY" for e in graph.edges_from(h))`.
   - Method on `KnowledgeGraph`: `get_hosts_without_vulnerabilities() -> list[Node]`.

3. **Query (c): Asset counts by type (Summary query)**:
   - Returns a dictionary mapping node type to integer count: `{"target": 1, "subdomain": 2, "live_host": 2, "endpoint": 3, "technology": 1, "vulnerability": 1}`.
   - Method on `KnowledgeGraph`: `get_asset_counts() -> dict[str, int]` or `asset_counts() -> dict[str, int]`.
   - Existing `summary()` method remains intact for backward compatibility.

4. **Integration into `GapAnalyzer` and `CoverageTracker`**:
   - In `GapAnalyzer._check_recon_gaps()`:
     - If `mission.attack_surface_graph` is populated with `live_host` nodes:
       - Query `get_hosts_without_endpoints()`: if uncrawled hosts exist, emit `CoverageGap(area="Endpoints", category=TaskCategory.API_DISCOVERY, related_assets=[h.value for h in uncrawled_hosts])`.
       - Query `get_hosts_without_vulnerabilities()`: if unscanned hosts exist and `not self._has_vulnerability_scan()`, emit `CoverageGap(area="Vulnerability Scanning", category=TaskCategory.EVIDENCE_CORRELATION, related_assets=[h.value for h in unscanned_hosts])`.
     - If `mission.attack_surface_graph` has no nodes (fallback mode), fall back to inspecting `mission.subdomains`, `mission.live_hosts`, `mission.endpoints`, and `mission.evidence` lists directly.
   - In `TaskGenerator.from_gaps()`:
     - When `CoverageGap` contains specific `related_assets` (the uncrawled/unscanned hosts), `task.required_inputs` is automatically set to those specific host URLs, allowing targeted crawling and scanning per host.

### 2.3 Backward Compatibility Architecture
1. **Dual-Mode Gap Analysis**:
   - Existing test fixtures (e.g. `tests/planning/test_recon_task_generation.py`, `tests/planning/test_research_planner.py`) construct `Mission` instances with list attributes (`subdomains = [...]`, `live_hosts = [...]`) without building a graph.
   - By falling back to list inspections when `attack_surface_graph` has no nodes, 100% of existing tests continue to pass with zero modifications.
2. **KnowledgeGraph Interface Stability**:
   - All existing methods (`add`, `get`, `connect`, `all`, `node_count`, `edge_count`, `nodes_by_type`, `edges_from`, `edges_to`, `neighbors`, `summary`) retain exact signatures and behavior.
   - New queries are purely additive.
3. **Mission Lifecycle Non-Interference**:
   - Adding graph construction in `AutonomousMissionRuntime` during `COLLECTING_EVIDENCE` does not alter state machine transitions or task scheduler operation.
   - `tests/runtime/test_e2e_mission.py` continues to execute to completion (`mission.status == COMPLETED`).

---

## 3. Caveats

1. **Host-to-Subdomain Resolution Heuristics**:
   - When evidence contains a live host URL (e.g. `http://api.example.com`) and subdomains (e.g. `api.example.com`), the builder matches hostnames via `urllib.parse.urlparse(url).hostname`. If a live host is an IP address or does not match an enumerated subdomain, the builder should link the live host node directly to the target node via `HOSTS` to maintain graph connectedness.
2. **Nuclei Zero-Finding Scans**:
   - If Nuclei scans a host and discovers zero vulnerabilities, no `vulnerability` evidence is generated, so no `HAS_VULNERABILITY` edge is added. `GapAnalyzer` must continue to check `_has_vulnerability_scan()` (inspecting `mission.tool_runs`, `mission.execution_history`, and `mission.task_states`) so it does not endlessly schedule Nuclei scans for clean hosts.
3. **Multi-Agent File Ownership**:
   - This investigation is read-only. Proposed code changes must be applied by the designated implementation subagent.

---

## 4. Conclusion

1. **Mission Attribute & Lifecycle Integration**:
   - Add `attack_surface_graph: KnowledgeGraph = field(default_factory=KnowledgeGraph)` to `Mission` in `argus/runtime/mission.py`, aliasing `mission.graph = self.attack_surface_graph` in `__post_init__`.
   - Update `AutonomousMissionRuntime.step()` in `argus/runtime/mission_runtime.py` to invoke `AttackSurfaceGraphBuilder().build(mission)` during `COLLECTING_EVIDENCE` and before planning in `PLANNING`.
2. **Graph Query Implementation**:
   - Implement `get_hosts_without_endpoints() -> list[Node]`, `get_hosts_without_vulnerabilities() -> list[Node]`, and `get_asset_counts() -> dict[str, int]` on `KnowledgeGraph` (or via a graph query helper).
3. **Planning & Gap Analysis Wiring**:
   - Update `GapAnalyzer._check_recon_gaps()` in `argus/planning/gap_analysis.py` to use graph queries for granular host-level endpoint and vulnerability gap detection, with automatic fallback to list attributes for bare missions.
   - Update `CoverageTracker` in `argus/planning/coverage.py` to utilize graph asset counts.
4. **Zero Regression Strategy**:
   - Dual-mode evaluation ensures that all 493 existing tests remain green, while providing graph-powered capabilities when the attack-surface graph is populated.

---

## 5. Verification Method

### 5.1 Test Execution Commands
1. Run baseline regression test:
   ```bash
   python3 -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   *Expected*: All 493+ tests pass.
2. Run planning specific tests:
   ```bash
   python3 -m pytest tests/planning/test_recon_task_generation.py tests/planning/test_research_planner.py -v
   ```
   *Expected*: All 26 recon generation tests and all ResearchPlanner tests pass.
3. Run E2E mission execution test:
   ```bash
   python3 -m pytest tests/runtime/test_e2e_mission.py -v
   ```
   *Expected*: Test passes with `mission.status == COMPLETED`.
4. Run graph unit tests:
   ```bash
   python3 -m pytest tests/test_graph_root.py tests/workspace/test_graph_retrieval.py -v
   ```
   *Expected*: All existing graph tests pass.

### 5.2 Specific Code Verification Checklist
- [ ] `getattr(mission, "attack_surface_graph", None)` is an instance of `KnowledgeGraph`.
- [ ] `mission.attack_surface_graph.get_asset_counts()` returns exact dict mapping of asset types to counts.
- [ ] `mission.attack_surface_graph.get_hosts_without_endpoints()` returns only live host nodes without `HAS_ENDPOINT` edges.
- [ ] `mission.attack_surface_graph.get_hosts_without_vulnerabilities()` returns only live host nodes without `HAS_VULNERABILITY` edges.
- [ ] `GapAnalyzer(mission).analyze()` correctly populates `CoverageGap.related_assets` with uncrawled/unscanned hosts when the graph is populated.
- [ ] `GapAnalyzer(mission).analyze()` succeeds without error when `mission.attack_surface_graph` is empty (fallback mode).

### 5.3 Invalidation Conditions
- Any change that alters the signature or return type of existing `KnowledgeGraph` methods (`summary()`, `add()`, `connect()`, `nodes_by_type()`).
- Any change that causes `GapAnalyzer` or `CoverageTracker` to raise an `AttributeError` or `TypeError` on bare `Mission` objects lacking graph nodes.
- Any change that breaks pickle serialization of `Mission` in `MissionCheckpointer`.
