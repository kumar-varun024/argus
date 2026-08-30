# Correlation Engine & Graph Integration Investigation (Requirement R1)

## 1. Observation

### Current Implementation & Code Locations

1. **`CorrelationEngine` (`argus/correlation/engine.py:21-29, 30-75`):**
   ```python
   def __init__(self, observation_registry: ObservationRegistry, 
                correlation_registry: CorrelationRegistry, 
                graph: CorrelationGraph):
       self.obs_registry = observation_registry
       self.corr_registry = correlation_registry
       self.graph = graph
       self.matcher = CorrelationMatcher()
       self.scorer = CorrelationScorer(self.obs_registry)
   ```
   - `CorrelationEngine.__init__` accepts `graph: CorrelationGraph` (which is an internal NetworkX representation for tracking `Observation` and `Correlation` relationships).
   - It does NOT accept or hold a reference to `KnowledgeGraph` or `mission.attack_surface_graph`.
   - `CorrelationEngine.process_observation()` delegates matching to `self.matcher.find_matches(new_obs, existing_obs)` without passing any graph context.

2. **`CorrelationMatcher` (`argus/correlation/matcher.py:8-25`):**
   ```python
   class CorrelationMatcher:
       def __init__(self, rules: List[Tuple[str, callable]] = None):
           self.rules = rules or DEFAULT_RULES

       def find_matches(self, obs1: Observation, obs2: Observation) -> List[str]:
           matched_rules = []
           for rule_name, rule_func in self.rules:
               try:
                   if rule_func(obs1, obs2):
                       matched_rules.append(rule_name)
               except Exception:
                   pass
           return matched_rules
   ```
   - `CorrelationMatcher` only iterates over `(rule_name, rule_func)` and invokes `rule_func(obs1, obs2)` with 2 arguments.
   - It holds no reference to `KnowledgeGraph`.

3. **`match_shared_graph_nodes` (`argus/correlation/rules.py:33-36`):**
   ```python
   def match_shared_graph_nodes(obs1: Observation, obs2: Observation) -> bool:
       if not obs1.graph_nodes or not obs2.graph_nodes:
           return False
       return bool(set(obs1.graph_nodes) & set(obs2.graph_nodes))
   ```
   - Evaluates purely via raw string set intersection: `bool(set(obs1.graph_nodes) & set(obs2.graph_nodes))`.
   - Cannot detect relationships between two observations referencing different entities on the same host (e.g., `endpoint:http://api.example.com/v1/users` and `vulnerability:CVE-2023-XXXX`).

4. **`EvidenceFusionEngine` (`argus/correlation/fusion.py:13-60, 68-76`):**
   - Contains 9 fusion rules (`fuse_shared_business_objects`, `fuse_shared_workflows`, `fuse_shared_technologies`, `fuse_shared_endpoints`, `fuse_shared_graphql_types`, `fuse_shared_authentication_context`, `fuse_shared_authorization_context`, `fuse_shared_api_resource`, `fuse_shared_client_route`).
   - `DEFAULT_FUSION_RULES` currently does not include a graph-neighborhood fusion rule.
   - `_sync_metadata` collects `graph_nodes` and `graph_edges` into `EvidenceBundle`.

5. **`KnowledgeGraph` (`argus/graph/graph.py:6-215`):**
   - Core storage: `self.nodes: dict[str, Node]`, `self.edges: list[Edge]`.
   - Existing query methods:
     - `add(node: Node) -> bool`
     - `get(node_id: str) -> Optional[Node]`
     - `connect(source: str, target: str, edge_type: str, metadata: dict) -> bool`
     - `all() -> list[Node]`, `node_count() -> int`, `edge_count() -> int`
     - `nodes_by_type(node_type: str) -> list[Node]`
     - `edges_from(node: Node) -> list[Edge]`, `edges_to(node: Node) -> list[Edge]`
     - `neighbors(node: Node) -> list[Node]` (undirected 1-hop neighbor nodes)
     - `summary() -> dict[str, int]`
     - `get_hosts_without_endpoints() -> list[Node]`
     - `get_hosts_without_vulnerabilities() -> list[Node]`
     - `get_asset_counts() -> dict[str, int]`
   - Missing topological query methods needed for R1, R2, and R3:
     - `get_host_for_node(node_or_id)`
     - `in_same_host_subgraph(node_id1, node_id2)`
     - `are_connected(node_id1, node_id2, max_depth=2)`
     - `get_node_degree(node_or_id)`
     - `get_connected_endpoints(host_node_or_id)`

6. **`AttackSurfaceGraphBuilder` (`argus/graph/attack_surface.py:37-212`):**
   - Canonical node naming conventions:
     - Target: `target:{target}`
     - Subdomain: `subdomain:{hostname}`
     - Live host: `live_host:{url}` or `live_host:{host}`
     - Technology: `technology:{tech_name}`
     - Endpoint: `endpoint:{ep_url}`
     - Vulnerability: `vulnerability:{template_id or name}`
   - Edge taxonomy:
     - `target` -> `subdomain` / `live_host`: `RESOLVES_TO`, `HOSTS`
     - `subdomain` -> `live_host`: `HOSTS`
     - `live_host` -> `technology`: `RUNS_TECHNOLOGY`
     - `live_host` -> `endpoint`: `HAS_ENDPOINT`
     - `live_host` -> `vulnerability`: `HAS_VULNERABILITY`

7. **`AutonomousMissionRuntime` during `CORRELATING` (`argus/runtime/mission_runtime.py:121-152`):**
   ```python
   elif mission.status == MissionState.CORRELATING:
       from argus.correlation.observation import Observation
       from argus.correlation.models import ObservationCategory, ObservationPriority
       
       if hasattr(mission, "evidence") and mission.evidence:
           if not hasattr(mission, "_correlated_evidence_ids"):
               mission._correlated_evidence_ids = set()
               
           for ev in mission.evidence.all():
               if ev.evidence_id not in mission._correlated_evidence_ids:
                   obs = Observation(
                       source="evidence_collector",
                       category=ObservationCategory.TECHNOLOGY,
                       title=f"Evidence: {ev.category}",
                       description=ev.description or str(ev.value),
                       confidence=0.8,
                       priority=ObservationPriority.MEDIUM,
                       evidence=[ev]
                   )
                   self.correlation_engine.process_observation(obs)
                   mission._correlated_evidence_ids.add(ev.evidence_id)
   ```
   - `category` is hardcoded to `ObservationCategory.TECHNOLOGY`.
   - `obs.graph_nodes` is NOT populated.
   - `obs.endpoints`, `obs.urls`, `obs.technology`, `obs.tags` are NOT populated from `ev.metadata`.
   - `mission.attack_surface_graph` is never passed to `self.correlation_engine`.
   - As a result, no rules match in `CorrelationMatcher`, and `mission.correlations` remains empty after `step()`.

8. **Test Suite Baseline (`pytest tests/correlation/ -v` & full suite):**
   - `pytest tests/correlation/ -v` executed with 30 passing tests in 0.77s.
   - Full suite `python -m pytest tests/ --ignore=tests/workspace -x -q` passed with 543 passing tests.
   - `tests/correlation/test_rules.py` imports `match_shared_graph_nodes` but contains no test function for it.

---

## 2. Logic Chain

1. **Root Cause of the Gap:**
   - In Sprint 2, `AttackSurfaceGraphBuilder` created `mission.attack_surface_graph` (a `KnowledgeGraph`).
   - However, during the `CORRELATING` phase in `AutonomousMissionRuntime.step()`:
     a. `mission.attack_surface_graph` is not forwarded to `CorrelationEngine`.
     b. `Observation` objects constructed from `mission.evidence` lack `graph_nodes` and structured entity references.
     c. `CorrelationMatcher` only has raw string matching rules, without any awareness of graph topology.
   - Consequently, downstream reasoning engines (`InvestigationBuilder`, `HypothesisEngine`) receive 0 correlations and operate in a context-free vacuum.

2. **Topological Neighborhood Traversal Logic:**
   - In an attack surface graph, each host subgraph is rooted at a `live_host` node:
     - `subdomain` points to `live_host` via `HOSTS`.
     - `live_host` points to `endpoint` via `HAS_ENDPOINT`.
     - `live_host` points to `technology` via `RUNS_TECHNOLOGY`.
     - `live_host` points to `vulnerability` via `HAS_VULNERABILITY`.
   - Two entities are topologically connected in the same host subgraph if:
     a. They have identical canonical node IDs (e.g. `n1 == n2`).
     b. They resolve to the same parent `live_host` via incoming/outgoing edges (`graph.get_host_for_node(n1) == graph.get_host_for_node(n2)`).
     c. They are connected via an undirected path of distance <= 2 hops in the `KnowledgeGraph` (`graph.are_connected(n1, n2, max_depth=2)`).

3. **Graph-Aware Correlation Workflow:**
   - **Step A (`KnowledgeGraph` Extensions in `argus/graph/graph.py`):**
     Add query methods:
     - `get_host_for_node(self, node_or_id: Union[str, Node]) -> Optional[Node]`
     - `in_same_host_subgraph(self, node_id1: str, node_id2: str) -> bool`
     - `are_connected(self, node_id1: str, node_id2: str, max_depth: int = 2) -> bool`
     - `get_node_degree(self, node_or_id: Union[str, Node]) -> int`
     - `get_connected_endpoints(self, host_node_or_id: Union[str, Node]) -> list[Node]`
   - **Step B (`rules.py` & `matcher.py` Upgrades):**
     - Update `match_shared_graph_nodes(obs1: Observation, obs2: Observation, graph: Optional[KnowledgeGraph] = None) -> bool`:
       - First checks direct string ID overlap `bool(set(obs1.graph_nodes) & set(obs2.graph_nodes))`.
       - If `graph` is provided, performs graph traversal checking `graph.in_same_host_subgraph(n1, n2)` and `graph.are_connected(n1, n2, max_depth=2)` across all pairs `(n1, n2)`.
     - Add `match_graph_neighborhood(obs1: Observation, obs2: Observation, graph: Optional[KnowledgeGraph] = None) -> bool` to `DEFAULT_RULES`.
     - Update `CorrelationMatcher.__init__(rules=None, knowledge_graph=None)` and `find_matches(obs1, obs2, knowledge_graph=None)` to pass `knowledge_graph` to rule functions supporting `graph` kwarg.
   - **Step C (`CorrelationEngine` in `argus/correlation/engine.py`):**
     - Add `knowledge_graph: Optional[KnowledgeGraph] = None` to `CorrelationEngine.__init__`.
     - Store `self.knowledge_graph = knowledge_graph` and pass to `self.matcher = CorrelationMatcher(knowledge_graph=knowledge_graph)`.
     - In `process_observation(self, new_obs, knowledge_graph=None)`, sync `self.matcher.knowledge_graph = knowledge_graph or self.knowledge_graph`.
   - **Step D (`AutonomousMissionRuntime` in `argus/runtime/mission_runtime.py`):**
     - In `MissionController._create_runtime()`: pass `knowledge_graph=mission.attack_surface_graph` to `CorrelationEngine`.
     - In `CORRELATING` phase of `AutonomousMissionRuntime.step()`:
       - Set `self.correlation_engine.knowledge_graph = mission.attack_surface_graph`.
       - When generating `Observation` from `ev in mission.evidence.all()`:
         - Map `category` dynamically based on `ev.category`.
         - Populate canonical `obs.graph_nodes` (e.g. `endpoint:{url}`, `vulnerability:{template_id or name}`, `live_host:{url or host}`, `subdomain:{hostname}`, `technology:{name}`).
         - Populate `obs.endpoints`, `obs.urls`, `obs.technology`, `obs.tags` from `ev.metadata` and `ev.value`.

---

## 3. Caveats

1. **Legacy Compatibility:**
   Existing tests instantiate `CorrelationEngine(obs_reg, corr_reg, graph)` with 3 arguments. `knowledge_graph` must be an optional 4th parameter (`knowledge_graph: Optional[KnowledgeGraph] = None`) with default `None` to preserve 100% backward compatibility.
2. **Rule Function Signature Backward Compatibility:**
   Existing external rules or custom matchers might call `rule_func(obs1, obs2)` with 2 positional arguments. Upgraded rules must use default `graph: Optional[Any] = None` and `CorrelationMatcher.find_matches` must gracefully fallback if a rule function does not accept `graph`.
3. **Graph Subgraph Boundary (Multi-Target Missions):**
   If a mission covers multiple unrelated domains (e.g. `example.com` and `foo.com`), the traversal depth must be capped (e.g., `max_depth=2`) so that two endpoints on completely different subdomains/hosts do not correlate via the root target node unless explicitly configured.

---

## 4. Conclusion

Requirement R1 can be achieved with full backward compatibility and zero regressions by implementing the following localized changes:

1. **`argus/graph/graph.py`**:
   Add `get_host_for_node`, `in_same_host_subgraph`, `are_connected`, `get_node_degree`, and `get_connected_endpoints` methods to `KnowledgeGraph`.
2. **`argus/correlation/rules.py`**:
   Upgrade `match_shared_graph_nodes` to accept `graph: Optional[KnowledgeGraph] = None` and perform graph traversal (`in_same_host_subgraph` / `are_connected`). Add `match_graph_neighborhood`.
3. **`argus/correlation/matcher.py`**:
   Accept `knowledge_graph` in `__init__` and `find_matches`, forwarding the graph to matching rules.
4. **`argus/correlation/engine.py`**:
   Accept optional `knowledge_graph` in `__init__` and pass down to `self.matcher`.
5. **`argus/runtime/mission_runtime.py` & `argus/runtime/controller.py`**:
   Pass `mission.attack_surface_graph` to `CorrelationEngine` during controller initialization and runtime step, and populate `obs.graph_nodes` from structured evidence metadata.
6. **Tests**:
   Add comprehensive unit tests in `tests/correlation/` covering:
   - `test_match_shared_graph_nodes_string_intersection`
   - `test_match_shared_graph_nodes_same_host_subgraph`
   - `test_match_shared_graph_nodes_connected_hops`
   - `test_match_shared_graph_nodes_disconnected`
   - `test_correlation_engine_with_knowledge_graph`
   - `test_knowledge_graph_topological_queries`

---

## 5. Verification Method

### Test Commands to Run

1. **Verify correlation tests:**
   ```bash
   pytest tests/correlation/ -v
   ```
2. **Verify graph tests:**
   ```bash
   pytest tests/test_graph*.py tests/graph/ -v
   ```
3. **Verify full test suite with zero regressions:**
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```

### Invalidation Conditions
- Any of the 543 existing tests fail.
- `match_shared_graph_nodes` fails when two observations reference disconnected nodes across different hosts.
- `match_shared_graph_nodes` fails when `graph` is `None` (must fall back to string intersection).
