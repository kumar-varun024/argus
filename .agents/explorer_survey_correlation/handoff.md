# Investigation Report: R1 (Graph-Aware Correlation Engine)

**Path:** `/home/varun/argus/.agents/explorer_survey_correlation/handoff.md`  
**Date:** 2026-08-28  
**Subsystem:** Correlation Engine (`argus/correlation`), Knowledge Graph (`argus/graph`), Runtime (`argus/runtime`)  
**Objective:** Complete survey, architectural design, interface signatures, rule implementations, and test suite specifications for R1 (Graph-Aware Correlation Engine).

---

## 1. Observation

Direct code inspection of relevant files produced the following key observations:

### 1.1 `argus/correlation/engine.py` (lines 21–29, 30–75)
- `CorrelationEngine.__init__` accepts 3 parameters:
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
- `graph` is an internal `CorrelationGraph` (NetworkX `DiGraph` tracking `Observation` $\leftrightarrow$ `Observation` links and `Observation` $\rightarrow$ `Correlation` grouping).
- `CorrelationEngine` currently has no reference to `KnowledgeGraph` (`mission.attack_surface_graph`).
- `self.matcher` is instantiated with no parameters and evaluated during `process_observation()` via:
  ```python
  matched_rules = self.matcher.find_matches(new_obs, existing_obs)
  ```
- When matches occur, `self.graph.link_observations(new_obs.id, existing_obs.id, rule)` links them, and observations are grouped into `Correlation` objects.
- `_sync_correlation_metadata()` aggregates `graph_nodes`, `graph_edges`, `technologies`, etc., and calculates score via `self.scorer.calculate_score(corr)`.

### 1.2 `argus/correlation/matcher.py` (lines 5–25)
- `CorrelationMatcher.__init__(self, rules: List[Tuple[str, callable]] = None)` takes optional rules (defaults to `DEFAULT_RULES`).
- `find_matches(self, obs1: Observation, obs2: Observation) -> List[str]` iterates over `self.rules` and invokes each `rule_func(obs1, obs2)` with only 2 positional arguments.
- It has no reference or access to `KnowledgeGraph`.

### 1.3 `argus/correlation/rules.py` (lines 1–83)
- `match_shared_graph_nodes` (lines 33–36) currently implements flat string intersection only:
  ```python
  def match_shared_graph_nodes(obs1: Observation, obs2: Observation) -> bool:
      if not obs1.graph_nodes or not obs2.graph_nodes:
          return False
      return bool(set(obs1.graph_nodes) & set(obs2.graph_nodes))
  ```
- No graph-neighborhood rule or graph traversal exists in `rules.py`.
- `DEFAULT_RULES` contains 12 string/set-matching rules.

### 1.4 `argus/correlation/fusion.py` (lines 14–60, 68–76, 143–188)
- `EvidenceFusionEngine` combines `Observation` and `Correlation` items into `EvidenceBundle` instances.
- `_sync_metadata` aggregates `graph_nodes` and `graph_edges` from observations and correlations into `bundle.graph_nodes` and `bundle.graph_edges`.
- `EvidenceStrengthScorer` (`argus/correlation/strength.py:52-53`) and `ConfidenceCalculator` (`argus/correlation/confidence.py:21`) already award bonuses for `bundle.graph_nodes` and `bundle.graph_edges`.
- `DEFAULT_FUSION_RULES` currently lacks a `fuse_shared_graph_nodes` rule.

### 1.5 `argus/graph/graph.py` (lines 6–369)
`KnowledgeGraph` provides the following query methods:
- `get(node_id: str) -> Optional[Node]` (line 33)
- `neighbors(node: Node) -> list[Node]` (line 132): returns deduplicated list of connected nodes across incoming/outgoing edges.
- `edges_from(node: Node) -> list[Edge]` & `edges_to(node: Node) -> list[Edge]` (lines 108, 120)
- `get_host_for_node(node_or_id: Union[str, Node]) -> Optional[Node]` (line 216): resolves any node (endpoint, technology, subdomain, vulnerability) to its parent `live_host` Node via direct edges and BFS (up to 3 hops).
- `in_same_host_subgraph(node_id1: str, node_id2: str) -> bool` (line 264): returns `True` if `node_id1 == node_id2`, or if both resolve to the same `live_host`, or if connected within 2 hops (`are_connected(node_id1, node_id2, max_depth=2)`).
- `are_connected(node_id1: str, node_id2: str, max_depth: int = 2) -> bool` (line 286): undirected BFS checking connectivity within `max_depth` hops.
- `get_node_degree(node_or_id: Union[str, Node]) -> int` (line 320): in-degree + out-degree.
- `get_connected_endpoints(host_node_or_id: Union[str, Node]) -> list[Node]` (line 339).

### 1.6 `argus/graph/attack_surface.py` (lines 11–373)
Node and Edge taxonomy constructed by `AttackSurfaceGraphBuilder`:
- Node IDs:
  - `target:<target>`
  - `subdomain:<hostname>`
  - `live_host:<url>` or `live_host:<host>`
  - `technology:<tech_name>`
  - `endpoint:<ep_url>`
  - `vulnerability:<vuln_name>`
- Edges:
  - `target` $\xrightarrow{\text{RESOLVES\_TO}}$ `subdomain`
  - `subdomain` $\xrightarrow{\text{HOSTS}}$ `live_host`
  - `live_host` $\xrightarrow{\text{RUNS\_TECHNOLOGY}}$ `technology`
  - `live_host` $\xrightarrow{\text{HAS\_ENDPOINT}}$ `endpoint`
  - `live_host` $\xrightarrow{\text{HAS\_VULNERABILITY}}$ `vulnerability`

### 1.7 `argus/runtime/controller.py` & `argus/runtime/mission_runtime.py`
- In `MissionController._create_runtime()` (lines 33–49):
  ```python
  correlation_engine=CorrelationEngine(mission.observations, mission.correlations, mission.correlation_graph),
  ```
  `KnowledgeGraph` is not passed into `CorrelationEngine`.
- In `AutonomousMissionRuntime.step()`:
  - During `COLLECTING_EVIDENCE` (lines 115–119): `AttackSurfaceGraphBuilder().build(mission)` is invoked, attaching the populated `KnowledgeGraph` to `mission.attack_surface_graph`.
  - During `CORRELATING` (lines 121–142): `Observation` objects are created from `mission.evidence.all()`:
    ```python
    obs = Observation(
        source="evidence_collector",
        category=ObservationCategory.TECHNOLOGY,
        title=f"Evidence: {ev.category}",
        description=ev.description or str(ev.value),
        confidence=0.8,
        priority=ObservationPriority.MEDIUM,
        evidence=[ev]
    )
    ```
    `obs.graph_nodes`, `obs.endpoints`, `obs.urls`, and `obs.technology` are not populated from `ev`.
    `self.correlation_engine.knowledge_graph` is never set or updated.

---

## 2. Logic Chain

1. **Premise:** In Sprint 2, `AttackSurfaceGraphBuilder` constructed a rich domain topology in `mission.attack_surface_graph` with typed nodes (`target`, `subdomain`, `live_host`, `endpoint`, `technology`, `vulnerability`) and relationships (`RESOLVES_TO`, `HOSTS`, `RUNS_TECHNOLOGY`, `HAS_ENDPOINT`, `HAS_VULNERABILITY`).
2. **Current Breakdown:**
   - `CorrelationEngine` and `CorrelationMatcher` operate in isolation from `KnowledgeGraph`, relying solely on flat string intersection.
   - `match_shared_graph_nodes` only compares `set(obs1.graph_nodes) & set(obs2.graph_nodes)`. Disjoint nodes on the same host (e.g. `endpoint:http://api.example.com/login` and `vulnerability:CVE-2023-XXXX`) evaluate to `False`.
   - `Observation` objects created during `CORRELATING` do not carry `graph_nodes` or structured metadata, depriving rules of node IDs.
   - `CorrelationEngine` does not have access to `mission.attack_surface_graph`.
3. **Inference & Solution:**
   - Passing `KnowledgeGraph` to `CorrelationEngine` (as an optional parameter `knowledge_graph: Optional[KnowledgeGraph] = None`) and forwarding it to `CorrelationMatcher`.
   - Upgrading `match_shared_graph_nodes` to perform actual graph traversal (`graph.in_same_host_subgraph` and `graph.are_connected`) when `graph` is present, while preserving string intersection when `graph` is None.
   - Adding `match_graph_neighborhood` to `DEFAULT_RULES`, which resolves entity references across `graph_nodes`, `endpoints`, `urls`, `technology`, and `evidence` to topologically connected graph nodes.
   - Adding `fuse_shared_graph_nodes` to `DEFAULT_FUSION_RULES` in `fusion.py`.
   - In `AutonomousMissionRuntime.step()` under `CORRELATING`:
     - Syncing `self.correlation_engine.knowledge_graph = mission.attack_surface_graph`.
     - Populating `obs.graph_nodes` with canonical node IDs (`f"{ev.category}:{ev.value}"` and relevant host/url references) and mapping category/metadata.

---

## 3. Caveats

1. **Graph Lifecycle Timing:**
   - At mission startup (`MissionController._create_runtime`), `mission.attack_surface_graph` may initially be empty or None until `COLLECTING_EVIDENCE` runs `AttackSurfaceGraphBuilder().build(mission)`.
   - Therefore, `CorrelationEngine` must support dynamic updating of its `knowledge_graph` (via a property setter or explicit sync before `CORRELATING`).
2. **Node ID Resolution Diversity:**
   - Some observations may supply bare values (e.g. `"api.example.com"`, `"http://api.example.com"`, `"Nginx"`) rather than prefixed node IDs (`"subdomain:api.example.com"`, `"live_host:http://api.example.com"`, `"technology:Nginx"`).
   - The entity extractor must resolve both direct IDs and value lookups against `KnowledgeGraph`.
3. **Backward Compatibility:**
   - 543+ existing unit tests instantiate `CorrelationEngine(obs_registry, corr_registry, graph)` with 3 arguments and call rules with 2 arguments `(obs1, obs2)`.
   - `knowledge_graph` must be an optional 4th parameter (`knowledge_graph: Optional[KnowledgeGraph] = None`), and `CorrelationMatcher.find_matches` must support both 2-argument and 3-argument rule callables.

---

## 4. Conclusion & Proposed Architecture

### 4.1 Interface Signatures

#### A. `argus/correlation/matcher.py`
```python
class CorrelationMatcher:
    """Matches observations against each other using modular rules."""

    def __init__(
        self,
        rules: Optional[List[Tuple[str, Callable]]] = None,
        graph: Optional[KnowledgeGraph] = None
    ) -> None:
        self.rules = rules or DEFAULT_RULES
        self.graph = graph

    def find_matches(self, obs1: Observation, obs2: Observation) -> List[str]:
        """
        Evaluate all rules against the two observations.
        Passes self.graph to rule functions that support it.
        """
        matched_rules = []
        for rule_name, rule_func in self.rules:
            try:
                matched = False
                try:
                    matched = rule_func(obs1, obs2, graph=self.graph)
                except TypeError:
                    matched = rule_func(obs1, obs2)
                if matched:
                    matched_rules.append(rule_name)
            except Exception:
                pass
        return matched_rules
```

#### B. `argus/correlation/engine.py`
```python
class CorrelationEngine:
    """
    Central engine for discovering relationships between observations.
    Consumes observations, evaluates matching rules, and maintains correlations.
    Does NOT generate investigations.
    """

    def __init__(
        self,
        observation_registry: ObservationRegistry,
        correlation_registry: CorrelationRegistry,
        graph: CorrelationGraph,
        knowledge_graph: Optional[KnowledgeGraph] = None
    ) -> None:
        self.obs_registry = observation_registry
        self.corr_registry = correlation_registry
        self.graph = graph
        self._knowledge_graph = knowledge_graph
        self.matcher = CorrelationMatcher(graph=self._knowledge_graph)
        self.scorer = CorrelationScorer(self.obs_registry)

    @property
    def knowledge_graph(self) -> Optional[KnowledgeGraph]:
        return self._knowledge_graph

    @knowledge_graph.setter
    def knowledge_graph(self, kg: Optional[KnowledgeGraph]) -> None:
        self._knowledge_graph = kg
        if hasattr(self, "matcher") and self.matcher is not None:
            self.matcher.graph = kg
```

#### C. `argus/correlation/rules.py`
```python
from typing import Optional, Set
from argus.correlation.observation import Observation
from argus.graph.graph import KnowledgeGraph

def _extract_graph_nodes(obs: Observation, graph: Optional[KnowledgeGraph] = None) -> Set[str]:
    """Extract and resolve canonical KnowledgeGraph node IDs from an Observation."""
    nodes = set()
    if obs.graph_nodes:
        nodes.update(obs.graph_nodes)

    if graph is not None:
        # Check direct nodes and prefix variants
        for gn in list(nodes):
            if gn not in graph.nodes:
                for prefix in ("target:", "subdomain:", "live_host:", "technology:", "endpoint:", "vulnerability:"):
                    cand = f"{prefix}{gn}"
                    if cand in graph.nodes:
                        nodes.add(cand)

        # Endpoints
        for ep in getattr(obs, "endpoints", []):
            ep_id = f"endpoint:{ep}"
            if ep_id in graph.nodes:
                nodes.add(ep_id)
            elif ep in graph.nodes:
                nodes.add(ep)

        # URLs
        for url in getattr(obs, "urls", []):
            for cand in (f"endpoint:{url}", f"live_host:{url}", url):
                if cand in graph.nodes:
                    nodes.add(cand)

        # Technology
        for tech in getattr(obs, "technology", []):
            tech_id = f"technology:{tech}"
            if tech_id in graph.nodes:
                nodes.add(tech_id)
            elif tech in graph.nodes:
                nodes.add(tech)

        # Evidence
        for ev in getattr(obs, "evidence", []):
            cat = getattr(ev, "category", None)
            val = getattr(ev, "value", None)
            if cat and val:
                cand = f"{cat}:{val}"
                if cand in graph.nodes:
                    nodes.add(cand)
                elif val in graph.nodes:
                    nodes.add(val)
    return nodes


def match_shared_graph_nodes(
    obs1: Observation,
    obs2: Observation,
    graph: Optional[KnowledgeGraph] = None
) -> bool:
    """
    Correlates observations referencing identical or topologically connected graph nodes.
    Performs graph traversal when KnowledgeGraph is provided.
    """
    if not obs1.graph_nodes or not obs2.graph_nodes:
        return False

    # 1. Direct string intersection (backward compatible fast path)
    if bool(set(obs1.graph_nodes) & set(obs2.graph_nodes)):
        return True

    # 2. Graph traversal
    if graph is not None:
        nodes1 = _extract_graph_nodes(obs1, graph)
        nodes2 = _extract_graph_nodes(obs2, graph)
        for n1 in nodes1:
            for n2 in nodes2:
                if n1 == n2:
                    return True
                if n1 in graph.nodes and n2 in graph.nodes:
                    if graph.in_same_host_subgraph(n1, n2):
                        return True
                    if graph.are_connected(n1, n2, max_depth=2):
                        return True
    return False


def match_graph_neighborhood(
    obs1: Observation,
    obs2: Observation,
    graph: Optional[KnowledgeGraph] = None,
    max_hops: int = 2
) -> bool:
    """
    Correlates observations if their referenced entities are topologically
    connected in the KnowledgeGraph within max_hops or in the same host subgraph.
    """
    if graph is None:
        return False

    nodes1 = _extract_graph_nodes(obs1, graph)
    nodes2 = _extract_graph_nodes(obs2, graph)

    if not nodes1 or not nodes2:
        return False

    for n1 in nodes1:
        for n2 in nodes2:
            if n1 == n2:
                return True
            if n1 in graph.nodes and n2 in graph.nodes:
                if graph.in_same_host_subgraph(n1, n2):
                    return True
                if graph.are_connected(n1, n2, max_depth=max_hops):
                    return True
    return False
```

#### D. `argus/correlation/fusion.py`
Add `fuse_shared_graph_nodes` to `DEFAULT_FUSION_RULES`:
```python
def fuse_shared_graph_nodes(item1, item2) -> bool:
    gn1 = getattr(item1, "graph_nodes", [])
    gn2 = getattr(item2, "graph_nodes", [])
    return bool(set(gn1) & set(gn2))
```

#### E. `argus/runtime/mission_runtime.py` (`CORRELATING` step)
```python
        elif mission.status == MissionState.CORRELATING:
            from argus.correlation.observation import Observation
            from argus.correlation.models import ObservationCategory, ObservationPriority

            # Sync latest KnowledgeGraph to CorrelationEngine
            kg = getattr(mission, "attack_surface_graph", getattr(mission, "graph", None))
            if kg is not None:
                self.correlation_engine.knowledge_graph = kg

            if hasattr(mission, "evidence") and mission.evidence:
                if not hasattr(mission, "_correlated_evidence_ids"):
                    mission._correlated_evidence_ids = set()

                cat_map = {
                    "subdomain": ObservationCategory.INFRASTRUCTURE,
                    "live_host": ObservationCategory.INFRASTRUCTURE,
                    "technology": ObservationCategory.TECHNOLOGY,
                    "endpoint": ObservationCategory.API,
                    "vulnerability": ObservationCategory.BUSINESS_LOGIC,
                }

                for ev in mission.evidence.all():
                    if ev.evidence_id not in mission._correlated_evidence_ids:
                        # Build graph node IDs
                        gn = [f"{ev.category}:{ev.value}"]
                        if ev.metadata:
                            if ev.metadata.get("host"):
                                gn.append(f"subdomain:{ev.metadata['host']}")
                            if ev.metadata.get("url"):
                                gn.append(f"live_host:{ev.metadata['url']}")
                            if ev.metadata.get("template_id"):
                                gn.append(f"vulnerability:{ev.metadata['template_id']}")

                        obs = Observation(
                            source="evidence_collector",
                            category=cat_map.get(ev.category, ObservationCategory.EVIDENCE),
                            title=f"Evidence: {ev.category}",
                            description=ev.description or str(ev.value),
                            confidence=0.8,
                            priority=ObservationPriority.MEDIUM,
                            graph_nodes=list(set(gn)),
                            technology=[ev.value] if ev.category == "technology" else [],
                            endpoints=[ev.value] if ev.category == "endpoint" else [],
                            urls=[ev.value] if ev.category == "live_host" else [],
                            metadata=dict(ev.metadata) if ev.metadata else {},
                            evidence=[ev]
                        )
                        self.correlation_engine.process_observation(obs)
                        mission._correlated_evidence_ids.add(ev.evidence_id)
```

---

## 5. Verification Method

### Test Plan for R1

1. **`tests/correlation/test_rules.py`**:
   - `test_match_shared_graph_nodes_string_only()`: verifies string set intersection without graph (backward compat).
   - `test_match_shared_graph_nodes_subgraph_traversal()`: verifies matching of `live_host:http://api.example.com` and `vulnerability:CVE-2023-XXXX` via `in_same_host_subgraph`.
   - `test_match_graph_neighborhood_connected()`: verifies matching between endpoint and vulnerability on same host.
   - `test_match_graph_neighborhood_unconnected()`: verifies isolated subdomains return `False`.
   - `test_match_graph_neighborhood_no_graph()`: verifies safe `False` return when graph is `None`.

2. **`tests/correlation/test_matcher.py`**:
   - `test_matcher_with_knowledge_graph()`: asserts `matcher.find_matches()` detects `match_graph_neighborhood` and `match_shared_graph_nodes`.

3. **`tests/correlation/test_correlation_engine.py`**:
   - `test_correlation_engine_with_knowledge_graph()`: tests end-to-end grouping of topologically connected observations into a single `Correlation` with combined `graph_nodes` and recalculated score.
   - `test_correlation_engine_dynamic_graph_setter()`: tests updating `engine.knowledge_graph = kg` after initialization.

4. **Integration / E2E Verification Command**:
   ```bash
   python3 -m pytest tests/correlation/ tests/runtime/ -q
   ```
   Ensures zero regressions across existing test suite and passing of new graph-aware correlation tests.

---

### Invalidation Conditions
- If `KnowledgeGraph.in_same_host_subgraph` or `are_connected` semantics are changed in `argus/graph/graph.py`, `_extract_graph_nodes` resolution should be adjusted accordingly.
- If `AttackSurfaceGraphBuilder` changes node prefix schemes (e.g. from `live_host:` to `host:`), prefix constants in `_extract_graph_nodes` must match.
