# ARGUS Sprint 3 Investigation Report: Correlation Subsystem

**Author**: Explorer 2 (`explorer_correlation`)  
**Target**: ARGUS Correlation Subsystem (`argus/correlation/`)  
**Working Directory**: `/home/varun/argus/.agents/explorer_correlation_1/`  
**Date**: 2026-08-28  

---

## 1. Observation

### 1.1 `argus/correlation/engine.py` (`CorrelationEngine`)
- **Location**: `argus/correlation/engine.py:14-152`
- **Constructor** (`lines 21-29`):
  ```python
  class CorrelationEngine:
      def __init__(self, observation_registry: ObservationRegistry, 
                   correlation_registry: CorrelationRegistry, 
                   graph: CorrelationGraph):
          self.obs_registry = observation_registry
          self.corr_registry = correlation_registry
          self.graph = graph
          self.matcher = CorrelationMatcher()
          self.scorer = CorrelationScorer(self.obs_registry)
  ```
  `CorrelationEngine` takes `ObservationRegistry`, `CorrelationRegistry`, and internal `CorrelationGraph`. It currently does **not** accept or store a reference to the domain `KnowledgeGraph` (`mission.attack_surface_graph`).
- **`process_observation(new_obs: Observation) -> None`** (`lines 30-75`):
  - Adds `new_obs` to `self.obs_registry` and adds a node into `self.graph` (internal `CorrelationGraph`).
  - Iterates over all existing observations in `self.obs_registry.get_all()` (excluding `new_obs`).
  - Calls `matched_rules = self.matcher.find_matches(new_obs, existing_obs)`.
  - For each matched rule, records an edge `self.graph.link_observations(new_obs.id, existing_obs.id, rule)`.
  - Looks up correlations for `existing_obs` via `self.graph.get_correlations_for_observation(existing_obs.id)`.
  - If no correlations are matched: checks if any related observations exist via `self.graph.get_related_observations(new_obs.id)`; if so, creates a new `Correlation` via `self._create_correlation(...)`.
  - If existing correlations matched: merges multiple correlations if needed via `self._merge_correlations(...)` and adds `new_obs.id` via `self._update_correlation(...)`.
  - Recalculates correlation score via `self._sync_correlation_metadata(...)` and `self.scorer.calculate_score(corr)`.
- **Note on `process_mission_state()`**:
  - `process_mission_state()` does not exist on `CorrelationEngine`; it exists on `EvidenceFusionEngine` in `argus/correlation/fusion.py:77`.

### 1.2 `argus/correlation/graph.py` (`CorrelationGraph`)
- **Location**: `argus/correlation/graph.py:5-63`
- **Structure**:
  - Wraps a NetworkX `DiGraph` (`self._graph = nx.DiGraph()`).
  - Nodes represent:
    - `"Observation"` (node ID = `str(obs_id)`, attrs: `title`, `source`, etc.)
    - `"Correlation"` (node ID = `str(corr_id)`, attrs: `title`, etc.)
  - Edges represent:
    - `"Matched"` (directed edge between observation IDs with attribute `rule=rule_name`).
    - `"PartOf"` (directed edge from observation ID to correlation ID).
  - Methods: `add_observation`, `add_correlation`, `link_observations`, `link_observation_to_correlation`, `get_correlations_for_observation`, `get_related_observations`, `to_dict`.
- **Distinction**: `CorrelationGraph` is an internal bookkeeping graph tracking observation-to-observation rule matches and observation-to-correlation grouping. It is **not** the attack-surface entity graph (`KnowledgeGraph`).

### 1.3 `argus/correlation/matcher.py` (`CorrelationMatcher`) & `argus/correlation/rules.py`
- **Location**: `argus/correlation/matcher.py:5-25`
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
- **The 12 Default Matching Rules in `argus/correlation/rules.py`**:
  1. `match_shared_business_objects`: checks `set(obs1.business_objects) & set(obs2.business_objects)`
  2. `match_shared_workflows`: checks `set(obs1.workflows) & set(obs2.workflows)`
  3. `match_shared_api_operations`: checks `set(obs1.api_operations) & set(obs2.api_operations)`
  4. `match_shared_technologies`: checks `set(obs1.technology) & set(obs2.technology)`
  5. `match_shared_authentication_context`: checks `set(obs1.authentication_context) & set(obs2.authentication_context)`
  6. `match_shared_authorization_context`: checks `set(obs1.authorization_context) & set(obs2.authorization_context)`
  7. `match_shared_graph_nodes` (`rules.py:33-36`):
     ```python
     def match_shared_graph_nodes(obs1: Observation, obs2: Observation) -> bool:
         if not obs1.graph_nodes or not obs2.graph_nodes:
             return False
         return bool(set(obs1.graph_nodes) & set(obs2.graph_nodes))
     ```
  8. `match_shared_tags`: checks `set(obs1.tags) & set(obs2.tags)`
  9. `match_shared_graphql_types`: checks `set(obs1.graphql_types) & set(obs2.graphql_types)`
  10. `match_shared_endpoints`: checks `set(obs1.endpoints) & set(obs2.endpoints)`
  11. `match_shared_urls`: checks `set(obs1.urls) & set(obs2.urls)`
  12. `match_shared_evidence`: checks `set(str(e) for e in obs1.evidence) & set(str(e) for e in obs2.evidence)`
- **Rule Signatures & Return Values**:
  - Every rule currently takes `(obs1: Observation, obs2: Observation)` and returns `bool`.
  - `match_shared_graph_nodes` currently does only a string set intersection on `obs1.graph_nodes` and `obs2.graph_nodes`.

### 1.4 `argus/graph/graph.py` (`KnowledgeGraph`) Topology Queries Available
- **Location**: `argus/graph/graph.py:6-368`
- `KnowledgeGraph` implements domain topology query methods built in Sprint 2:
  - `in_same_host_subgraph(node_id1: str, node_id2: str) -> bool`: Checks if both nodes resolve to the same `live_host` node or are connected within 2 hops (`graph.py:264-284`).
  - `are_connected(node_id1: str, node_id2: str, max_depth: int = 2) -> bool`: Undirected BFS path check within `max_depth` hops (`graph.py:285-319`).
  - `get_host_for_node(node_or_id: Union[str, Node]) -> Optional[Node]`: Resolves endpoint, subdomain, technology, or vulnerability node to its parent `live_host` Node (`graph.py:216-263`).
  - `get_node_degree(node_or_id: Union[str, Node]) -> int`: Total in-degree + out-degree (`graph.py:320-338`).
  - `get_connected_endpoints(host_node_or_id: Union[str, Node]) -> list[Node]`: All endpoint nodes attached via `HAS_ENDPOINT` edges (`graph.py:339-368`).
  - `get_asset_counts() -> dict[str, int]`: Returns counts grouped by `target`, `subdomain`, `live_host`, `endpoint`, `technology`, `vulnerability` (`graph.py:196-215`).

### 1.5 `argus/graph/attack_surface.py` (`AttackSurfaceGraphBuilder`) Node ID Conventions
- Subdomain: `subdomain:<hostname>` (e.g. `subdomain:api.example.com`)
- Live Host: `live_host:<url>` or `live_host:<host>` (e.g. `live_host:http://api.example.com`)
- Technology: `technology:<tech_name>` (e.g. `technology:Nginx`)
- Endpoint: `endpoint:<ep_url>` (e.g. `endpoint:http://api.example.com/v1/users`)
- Vulnerability: `vulnerability:<template_id or name>` (e.g. `vulnerability:CVE-2023-XXXX`)
- Graph builder connects:
  - `target:<target>` -[RESOLVES_TO]-> `subdomain:<host>`
  - `subdomain:<host>` -[HOSTS]-> `live_host:<url>`
  - `live_host:<url>` -[RUNS_TECHNOLOGY]-> `technology:<tech_name>`
  - `live_host:<url>` -[HAS_ENDPOINT]-> `endpoint:<ep_url>`
  - `live_host:<url>` -[HAS_VULNERABILITY]-> `vulnerability:<template_id>`

### 1.6 `argus/correlation/fusion.py` (`EvidenceFusionEngine`)
- **Location**: `argus/correlation/fusion.py:62-208`
- **Constructor** (`lines 68-76`): Takes `obs_registry: ObservationRegistry`, `corr_registry: CorrelationRegistry`, `bundle_registry: EvidenceBundleRegistry`, and `rules` (defaults to `DEFAULT_FUSION_RULES` of 9 fusion rules).
- **`process_mission_state()`** (`lines 77-83`):
  - Fetches all observations from `obs_registry` and correlations from `corr_registry`.
  - For each item, calls `_fuse_item(item)` to find matching `EvidenceBundle` in `bundle_registry`.
  - If no bundle matches, creates a new `EvidenceBundle`. If multiple bundles match, merges them.
  - Calls `_sync_metadata(bundle)` which aggregates `business_objects`, `workflows`, `technologies`, `graph_nodes`, `graph_edges`, `auth`, `endpoints`, `urls`, and deduplicates evidence.
  - Computes `strength` via `EvidenceStrengthScorer` and `confidence` via `ConfidenceCalculator`.

### 1.7 Mission Runtime Wiring (`argus/runtime/mission_runtime.py` and `argus/runtime/controller.py`)
- In `argus/runtime/controller.py:43-45`:
  ```python
  correlation_engine=CorrelationEngine(mission.observations, mission.correlations, mission.correlation_graph),
  fusion_engine=EvidenceFusionEngine(mission.observations, mission.correlations, mission.evidence_bundles),
  ```
  `mission.attack_surface_graph` is **not** passed into `CorrelationEngine`.
- In `argus/runtime/mission_runtime.py:121-152` (`CORRELATING` phase):
  - Ingests `mission.evidence.all()` into `Observation`:
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
    self.correlation_engine.process_observation(obs)
    ```
  - Note: `obs.graph_nodes`, `obs.endpoints`, `obs.technology`, `obs.urls` are **not** populated when converted to `Observation`. Thus, observations from evidence currently have empty `graph_nodes = []`, preventing any graph matching rule from firing during the mission loop.

### 1.8 Existing Correlation Tests (`tests/correlation/`)
- 14 test suites exist in `tests/correlation/`:
  1. `test_correlation_engine.py`: linking and merging observations with shared business objects.
  2. `test_matcher.py`: rule evaluation with `create_obs()` fixture helper.
  3. `test_rules.py`: unit tests for individual rules.
  4. `test_fusion.py`: fusion into `EvidenceBundle`.
  5. `test_graph.py`: NetworkX `CorrelationGraph` operations.
  6. `test_scoring.py`: `CorrelationScorer` point system.
  7. `test_strength.py`: `EvidenceStrengthScorer` & `ConfidenceCalculator`.
  8. `test_observation.py`: `Observation` model validation & immutability.
  9. `test_registry.py`: `ObservationRegistry`, `CorrelationRegistry`, `EvidenceBundleRegistry`.
  10. `test_deduplication.py`: `EvidenceDeduplicator`.
  11. `test_serializer.py`: JSON/YAML/msgpack serialization.
  12. `test_integration.py`: `Mission` attachment & Typer CLI.
  13. `test_mission.py`: mission lifecycle integration.
  14. `test_evidence_integration.py`: bundle registry & CLI.
- **Mock Fixtures**: In-memory registry instantiations (`ObservationRegistry()`, `CorrelationRegistry()`, `CorrelationGraph()`, `EvidenceBundleRegistry()`), helper function `create_obs(**kwargs) -> Observation`.
- **Baseline Test Suite Status**: `python -m pytest tests/ --ignore=tests/workspace -x -q` passed 543 tests.

---

## 2. Logic Chain

1. **Current Graph Isolation**:
   - Sprint 2 created `AttackSurfaceGraphBuilder`, which builds a rich `KnowledgeGraph` attached to `mission.attack_surface_graph` and `mission.graph`.
   - However, during the `CORRELATING` phase in `AutonomousMissionRuntime.step()`, `CorrelationEngine` operates only with `ObservationRegistry`, `CorrelationRegistry`, and `CorrelationGraph`. It does not have access to `mission.attack_surface_graph`.
2. **Current Shallow Rule Limitation**:
   - `CorrelationMatcher` runs 12 rules against pairs of `Observation`.
   - `match_shared_graph_nodes` evaluates only `bool(set(obs1.graph_nodes) & set(obs2.graph_nodes))`.
   - Because a subdomain observation (`subdomain:api.example.com`) and an endpoint observation (`endpoint:http://api.example.com/v1/users`) have different string IDs, `set.intersection` evaluates to `False`.
   - Consequently, disparate observations on the same host subgraph are never correlated under the current implementation.
3. **Graph Topology Capability Already in Place**:
   - `KnowledgeGraph.in_same_host_subgraph(id1, id2)` resolves both entity IDs to their parent `live_host` node and tests if they belong to the same host subgraph (or within 2 hops).
   - `KnowledgeGraph.are_connected(id1, id2, max_depth=2)` performs undirected BFS traversal.
4. **Enabling Graph-Aware Correlation**:
   - Upgrading `match_shared_graph_nodes(obs1, obs2, graph=None)` to check:
     a) exact string intersection (instant match / fallback),
     b) if `graph` is provided and nodes exist, check `graph.in_same_host_subgraph(n1, n2)` or `graph.are_connected(n1, n2, max_depth=2)`.
   - Adding a dedicated `match_graph_neighborhood(obs1, obs2, graph=None)` rule to `DEFAULT_RULES` that handles both explicit `graph_nodes` and inferred node IDs (`f"endpoint:{ep}"`, `f"live_host:{url}"`, `f"subdomain:{host}"`, `f"technology:{tech}"`, `f"vulnerability:{vuln}"`).
   - Updating `CorrelationMatcher.find_matches(obs1, obs2, graph=None)` to pass `graph` to rules supporting it.
   - Updating `CorrelationEngine` to accept `knowledge_graph: Optional[KnowledgeGraph] = None` and pass it to `CorrelationMatcher`.
   - In `AutonomousMissionRuntime.step()` (`CORRELATING` phase), setting `self.correlation_engine.knowledge_graph = mission.attack_surface_graph` (or `mission.graph`) and mapping evidence items to observations with their corresponding `graph_nodes` (e.g. `[f"endpoint:{url}"]`, `[f"subdomain:{hostname}"]`, `[f"live_host:{url}"]`, `[f"vulnerability:{template_id}"]`, `[f"technology:{name}"]`).
   - In `MissionController._create_runtime()`, passing `knowledge_graph=getattr(mission, "attack_surface_graph", None)` when initializing `CorrelationEngine`.
5. **Outcome**:
   - Subdomains, live hosts, endpoints, technologies, and vulnerabilities discovered on the same target host are topologically correlated into rich `Correlation` objects with high correlation scores.
   - `EvidenceFusionEngine` fuses them into unified `EvidenceBundle`s.
   - Downstream `InvestigationBuilder` and `HypothesisEngine` receive topological context.
   - Acceptance criteria for R1 and R4 are cleanly satisfied.

---

## 3. Caveats

1. **Strict Backward Compatibility**:
   - Existing rules take 2 arguments `(obs1, obs2)`. Upgrading `match_shared_graph_nodes` and other rules must use `graph: Optional[Any] = None` with default `None`.
   - `CorrelationMatcher.find_matches` must gracefully handle both 2-arg rules and 3-arg (or keyword `graph=`) rules so custom rules or legacy signatures never throw `TypeError`.
2. **`CorrelationGraph` vs `KnowledgeGraph` Separation**:
   - `CorrelationGraph` (NetworkX `DiGraph` in `argus/correlation/graph.py`) must remain focused on observation-rule-correlation linkages.
   - `KnowledgeGraph` (domain ontology in `argus/graph/graph.py`) must remain the source of truth for asset/attack-surface topology.
   - `CorrelationEngine` bridges the two by using `KnowledgeGraph` to inform matches recorded in `CorrelationGraph`.
3. **Graph Traversal Performance**:
   - BFS traversal in `KnowledgeGraph` is bounded (`max_depth=2` or `max_depth=3`), keeping traversal time negligible (<1ms per pair).
   - Direct node matching (`n1 == n2`) and string intersection should always be checked first before initiating graph queries.

---

## 4. Conclusion & Recommended Implementation

### 4.1 Summary of Proposed Architecture Changes

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Mission Runtime Loop                              │
│                                                                             │
│  COLLECTING_EVIDENCE        CORRELATING Phase                               │
│  ┌──────────────────┐       ┌────────────────────────────────────────────┐  │
│  │ AttackSurface-   │       │ Evidence -> Observation mapping            │  │
│  │ GraphBuilder     │──────>│ (populates graph_nodes, category, metadata)│  │
│  └────────┬─────────┘       └─────────────────────┬──────────────────────┘  │
│           │                                       │                         │
│           ▼                                       ▼                         │
│  ┌──────────────────┐       ┌────────────────────────────────────────────┐  │
│  │ KnowledgeGraph   │──────>│ CorrelationEngine(knowledge_graph=...)     │  │
│  │ (attack surface  │       │   └── CorrelationMatcher(graph=...)        │  │
│  │  topology)       │       │         ├── match_shared_graph_nodes(...,G)│  │
│  │                  │       │         └── match_graph_neighborhood(...,G)│  │
│  └──────────────────┘       └─────────────────────┬──────────────────────┘  │
│                                                   │                         │
│                                                   ▼                         │
│                             ┌────────────────────────────────────────────┐  │
│                             │ EvidenceFusionEngine.process_mission_state │  │
│                             │ (fuses into rich EvidenceBundles)          │  │
│                             └─────────────────────┬──────────────────────┘  │
│                                                   │                         │
│  BUILDING_INVESTIGATIONS                          ▼                         │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ InvestigationBuilder & PriorityEngine (KnowledgeGraph-weighted)       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Proposed File Modifications & Snippets

#### A. `argus/correlation/rules.py`
Upgrade `match_shared_graph_nodes` and add `match_graph_neighborhood`:

```python
# In argus/correlation/rules.py

def match_shared_graph_nodes(obs1: Observation, obs2: Observation, graph: Optional[Any] = None) -> bool:
    """
    Matches if observations share exact graph node IDs or if their referenced nodes
    are topologically connected in the KnowledgeGraph (same host subgraph or <=2 hops).
    """
    if not obs1.graph_nodes or not obs2.graph_nodes:
        return False
    # 1. Exact string intersection
    if bool(set(obs1.graph_nodes) & set(obs2.graph_nodes)):
        return True
    # 2. Graph topology check if KnowledgeGraph is supplied
    if graph is not None:
        for n1 in obs1.graph_nodes:
            for n2 in obs2.graph_nodes:
                if hasattr(graph, "in_same_host_subgraph") and graph.in_same_host_subgraph(n1, n2):
                    return True
                if hasattr(graph, "are_connected") and graph.are_connected(n1, n2, max_depth=2):
                    return True
    return False


def match_graph_neighborhood(obs1: Observation, obs2: Observation, graph: Optional[Any] = None) -> bool:
    """
    Matches if two observations reference entities (hosts, endpoints, subdomains,
    technologies, vulnerabilities) connected in the KnowledgeGraph topology.
    """
    if graph is None:
        return False

    nodes1 = list(obs1.graph_nodes)
    nodes2 = list(obs2.graph_nodes)

    # Infer node IDs from endpoints / urls if graph_nodes not explicitly set
    if not nodes1:
        nodes1.extend(f"endpoint:{ep}" for ep in obs1.endpoints)
        nodes1.extend(f"live_host:{u}" for u in obs1.urls)
    if not nodes2:
        nodes2.extend(f"endpoint:{ep}" for ep in obs2.endpoints)
        nodes2.extend(f"live_host:{u}" for u in obs2.urls)

    if not nodes1 or not nodes2:
        return False

    for n1 in nodes1:
        for n2 in nodes2:
            if n1 == n2:
                return True
            if hasattr(graph, "in_same_host_subgraph") and graph.in_same_host_subgraph(n1, n2):
                return True
            if hasattr(graph, "are_connected") and graph.are_connected(n1, n2, max_depth=2):
                return True
    return False

# Register in DEFAULT_RULES
DEFAULT_RULES = [
    ("match_shared_business_objects", match_shared_business_objects),
    ("match_shared_workflows", match_shared_workflows),
    ("match_shared_api_operations", match_shared_api_operations),
    ("match_shared_technologies", match_shared_technologies),
    ("match_shared_authentication_context", match_shared_authentication_context),
    ("match_shared_authorization_context", match_shared_authorization_context),
    ("match_shared_graph_nodes", match_shared_graph_nodes),
    ("match_graph_neighborhood", match_graph_neighborhood),
    ("match_shared_tags", match_shared_tags),
    ("match_shared_graphql_types", match_shared_graphql_types),
    ("match_shared_endpoints", match_shared_endpoints),
    ("match_shared_urls", match_shared_urls),
    ("match_shared_evidence", match_shared_evidence),
]
```

#### B. `argus/correlation/matcher.py`
Upgrade `CorrelationMatcher` to pass `graph`:

```python
# In argus/correlation/matcher.py

class CorrelationMatcher:
    """Matches observations against each other using modular rules with optional graph awareness."""

    def __init__(self, rules: List[Tuple[str, callable]] = None, graph: Optional[Any] = None):
        self.rules = rules or DEFAULT_RULES
        self.graph = graph

    def find_matches(self, obs1: Observation, obs2: Observation, graph: Optional[Any] = None) -> List[str]:
        """
        Evaluate all rules against the two observations.
        Returns a list of rule names that successfully matched.
        """
        active_graph = graph if graph is not None else self.graph
        matched_rules = []
        for rule_name, rule_func in self.rules:
            try:
                # Attempt invocation with graph kwarg; fallback to 2-arg call
                matched = False
                if active_graph is not None:
                    try:
                        matched = rule_func(obs1, obs2, graph=active_graph)
                    except TypeError:
                        matched = rule_func(obs1, obs2)
                else:
                    matched = rule_func(obs1, obs2)
                if matched:
                    matched_rules.append(rule_name)
            except Exception:
                pass
        return matched_rules
```

#### C. `argus/correlation/engine.py`
Upgrade `CorrelationEngine` to store `knowledge_graph` and pass to matcher:

```python
# In argus/correlation/engine.py

class CorrelationEngine:
    def __init__(self, observation_registry: ObservationRegistry, 
                 correlation_registry: CorrelationRegistry, 
                 graph: CorrelationGraph,
                 knowledge_graph: Optional[Any] = None):
        self.obs_registry = observation_registry
        self.corr_registry = correlation_registry
        self.graph = graph
        self.knowledge_graph = knowledge_graph
        self.matcher = CorrelationMatcher(graph=self.knowledge_graph)
        self.scorer = CorrelationScorer(self.obs_registry)

    def process_observation(self, new_obs: Observation, knowledge_graph: Optional[Any] = None) -> None:
        """Process a newly discovered observation with optional KnowledgeGraph."""
        active_kg = knowledge_graph if knowledge_graph is not None else self.knowledge_graph
        if active_kg is not None:
            self.knowledge_graph = active_kg
            self.matcher.graph = active_kg

        self.obs_registry.add(new_obs)
        self.graph.add_observation(new_obs.id, title=new_obs.title, source=new_obs.source)
        
        matched_correlations = []
        
        all_obs = self.obs_registry.get_all()
        for existing_obs in all_obs:
            if existing_obs.id == new_obs.id:
                continue
                
            matched_rules = self.matcher.find_matches(new_obs, existing_obs, graph=self.knowledge_graph)
            if matched_rules:
                for rule in matched_rules:
                    self.graph.link_observations(new_obs.id, existing_obs.id, rule)
                    logger.info(f"Observation linked: {new_obs.id} <-> {existing_obs.id} via {rule}")
                
                corr_ids = self.graph.get_correlations_for_observation(existing_obs.id)
                for c_id in corr_ids:
                    corr = self.corr_registry.find(uuid.UUID(c_id))
                    if corr and corr not in matched_correlations:
                        matched_correlations.append(corr)
        ...
```

#### D. `argus/runtime/controller.py` & `argus/runtime/mission_runtime.py`
In `argus/runtime/controller.py:43`:
```python
correlation_engine=CorrelationEngine(
    mission.observations,
    mission.correlations,
    mission.correlation_graph,
    knowledge_graph=getattr(mission, "attack_surface_graph", None)
),
```

In `argus/runtime/mission_runtime.py:121-152` (`CORRELATING` phase):
```python
        elif mission.status == MissionState.CORRELATING:
            from argus.correlation.observation import Observation
            from argus.correlation.models import ObservationCategory, ObservationPriority
            
            # Ensure correlation engine has access to the latest attack surface graph
            if hasattr(mission, "attack_surface_graph") and mission.attack_surface_graph:
                self.correlation_engine.knowledge_graph = mission.attack_surface_graph
                self.correlation_engine.matcher.graph = mission.attack_surface_graph

            if hasattr(mission, "evidence") and mission.evidence:
                if not hasattr(mission, "_correlated_evidence_ids"):
                    mission._correlated_evidence_ids = set()
                    
                for ev in mission.evidence.all():
                    if ev.evidence_id not in mission._correlated_evidence_ids:
                        # Map evidence attributes into graph_nodes and contextual fields
                        graph_nodes = []
                        techs = []
                        endpoints = []
                        urls = []
                        tags = []

                        if ev.category == "subdomain":
                            host = ev.metadata.get("hostname") or ev.value
                            if host: graph_nodes.append(f"subdomain:{host}")
                            category = ObservationCategory.INFRASTRUCTURE
                        elif ev.category == "live_host":
                            url = ev.metadata.get("url") or ev.value
                            host = ev.metadata.get("host")
                            if url:
                                graph_nodes.append(f"live_host:{url}")
                                urls.append(url)
                            elif host:
                                graph_nodes.append(f"live_host:{host}")
                            ev_techs = ev.metadata.get("technologies") or []
                            if isinstance(ev_techs, str): ev_techs = [t.strip() for t in ev_techs.split(",") if t.strip()]
                            techs.extend(ev_techs)
                            category = ObservationCategory.INFRASTRUCTURE
                        elif ev.category == "technology":
                            tech_name = ev.metadata.get("name") or ev.value
                            if tech_name:
                                graph_nodes.append(f"technology:{tech_name}")
                                techs.append(tech_name)
                            category = ObservationCategory.TECHNOLOGY
                        elif ev.category == "endpoint":
                            ep_url = ev.metadata.get("url") or ev.value
                            if ep_url:
                                graph_nodes.append(f"endpoint:{ep_url}")
                                endpoints.append(ep_url)
                                urls.append(ep_url)
                            category = ObservationCategory.API
                        elif ev.category == "vulnerability":
                            vuln_name = ev.metadata.get("template_id") or ev.metadata.get("name") or ev.value
                            if vuln_name:
                                graph_nodes.append(f"vulnerability:{vuln_name}")
                                tags.append(vuln_name)
                            category = ObservationCategory.EVIDENCE
                        else:
                            category = ObservationCategory.TECHNOLOGY

                        obs = Observation(
                            source="evidence_collector",
                            category=category,
                            title=f"Evidence: {ev.category}",
                            description=ev.description or str(ev.value),
                            confidence=0.8,
                            priority=ObservationPriority.MEDIUM,
                            graph_nodes=graph_nodes,
                            technology=techs,
                            endpoints=endpoints,
                            urls=urls,
                            tags=tags,
                            evidence=[ev]
                        )
                        self.correlation_engine.process_observation(obs)
                        mission._correlated_evidence_ids.add(ev.evidence_id)
            
            if hasattr(mission, "findings"):
                for finding in mission.findings:
                    if not getattr(finding, "_correlated", False):
                        if isinstance(finding, Observation):
                            self.correlation_engine.process_observation(finding)
                        finding._correlated = True
            
            self.fusion_engine.process_mission_state()
            self.state_machine.transition_to(MissionState.BUILDING_INVESTIGATIONS, "Building investigations")
            return
```

---

## 5. Verification Method

### 5.1 Unit Tests to Add in `tests/correlation/`
1. **`test_match_shared_graph_nodes_with_knowledge_graph`**:
   - Construct `KnowledgeGraph` with `subdomain:api.example.com` -[HOSTS]-> `live_host:http://api.example.com` -[HAS_ENDPOINT]-> `endpoint:http://api.example.com/v1/users`.
   - Create `obs1` with `graph_nodes=["subdomain:api.example.com"]`.
   - Create `obs2` with `graph_nodes=["endpoint:http://api.example.com/v1/users"]`.
   - Assert `match_shared_graph_nodes(obs1, obs2, graph=None)` is `False` (string set intersection alone fails).
   - Assert `match_shared_graph_nodes(obs1, obs2, graph=kg)` is `True` (graph traversal succeeds).
2. **`test_match_graph_neighborhood_rule`**:
   - Construct `KnowledgeGraph` with `live_host:http://api.example.com` -[HAS_VULNERABILITY]-> `vulnerability:CVE-2023-XXXX`.
   - Create `obs1` with `endpoints=["http://api.example.com/v1/login"]` and `obs2` with `graph_nodes=["vulnerability:CVE-2023-XXXX"]`.
   - Assert `match_graph_neighborhood(obs1, obs2, graph=kg)` is `True`.
3. **`test_correlation_engine_with_knowledge_graph`**:
   - Instantiate `CorrelationEngine(obs_reg, corr_reg, corr_graph, knowledge_graph=kg)`.
   - Process `obs1` (subdomain) and `obs2` (endpoint).
   - Assert `len(corr_reg.get_all()) == 1`.
   - Assert `corr_reg.get_all()[0].observations` contains both observation IDs.
   - Assert `corr.graph_nodes` contains both node IDs.
4. **`test_correlation_engine_fallback_without_knowledge_graph`**:
   - Instantiate `CorrelationEngine(obs_reg, corr_reg, corr_graph, knowledge_graph=None)`.
   - Process `obs1` (business_objects=["User"]) and `obs2` (business_objects=["User"]).
   - Assert `len(corr_reg.get_all()) == 1` (zero regression on non-graph rules).

### 5.2 Verification Commands
- Run all correlation tests:
  ```bash
  pytest tests/correlation/ -v
  ```
- Run full test suite:
  ```bash
  pytest tests/ --ignore=tests/workspace -x -q
  ```
- Invalidation Conditions:
  - If any of the existing 543 tests fail, rule signature backward compatibility is broken.
  - If `CorrelationEngine` fails to correlate two observations on the same host subgraph when `KnowledgeGraph` is provided, graph traversal resolution failed.
