# Handoff Report: Investigation Builder & Priority Engine Graph Integration (Requirement R2)

**Agent**: Explorer 2 (Investigation Specialist)  
**Date**: 2026-08-28  
**Scope**: Requirement R2 & Graph Integration into `InvestigationBuilder` and `PriorityEngine`

---

## 1. Observation

### 1.1 Architecture & Call Flow Analysis
We inspected the investigation subsystem, runtime orchestration, knowledge graph model, and test suite.

- **`argus/runtime/mission_runtime.py:155-161`**:
  ```python
  elif mission.status == MissionState.BUILDING_INVESTIGATIONS:
      from argus.runtime.events import EventBus, RuntimeEventType
      EventBus().publish(RuntimeEventType.INVESTIGATION_STARTED, mission.id)
      self.investigation_builder.build_all()
      self.investigation_builder.prioritize_all(mission)
      self.state_machine.transition_to(MissionState.GENERATING_HYPOTHESES, "Generating hypotheses")
      return
  ```
  *Observation*: `self.investigation_builder.build_all()` is called with zero arguments. `prioritize_all(mission)` is passed `mission`. `mission.attack_surface_graph` is attached to `mission` in lines 65 and 117 (`AttackSurfaceGraphBuilder().build(mission)`), but is not explicitly queried or passed during building.

- **`argus/investigation/builder.py:15-52`**:
  ```python
  class InvestigationBuilder:
      def __init__(self, inv_registry: InvestigationRegistry, bundle_registry: EvidenceBundleRegistry,
                   corr_registry: CorrelationRegistry, obs_registry: ObservationRegistry,
                   weight_config: WeightConfig = None):
          self.inv_registry = inv_registry
          self.bundle_registry = bundle_registry
          self.conf_scorer = InvestigationConfidenceScorer(bundle_registry)
          self.prio_engine = PriorityEngine(bundle_registry, weight_config)
          self.val_gen = ManualValidationGenerator()
          self.reasoning_builder = ReasoningTreeBuilder(bundle_registry, corr_registry, obs_registry)
          self.generator = InvestigationGenerator(
              self.inv_registry, self.conf_scorer, self.prio_engine, 
              self.val_gen, self.reasoning_builder
          )

      def build_all(self) -> None:
          """Processes all Evidence Bundles to form Investigations."""
          for bundle in self.bundle_registry.get_all():
              self.generator.process_bundle(bundle)
  ```
  *Observation*: `InvestigationBuilder` iterates over `self.bundle_registry.get_all()` and delegates to `InvestigationGenerator.process_bundle(bundle)`.

- **`argus/investigation/generator.py:26-83`**:
  ```python
  def process_bundle(self, bundle: EvidenceBundle) -> Optional[Investigation]:
      if bundle.strength < 20 and bundle.confidence < 0.2:
          return None
      category = self._determine_category(bundle)
      existing_inv = self._find_duplicate(bundle, category)
      if existing_inv:
          self._merge(existing_inv, bundle)
          return existing_inv
      inv = Investigation(
          title=f"Review {category.value} Configuration",
          summary=f"Investigation into {category.value} based on fused evidence.",
          description=bundle.description,
          category=category
      )
      self._merge(inv, bundle)
      self.inv_registry.add(inv)
      return inv

  def _find_duplicate(self, bundle: EvidenceBundle, category: InvestigationCategory) -> Optional[Investigation]:
      for inv in self.inv_registry.get_all():
          if inv.category == category:
              shared_bo = set(inv.business_objects) & set(bundle.business_objects)
              shared_wf = set(inv.workflows) & set(bundle.workflows)
              if shared_bo or shared_wf:
                  return inv
      return None
  ```
  *Observation*: Deduplication (`_find_duplicate`) currently requires identical `category` and intersection of `business_objects` or `workflows`. It has zero awareness of host nodes (`live_host`, `subdomain`, URLs, endpoints). Multiple bundles referring to the same host will produce duplicate, fragmented investigations if they differ in category or lack shared business objects/workflows.

- **`argus/investigation/priority_engine.py:21-60`**:
  ```python
  def evaluate(self, investigation: Investigation, mission: Any = None) -> InvestigationPriority:
      self.weight_config.log_weights()
      score, explanations = self.score_calculator.calculate(
          investigation, 
          self.bundle_registry, 
          mission
      )
      investigation.priority_score = score
      investigation.priority_explanation = explanations
      investigation.priority = self._map_score_to_priority(score)
      return investigation.priority
  ```
  *Observation*: `PriorityEngine` delegates scoring to `ScoreCalculator.calculate`.

- **`argus/investigation/scoring.py:17-108, 181-190`**:
  ```python
  def _calculate_graph_completeness(self, investigation: Investigation, mission: Any) -> float:
      nodes = len(investigation.related_graph_nodes)
      edges = len(investigation.related_graph_edges)
      if nodes > 0 and edges > 0:
          return 90.0
      if nodes > 0 or edges > 0:
          return 60.0
      if mission and (getattr(mission, 'correlation_graph', None) or getattr(mission, 'authorization_graph', None)):
          return 40.0
      return 0.0
  ```
  *Observation*: Graph scoring in `ScoreCalculator` currently only measures the length of `related_graph_nodes` and `related_graph_edges` string lists. It does not inspect `KnowledgeGraph` topology, degree centrality, `HAS_VULNERABILITY` edges, or connected vulnerable technologies.

- **`argus/graph/graph.py` & `argus/graph/attack_surface.py`**:
  `KnowledgeGraph` provides rich querying methods:
  - `graph.get(node_id: str) -> Optional[Node]`
  - `graph.edges_from(node: Node) -> list[Edge]`
  - `graph.edges_to(node: Node) -> list[Edge]`
  - `graph.neighbors(node: Node) -> list[Node]`
  - `graph.nodes_by_type(node_type: str) -> list[Node]`
  - `graph.get_hosts_without_vulnerabilities() -> list[Node]`
  - `graph.get_hosts_without_endpoints() -> list[Node]`
  - `graph.get_asset_counts() -> dict[str, int]`
  Typed node formats: `target:<domain>`, `subdomain:<hostname>`, `live_host:<url/host>`, `technology:<name>`, `endpoint:<url>`, `vulnerability:<template_id/name>`.
  Typed edge formats: `RESOLVES_TO`, `HOSTS`, `RUNS_TECHNOLOGY`, `HAS_ENDPOINT`, `HAS_VULNERABILITY`.

### 1.2 Test Execution Results
- `pytest tests/investigation/ -v`:
  - **13 passed, 17 warnings in 1.07s**.
- `pytest tests/ --ignore=tests/workspace -q`:
  - **543 passed in 18.59s**.
  - All existing unit, integration, and CLI tests are passing.

---

## 2. Logic Chain

### 2.1 Investigation Creation from Observations & Correlations
1. In `CORRELATING` phase, `Observation` instances are ingested and correlated by `CorrelationEngine`.
2. `EvidenceFusionEngine.process_mission_state()` fuses observations and correlations into `EvidenceBundle`s in `mission.evidence_bundles` (`argus/correlation/fusion.py:77-83`).
3. In `BUILDING_INVESTIGATIONS` phase, `InvestigationBuilder.build_all()` iterates over `bundle_registry.get_all()`.
4. For each bundle, `InvestigationGenerator.process_bundle(bundle)` determines the category, attempts deduplication via `_find_duplicate(bundle, category)`, and merges the bundle into an existing investigation or creates a new `Investigation` in `inv_registry`.
5. `_merge(inv, bundle)` updates context fields (`business_objects`, `workflows`, `related_endpoints`, `related_graph_nodes`, `related_graph_edges`, `observations`, `correlations`) and triggers metric recalculation (`priority`, `confidence`, `reasoning`, `manual_validation`).

### 2.2 Current Priority Computation
1. `PriorityEngine.evaluate()` invokes `ScoreCalculator.calculate()`.
2. `ScoreCalculator` computes a base score (0–100) via weighted sum of 6 core factors (weights sum to 1.0):
   - Evidence Strength (weight 0.25)
   - Workflow Importance (weight 0.20)
   - Business Object Importance (weight 0.20)
   - Observation Confidence (weight 0.15)
   - Correlation Confidence (weight 0.10)
   - Reachability (weight 0.10)
3. Adds bonus factors: Graph Completeness (weight 0.05) and Technology Confidence (weight 0.05).
4. Applies multipliers: Administrative Context (1.2x), Authorization Context (1.1x), Authentication Context (1.1x), Mission Policy Alignment (1.15x), Mission Scope Alignment (1.1x).
5. Clamps score to [0.0, 100.0] and maps to `InvestigationPriority` enum (`CRITICAL` >= 90, `HIGH` >= 70, `MEDIUM` >= 40, `LOW` >= 10, `INFORMATIONAL` < 10).
6. `PriorityEngine.evaluate_all()` sorts via `InvestigationRanker.rank(highest_first=True)` and populates `mission.priority_scores` and `mission.priority_queue`.

### 2.3 Incorporating KnowledgeGraph Metrics into PriorityEngine
To satisfy Requirement R2 and Acceptance Criteria:
1. **Graph Resolution**: `ScoreCalculator.calculate()` and `PriorityEngine.evaluate()` should retrieve the `KnowledgeGraph` from `graph or getattr(mission, 'attack_surface_graph', getattr(mission, 'graph', None))`.
2. **Node Association**: Map the investigation to its corresponding `live_host` node(s) and connected entities using `inv.related_graph_nodes`, `inv.related_endpoints`, `inv.technologies`, and underlying evidence items.
3. **Node Degree / Centrality**:
   - For associated host nodes, compute degree: `degree = len(graph.edges_from(host_node)) + len(graph.edges_to(host_node))` (or `len(graph.neighbors(host_node))`).
   - A host with higher degree (e.g. many endpoints, technologies, subdomains) represents a larger attack surface. This increases the reachability/centrality component and appends an explanation (e.g. `"High graph degree / centrality (X connected nodes) indicates significant attack surface."`).
4. **`HAS_VULNERABILITY` Edges**:
   - Check if any resolved host node or connected node has outgoing `HAS_VULNERABILITY` edges:
     `has_vulns = any(e.type == "HAS_VULNERABILITY" for e in graph.edges_from(host_node))` or check `host_node.id not in [h.id for h in graph.get_hosts_without_vulnerabilities()]`.
   - If present, apply a significant priority boost (or bonus multiplier/factor) and append explanation: `"Associated host node has active vulnerability relationships (HAS_VULNERABILITY)."`
   - *Directly satisfies Acceptance Criterion*: "An investigation touching a host node with a `HAS_VULNERABILITY` edge has a higher priority than one without."
5. **Vulnerable Technologies**:
   - Check if the host node has `RUNS_TECHNOLOGY` edges connecting to technologies associated with vulnerabilities.
   - Boost priority and explain: `"Host runs technologies associated with identified vulnerabilities."`

### 2.4 Clustering Investigations for the Same Host Node
1. **Current Failure Mode**: `InvestigationGenerator._find_duplicate` matches only on exact `category` and non-empty shared `business_objects` or `workflows`. If two bundles belong to the same host (`api.example.com`) but lack shared business objects or have different categories (e.g. `TECHNOLOGY` vs `API`), separate duplicate investigations are created for the same host.
2. **Graph-Aware Host Clustering**:
   - When `InvestigationGenerator.process_bundle(bundle, graph=graph)` runs, resolve the target host identifier / `live_host` node ID:
     - From `bundle.graph_nodes` (e.g. `live_host:...`).
     - From `bundle.metadata['endpoints']`, `bundle.metadata['urls']`, `bundle.evidence` (resolving URLs to hostname/netloc or querying `graph.nodes_by_type('live_host')`).
     - Using `graph` edges (e.g., endpoint nodes trace to their parent `live_host` via incoming `HAS_ENDPOINT` edge).
   - In `_find_duplicate(bundle, category, graph=graph)`:
     - Check if an existing investigation in `inv_registry` already covers the same host node / hostname (`inv.related_graph_nodes` or host metadata).
     - If a matching host is found, return the existing investigation for merging (`self._merge(existing_inv, bundle)`).
     - Otherwise, fall back to business object / workflow deduplication.
3. **Merge Result**:
   - Merges `related_graph_nodes`, `related_endpoints`, `evidence_bundles`, `observations`, `correlations`.
   - Re-evaluates priority and confidence with the combined topology.
   - *Directly satisfies Acceptance Criterion*: "Investigations on the same host node are clustered (not duplicated as separate investigations with identical host metadata)."

### 2.5 Passing Graph to InvestigationBuilder in `mission_runtime.py`
1. In `AutonomousMissionRuntime.step()` during `BUILDING_INVESTIGATIONS` (`argus/runtime/mission_runtime.py:155-161`):
   - Update call:
     ```python
     graph = getattr(mission, "attack_surface_graph", getattr(mission, "graph", None))
     self.investigation_builder.build_all(mission=mission, graph=graph)
     self.investigation_builder.prioritize_all(mission=mission, graph=graph)
     ```
2. In `InvestigationBuilder`:
   - Support `build_all(mission=None, graph=None)`:
     Extracts graph from `graph or getattr(mission, 'attack_surface_graph', None)` and passes to `self.generator.process_bundle(bundle, graph=graph)`.
   - Support `prioritize_all(mission=None, graph=None)`:
     Passes `graph` to `self.prio_engine.evaluate_all(invs, mission=mission, graph=graph)`.
3. In `argus/runtime/controller.py:45`:
   - Initialize `InvestigationBuilder` cleanly with mission registries while remaining backward-compatible.

---

## 3. Caveats

- **No Caveats.**
- Note on Weight Validation: `WeightConfig.validate_weights()` validates that base weights sum to ~1.0. Any graph-specific score adjustments should be designed as bonus factors (like `graph_completeness_weight`) or context multipliers (like `administrative_context_bonus` / `has_vulnerability_bonus`) rather than altering base weight distribution in a way that breaks existing weight validation.

---

## 4. Conclusion

1. `InvestigationBuilder` and `InvestigationGenerator` currently process bundles sequentially without host-aware clustering or graph traversal.
2. `PriorityEngine` and `ScoreCalculator` currently use shallow string-list checks for graph completeness instead of querying `KnowledgeGraph` degree, centrality, or `HAS_VULNERABILITY` edges.
3. Full integration requires:
   - Passing `mission.attack_surface_graph` into `InvestigationBuilder.build_all()` and `InvestigationBuilder.prioritize_all()`.
   - Adding host-aware clustering in `InvestigationGenerator._find_duplicate()` to merge bundles sharing the same host node.
   - Adding graph topology queries in `ScoreCalculator` for node degree / centrality, `HAS_VULNERABILITY` edge detection, and vulnerable technology boosts.
4. All existing 543 tests are currently passing and must remain green.

---

## 5. Verification Method

### Test Commands
1. Run investigation test suite:
   ```bash
   pytest tests/investigation/ -v
   ```
2. Run full test suite:
   ```bash
   pytest tests/ --ignore=tests/workspace -q
   ```
3. Run E2E mission test:
   ```bash
   pytest tests/runtime/test_e2e_mission.py -v
   ```

### Specific Invalidation Conditions
- Any regression in the 543 passing tests.
- Base weights in `WeightConfig` failing validation (`sum != 1.0`).
- Investigations for the same host node failing to cluster into a unified investigation.
- An investigation for a host with a `HAS_VULNERABILITY` edge having a lower or equal priority compared to an identical one without vulnerabilities.
