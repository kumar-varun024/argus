# Handoff Report: Graph-Aware Investigation Building (R2) & Hypothesis Scoring (R3)

**Author:** `explorer_survey_investigation_hypothesis`  
**Working Directory:** `/home/varun/argus/.agents/explorer_survey_investigation_hypothesis`  
**Date:** 2026-08-28  
**Scope:** Investigation of R2 (Graph-Aware Investigation Building & Priority Engine) and R3 (Graph-Aware Hypothesis Confidence Scorer & Ranker), including KnowledgeGraph traversal, AutonomousMissionRuntime integration, mathematical formulas, interface signatures, and test specifications.

---

## 1. Observation

Direct code observations from the ARGUS codebase:

### 1.1 Knowledge Graph Architecture (`argus/graph/`)
- `argus/graph/graph.py` implements `KnowledgeGraph` with methods:
  - `add(node: Node) -> bool`, `get(node_id: str) -> Optional[Node]`, `connect(source: str, target: str, edge_type: str, metadata: dict) -> bool`
  - `nodes_by_type(node_type: str) -> list[Node]`, `edges_from(node: Node) -> list[Edge]`, `edges_to(node: Node) -> list[Edge]`, `neighbors(node: Node) -> list[Node]`
  - `get_node_degree(node_or_id: Union[str, Node]) -> int` (Lines 320–338: returns `len(edges_from) + len(edges_to)`)
  - `get_host_for_node(node_or_id: Union[str, Node]) -> Optional[Node]` (Lines 216–262: resolves nodes via BFS up to 3 hops to `live_host`)
  - `in_same_host_subgraph(node_id1: str, node_id2: str) -> bool` (Lines 264–284: checks if two nodes resolve to the same host or connected within 2 hops)
  - `are_connected(node_id1: str, node_id2: str, max_depth: int = 2) -> bool` (Lines 285–318: undirected BFS)
- `argus/graph/attack_surface.py`: `AttackSurfaceGraphBuilder.build(mission)` attaches the graph to `mission.attack_surface_graph` and `mission.graph`. Standard node types include `target`, `subdomain`, `live_host`, `endpoint`, `technology`, and `vulnerability`. Standard edge types include `RESOLVES_TO`, `HOSTS`, `HAS_ENDPOINT`, `RUNS_TECHNOLOGY`, `HAS_VULNERABILITY`.

### 1.2 Current Investigation Building & Prioritization (`argus/investigation/`)
- `argus/investigation/builder.py`:
  - `InvestigationBuilder.__init__` accepts `(inv_registry, bundle_registry, corr_registry, obs_registry, weight_config=None)`. Does not accept or reference `KnowledgeGraph`.
  - `build_all()` iterates over `bundle_registry.get_all()` and calls `self.generator.process_bundle(bundle)`. Does not pass `mission` or graph.
  - `prioritize_all(mission: Any = None) -> List[Investigation]` calls `self.prio_engine.evaluate_all(invs, mission)`.
- `argus/investigation/generator.py`:
  - `InvestigationGenerator.process_bundle(bundle)` determines category and calls `_find_duplicate(bundle, category)`.
  - Lines 73–82: `_find_duplicate` only checks for shared `business_objects` or `workflows` within the same category. It does **not** cluster by host subgraph or graph topology.
  - Lines 84–111: `_merge` populates fields, calls `inv.priority = self.prio_engine.evaluate(inv)`, and `inv.confidence = self.conf_scorer.calculate_confidence(inv)`.
- `argus/investigation/priority_engine.py`:
  - `PriorityEngine.evaluate(investigation, mission=None)` invokes `self.score_calculator.calculate(investigation, self.bundle_registry, mission)`.
  - `PriorityEngine.evaluate_all(investigations, mission=None)` evaluates all and ranks via `InvestigationRanker.rank(investigations, highest_first=True)`, writing to `mission.priority_scores` and `mission.priority_queue`.
- `argus/investigation/scoring.py`:
  - `ScoreCalculator.calculate` computes base weighted factors (`evidence_strength` [0.25], `workflow_importance` [0.20], `business_object_importance` [0.20], `observation_confidence` [0.15], `correlation_confidence` [0.10], `reachability` [0.10]) and bonus factors (`graph_completeness_weight` [0.05], `technology_confidence_weight` [0.05]).
  - Lines 181–191: `_calculate_graph_completeness` only counts lengths of string lists `investigation.related_graph_nodes` and `investigation.related_graph_edges`. It does **not** traverse `mission.attack_surface_graph`, does **not** evaluate node degree, and does **not** detect `HAS_VULNERABILITY` edges.
- `argus/investigation/weights.py`:
  - `WeightConfig` validates base weights sum to ~1.0. Multipliers (e.g. `administrative_context_bonus = 1.2`, `mission_policy_bonus = 1.15`) are applied after summation.

### 1.3 Current Hypothesis Engine, Scorer, and Ranker (`argus/hypothesis/`)
- `argus/hypothesis/engine.py`:
  - `HypothesisEngine.__init__` initializes `registry`, `conf_scorer = HypothesisConfidenceScorer()`, `ranker = HypothesisRanker()`, `lifecycle = HypothesisLifecycleManager()`, `generator = HypothesisGenerator(registry, conf_scorer, ranker)`.
  - `process_investigation(investigation: Investigation, mission: Mission = None)` calls `self.generator.process_investigation(investigation, mission)`. Auto-proposes if `confidence > 0.8`.
  - `evaluate_all(mission: Mission = None)` re-calculates confidence and priority for all registered hypotheses.
- `argus/hypothesis/confidence.py`:
  - Lines 14–37: `HypothesisConfidenceScorer.calculate_confidence(hypothesis, mission_context=None)`.
  - Lines 39–64: `_calculate_from_mission` computes `max(evidence_confidences) + (len(evidence_confidences) - 1) * 0.05`.
  - There is zero graph inspection; isolated hosts and highly connected hosts with identical evidence receive the exact same confidence score.
- `argus/hypothesis/ranking.py`:
  - Lines 34–68: `HypothesisRanker.evaluate_priority(hypothesis, mission_context=None)` scores `confidence * 40.0 + min(len(bo)*5, 20) + min(len(wf)*10, 20) + min(total_evidence*5, 20)`. No graph degree or graph topology weighting is used.

### 1.4 Runtime Loop Execution (`argus/runtime/mission_runtime.py`)
- Lines 155–161 (`BUILDING_INVESTIGATIONS`):
  ```python
  EventBus().publish(RuntimeEventType.INVESTIGATION_STARTED, mission.id)
  self.investigation_builder.build_all()
  self.investigation_builder.prioritize_all(mission)
  self.state_machine.transition_to(MissionState.GENERATING_HYPOTHESES, "Generating hypotheses")
  ```
  `build_all()` does not pass `mission` to `InvestigationBuilder`.
- Lines 163–183 (`GENERATING_HYPOTHESES`):
  ```python
  self.hypothesis_engine.evaluate_all(mission)
  self.learning_engine.process_mission(mission)
  ```
  `GENERATING_HYPOTHESES` calls `evaluate_all(mission)`, but **never invokes `process_investigation(inv, mission)`** on the investigations built in the previous state. As a result, `mission.hypotheses` remains empty in full-mission execution unless `process_investigation` is called for each investigation.

---

## 2. Logic Chain

From the observations above, we establish the following deductive reasoning chain:

1. **Investigation Clustering Gap (R2)**:
   - *Premise*: Evidence bundles from the same host or host subgraph should cluster into unified investigations rather than fragmented entries.
   - *Inference*: `InvestigationGenerator._find_duplicate` must query `KnowledgeGraph.in_same_host_subgraph(n1, n2)` or match resolved `live_host` nodes between bundles/investigations.
2. **Investigation Priority Scoring Gap (R2)**:
   - *Premise*: Acceptance Criterion specifies: *"Host with HAS_VULNERABILITY edge has higher priority investigation than host without"* and *"Investigations on hosts with more connections or vulnerable technology receive higher priority"*.
   - *Inference*: `ScoreCalculator` must:
     a. Extract `KnowledgeGraph` from `mission.attack_surface_graph` or `graph` parameter.
     b. Resolve investigation nodes/endpoints to graph `live_host` nodes.
     c. Calculate graph connectivity bonus based on node degree: $Degree(Host) = |Edges_{in}(Host)| + |Edges_{out}(Host)|$.
     d. Detect if any connected node has outgoing/incoming `HAS_VULNERABILITY` edges (e.g. $e.type == 'HAS\_VULNERABILITY'$).
     e. Apply a dedicated graph vulnerability multiplier `graph_vulnerability_bonus` (e.g., $1.30\times$) and graph connectivity multiplier `graph_connectivity_bonus` (e.g., $1.15\times$ for degree $\ge 3$).
3. **Hypothesis Confidence Connectivity Weighting Gap (R3)**:
   - *Premise*: Acceptance Criterion specifies: *"Well-connected host hypothesis has higher confidence than isolated node (unit test)"*.
   - *Inference*: `HypothesisConfidenceScorer` must modulate base confidence using a monotonic graph connectivity factor:
     $$\text{ConnectivityMultiplier} = 0.85 + \min(0.35, \text{MaxDegree} \times 0.07)$$
     - For isolated node ($\text{degree} \le 1$): Multiplier is $0.85$–$0.92$ (penalty for isolation).
     - For moderate node ($\text{degree} = 2$): Multiplier is $0.99 \approx 1.0$.
     - For well-connected node ($\text{degree} \ge 5$): Multiplier is $1.20$.
     - Furthermore, if the host has a confirmed `HAS_VULNERABILITY` edge in the graph, apply a $1.10\times$ corroboration boost.
     - Final confidence is bounded in $[0.0, 1.0]$.
4. **Hypothesis Priority & Ranking Integration (R3)**:
   - *Inference*: `HypothesisRanker.evaluate_priority` benefits from higher confidence ($\text{confidence} \times 40.0$) and directly incorporates graph connectivity points ($\min(\text{MaxDegree} \times 2.0, 10.0)$), ensuring well-connected and vulnerable hosts rank at the top of `mission.hypotheses`.
5. **Runtime Lifecycle Pipeline Completion**:
   - *Premise*: In `BUILDING_INVESTIGATIONS`, `build_all(mission)` must supply the mission context. In `GENERATING_HYPOTHESES`, all investigations in `mission.investigations.get_all()` must be fed into `self.hypothesis_engine.process_investigation(inv, mission)` before `evaluate_all(mission)` is called.

---

## 3. Caveats

1. **No-Graph Fallback**: If `mission.attack_surface_graph` is `None` or empty (e.g., isolated unit tests), all scorers must gracefully fall back to baseline heuristics without raising `AttributeError` or returning `0.0` unexpectedly.
2. **Weight Configuration Constraint**: `WeightConfig.validate_weights()` enforces that the 6 core base weights sum to $1.0 \pm 0.01$. Graph bonuses must be implemented as multipliers or explicit bonus terms (like `administrative_context_bonus` and `graph_completeness_weight`) so existing weight validations continue to pass without error.
3. **Non-destructive Deduction**: An investigation or hypothesis on an isolated node must not be dropped; it should simply receive lower relative priority and confidence compared to well-connected targets.
4. **URL / Hostname Resolution**: Investigations reference endpoints (e.g., `http://api.example.com/v1/login`) while graph nodes are keyed as `live_host:http://api.example.com` or `endpoint:http://api.example.com/v1/login`. The node resolution helper must check exact ID, URL prefix matching, and hostname matching.

---

## 4. Conclusion & Proposed Architecture

### 4.1 Interface Signatures

#### A. Investigation Module
```python
# argus/investigation/weights.py
class WeightConfig(BaseModel):
    # Core base weights (sum = 1.0)
    evidence_strength: float = 0.25
    workflow_importance: float = 0.20
    business_object_importance: float = 0.20
    observation_confidence: float = 0.15
    correlation_confidence: float = 0.10
    reachability: float = 0.10

    # Multipliers & bonuses
    administrative_context_bonus: float = 1.2
    authorization_context_bonus: float = 1.1
    authentication_context_bonus: float = 1.1
    mission_policy_bonus: float = 1.15
    mission_scope_bonus: float = 1.1
    graph_completeness_weight: float = 0.05
    technology_confidence_weight: float = 0.05
    # New Graph-Aware parameters
    graph_connectivity_bonus: float = 1.15
    graph_vulnerability_bonus: float = 1.30

# argus/investigation/scoring.py
class ScoreCalculator:
    def calculate(
        self,
        investigation: Investigation,
        bundle_registry: Any = None,
        mission: Any = None,
        graph: Optional[KnowledgeGraph] = None
    ) -> Tuple[float, List[str]]: ...

# argus/investigation/priority_engine.py
class PriorityEngine:
    def evaluate(
        self,
        investigation: Investigation,
        mission: Any = None,
        graph: Optional[KnowledgeGraph] = None
    ) -> InvestigationPriority: ...

    def evaluate_all(
        self,
        investigations: List[Investigation],
        mission: Any = None,
        graph: Optional[KnowledgeGraph] = None
    ) -> List[Investigation]: ...

# argus/investigation/generator.py
class InvestigationGenerator:
    def process_bundle(
        self,
        bundle: EvidenceBundle,
        mission: Any = None,
        graph: Optional[KnowledgeGraph] = None
    ) -> Optional[Investigation]: ...

# argus/investigation/builder.py
class InvestigationBuilder:
    def build_all(self, mission: Any = None, graph: Optional[KnowledgeGraph] = None) -> None: ...
    def prioritize_all(self, mission: Any = None, graph: Optional[KnowledgeGraph] = None) -> List[Investigation]: ...
```

#### B. Hypothesis Module
```python
# argus/hypothesis/confidence.py
class HypothesisConfidenceScorer:
    def calculate_confidence(
        self,
        hypothesis: Hypothesis,
        mission_context: Any = None,
        graph: Optional[KnowledgeGraph] = None
    ) -> float: ...

# argus/hypothesis/ranking.py
class HypothesisRanker:
    def evaluate_priority(
        self,
        hypothesis: Hypothesis,
        mission_context: Any = None,
        graph: Optional[KnowledgeGraph] = None
    ) -> float: ...

# argus/hypothesis/generator.py
class HypothesisGenerator:
    def process_investigation(
        self,
        investigation: Investigation,
        mission: Any = None,
        graph: Optional[KnowledgeGraph] = None
    ) -> Optional[Hypothesis]: ...

# argus/hypothesis/engine.py
class HypothesisEngine:
    def process_investigation(
        self,
        investigation: Investigation,
        mission: Any = None,
        graph: Optional[KnowledgeGraph] = None
    ) -> Optional[Hypothesis]: ...

    def evaluate_all(
        self,
        mission: Any = None,
        graph: Optional[KnowledgeGraph] = None
    ) -> None: ...
```

#### C. Runtime State Machine Transitions
```python
# argus/runtime/mission_runtime.py

# In BUILDING_INVESTIGATIONS:
elif mission.status == MissionState.BUILDING_INVESTIGATIONS:
    EventBus().publish(RuntimeEventType.INVESTIGATION_STARTED, mission.id)
    self.investigation_builder.build_all(mission)
    self.investigation_builder.prioritize_all(mission)
    self.investigation_builder.update_reasoning_tree(mission.reasoning_tree)
    self.state_machine.transition_to(MissionState.GENERATING_HYPOTHESES, "Generating hypotheses")
    return

# In GENERATING_HYPOTHESES:
elif mission.status == MissionState.GENERATING_HYPOTHESES:
    if hasattr(mission, "investigations") and hasattr(mission.investigations, "get_all"):
        for inv in mission.investigations.get_all():
            self.hypothesis_engine.process_investigation(inv, mission)
    self.hypothesis_engine.evaluate_all(mission)
    self.learning_engine.process_mission(mission)
    ...
```

---

### 4.2 Formulas

#### 1. Investigation Priority Score Formula
$$\text{BaseScore} = \sum w_i \cdot F_i + w_{\text{graph}} \cdot C_{\text{graph}} + w_{\text{tech}} \cdot C_{\text{tech}}$$
$$\text{Multipliers} = \prod M_{\text{context}} \times (M_{\text{graph\_conn}} \text{ if } \text{Degree} \ge 3 \text{ else } 1.0) \times (M_{\text{graph\_vuln}} \text{ if HAS\_VULNERABILITY else } 1.0)$$
$$\text{FinalScore} = \min(100.0, \max(0.0, \text{BaseScore} \times \text{Multipliers}))$$

Where:
- $M_{\text{graph\_vuln}} = 1.30$
- $M_{\text{graph\_conn}} = 1.15$
- Ensures a host with a `HAS_VULNERABILITY` edge scores strictly higher (by $\ge 30\%$) than an identical host without.

#### 2. Hypothesis Confidence Score Formula
$$\text{BaseConf} = \max(\text{Conf}_{\text{bundles}}, \text{Conf}_{\text{invs}}) + (\text{Count}_{\text{evidence}} - 1) \times 0.05$$
$$\text{ConnectivityMultiplier} = 0.85 + \min(0.35, \text{MaxDegree} \times 0.07)$$
$$\text{VulnBonus} = 1.10 \text{ if host has HAS\_VULNERABILITY else } 1.0$$
$$\text{Penalties} = \begin{cases} 0.8 & \text{if } \text{Count}_{\text{evidence}} = 1 \\ 0.0 & \text{if } \text{Count}_{\text{evidence}} = 0 \\ 1.0 & \text{otherwise} \end{cases}$$
$$\text{HypothesisConfidence} = \min(1.0, \max(0.0, \text{BaseConf} \times \text{ConnectivityMultiplier} \times \text{VulnBonus} \times \text{Penalties}))$$

---

## 5. Verification Method

### 5.1 Test Suite Verification Command
Run the complete regression suite:
```bash
python -m pytest tests/ --ignore=tests/workspace -q
```
*Current state: 543 passed in 19.5s.*

### 5.2 Unit Test Cases for R2 & R3

Create `tests/investigation/test_graph_investigation.py` and `tests/hypothesis/test_graph_hypothesis.py` with the following test cases:

1. `test_investigation_priority_with_vulnerability_edge()`:
   - Construct two hosts: `live_host:http://vuln.example.com` and `live_host:http://clean.example.com`.
   - Add `HAS_VULNERABILITY` edge to `vuln.example.com`.
   - Build two identical investigations for both hosts.
   - Assert `inv_vuln.priority_score > inv_clean.priority_score`.
   - Assert `"Host has confirmed vulnerability relationships in knowledge graph."` in `inv_vuln.priority_explanation`.

2. `test_investigation_priority_with_connected_graph_nodes()`:
   - Construct a host with 5 endpoints and 2 technologies (degree = 8) and an isolated host (degree = 1).
   - Evaluate priority for investigations on both hosts.
   - Assert well-connected host receives `graph_connectivity_bonus` and ranks first.

3. `test_investigation_clustering_by_host_subgraph()`:
   - Create two evidence bundles referencing two different endpoints on the same live host.
   - Process both bundles through `InvestigationGenerator`.
   - Assert they cluster into a single consolidated `Investigation` based on `graph.in_same_host_subgraph`.

4. `test_hypothesis_confidence_well_connected_vs_isolated()`:
   - Setup `KnowledgeGraph` with well-connected host (degree 6) and isolated host (degree 1).
   - Create two hypotheses with identical base evidence confidence (e.g. 0.70).
   - Compute confidence via `HypothesisConfidenceScorer.calculate_confidence(hyp, graph=kg)`.
   - Assert `hyp_connected.confidence > hyp_isolated.confidence`.

5. `test_hypothesis_ranker_graph_topology_weighting()`:
   - Rank hypotheses with equal evidence but varying graph connectivity.
   - Assert well-connected host hypothesis achieves higher `priority_score` and higher rank in `HypothesisRanker.rank()`.

6. `test_runtime_investigations_and_hypotheses_generation_e2e()`:
   - Execute `AutonomousMissionRuntime.step()` through `BUILDING_INVESTIGATIONS` and `GENERATING_HYPOTHESES`.
   - Assert `len(mission.investigations.get_all()) >= 1`.
   - Assert `len(mission.hypotheses.get_all()) >= 1`.
   - Assert `mission.priority_queue` contains ranked investigation IDs.

### 5.3 Invalidation Conditions
- Any changes to base weights in `WeightConfig` that break the $1.0$ sum invariant.
- Omission of `mission.investigations` iteration during `GENERATING_HYPOTHESES` step in `AutonomousMissionRuntime`.
- Graph traversal raising `KeyError` on unknown node IDs (must use `graph.get()` defensively).
