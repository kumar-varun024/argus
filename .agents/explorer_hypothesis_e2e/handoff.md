# Handoff Report: Hypothesis Engine Graph Integration & E2E Pipeline Analysis

**Agent**: Explorer 3 (Hypothesis & E2E Specialist)  
**Working Directory**: `/home/varun/argus/.agents/explorer_hypothesis_e2e`  
**Date**: 2026-08-28  
**Mission**: Investigate Hypothesis Engine graph integration (R3), full E2E pipeline test (R4 & R5 baseline), and runtime lifecycle gaps.

---

## 1. Observation

### 1.1 Baseline Test Suite Execution
- **Command**: `python -m pytest tests/ --ignore=tests/workspace -x -q`
- **Result**: `543 passed, 12344 warnings in 21.20s` (exit code `0`).
- **Status**: Complete test suite passes cleanly with zero failures.

### 1.2 Current State of `HypothesisConfidenceScorer`
- **File**: `argus/hypothesis/confidence.py` (lines 11–64)
- **Observed Code**:
```python
class HypothesisConfidenceScorer:
    def calculate_confidence(self, hypothesis: Hypothesis, mission_context: 'Mission' = None) -> float:
        base_confidence = 0.0
        if mission_context:
            base_confidence = self._calculate_from_mission(hypothesis, mission_context)
        else:
            base_confidence = hypothesis.metadata.get('max_investigation_confidence', 0.2)

        num_evidence = len(hypothesis.related_evidence) + len(hypothesis.related_observations)
        if num_evidence == 1:
            base_confidence *= 0.8
        elif num_evidence == 0:
            base_confidence = 0.0

        final_confidence = min(max(base_confidence, 0.0), 1.0)
        return final_confidence

    def _calculate_from_mission(self, hypothesis: Hypothesis, mission: 'Mission') -> float:
        evidence_confidences = []
        for evid in hypothesis.related_evidence:
            if hasattr(mission, 'evidence_bundles'):
                bundle = mission.evidence_bundles.find(evid)
                if bundle:
                    evidence_confidences.append(bundle.confidence)
        for iid in hypothesis.related_investigations:
            if hasattr(mission, 'investigations'):
                inv = mission.investigations.find(iid)
                if inv:
                    evidence_confidences.append(inv.confidence)
        if not evidence_confidences:
            return 0.1
        max_conf = max(evidence_confidences)
        bonus = (len(evidence_confidences) - 1) * 0.05
        return min(max_conf + bonus, 1.0)
```
- **Finding**: Currently `HypothesisConfidenceScorer` only looks at `evidence_bundles` and `investigations` confidences. It does **not** inspect `mission.attack_surface_graph` or `mission.graph`, nor does it perform any topology/degree/endpoint connectivity calculations.

### 1.3 Current State of `HypothesisRanker`
- **File**: `argus/hypothesis/ranking.py` (lines 7–69)
- **Observed Code**:
```python
class HypothesisRanker:
    def evaluate_priority(self, hypothesis: Hypothesis, mission_context: Any = None) -> float:
        score = 0.0
        # 1. Base score from Confidence (up to 40 points)
        score += hypothesis.confidence * 40.0
        # 2. Business Impact (up to 20 points)
        if hypothesis.business_objects:
            score += min(len(hypothesis.business_objects) * 5, 20)
        # 3. Workflow Importance (up to 20 points)
        if hypothesis.workflows:
            score += min(len(hypothesis.workflows) * 10, 20)
        # 4. Evidence Strength / Volume (up to 20 points)
        total_evidence = len(hypothesis.related_evidence) + len(hypothesis.related_investigations)
        score += min(total_evidence * 5, 20)
        hypothesis.priority_score = min(score, 100.0)
        ...
```
- **Finding**: Priority calculation takes `mission_context` as a parameter but ignores it completely.

### 1.4 Current State of `AutonomousMissionRuntime` during `GENERATING_HYPOTHESES`
- **File**: `argus/runtime/mission_runtime.py` (lines 163–183)
- **Observed Code**:
```python
        elif mission.status == MissionState.GENERATING_HYPOTHESES:
            self.hypothesis_engine.evaluate_all(mission)
            self.learning_engine.process_mission(mission)
            if self.task_scheduler.queue_manager.is_complete():
                action = self.checkpointer.evaluate_checkpoint("pre_completion", mission)
                if action == CheckpointAction.APPROVE:
                    self.state_machine.transition_to(MissionState.COMPLETED, "Mission complete")
                    from argus.runtime.events import EventBus, RuntimeEventType
                    EventBus().publish(RuntimeEventType.MISSION_COMPLETED, mission.id)
```
- **Observed Defect / Gap**: `HypothesisEngine.evaluate_all(mission)` only iterates over `self.registry.get_all()`. But during `BUILDING_INVESTIGATIONS`, `InvestigationBuilder` created investigations in `mission.investigations`. Nobody in the runtime calls `self.hypothesis_engine.process_investigation(inv, mission)`.
- **Runtime Execution Verification Result**:
  When running the full mission loop in test environment:
  - `mission.attack_surface_graph.get_asset_counts()`: `{'target': 1, 'subdomain': 2, 'live_host': 2, 'endpoint': 2, 'technology': 2, 'vulnerability': 1}` (10 nodes, 9 edges)
  - `Correlations count`: `0`
  - `Evidence bundles count`: `9`
  - `Investigations count`: `9`
  - `Hypotheses count`: `0` (Hypothesis registry remains completely empty)

### 1.5 Current State of `tests/runtime/test_e2e_mission.py`
- **File**: `tests/runtime/test_e2e_mission.py` (lines 76–167)
- **Existing Assertions**:
  - `assert mission.status == MissionState.COMPLETED`
  - Asserts `mission.evidence` has elements and matches categories `{"subdomain", "live_host", "technology", "endpoint", "vulnerability"}`
  - Asserts structured attributes on `mission`: `subdomains`, `live_hosts`, `endpoints`, `vulnerabilities`, `technologies`
  - Asserts `execution_results` exists
- **Missing Assertions (R4 Requirement)**:
  - No assertion on `mission.attack_surface_graph is not None`
  - No assertion on `mission.attack_surface_graph.get_asset_counts()`
  - No assertion on `mission.correlations` producing at least 1 correlation
  - No assertion on `mission.investigations` producing at least 1 investigation
  - No assertion on `mission.hypotheses` producing at least 1 hypothesis

---

## 2. Logic Chain

### 2.1 Confidence Calculation Mechanism & Graph Topology Boost (R3)
1. **Current Confidence Calculation Flow**:
   - `HypothesisConfidenceScorer.calculate_confidence(hypothesis, mission_context)` evaluates base confidence by extracting `bundle.confidence` and `inv.confidence` from `mission.evidence_bundles` and `mission.investigations`.
   - Single-evidence penalty: If only 1 piece of evidence exists, confidence is multiplied by 0.8.
   - If 0 pieces of evidence exist, confidence is 0.0.
   - Result is bounded in `[0.0, 1.0]`.

2. **Graph Boost Design (Requirement R3)**:
   - When `mission_context` (or `mission_context.attack_surface_graph` / `mission_context.graph`) is present:
   - Identify candidate host nodes connected to the hypothesis:
     - Direct references in `hypothesis.supporting_graph_nodes` (e.g. `live_host:...`, `subdomain:...`).
     - Matching `live_host` nodes corresponding to `hypothesis.related_endpoints`.
     - Underlying nodes referenced in `hypothesis.related_investigations` and `hypothesis.related_evidence`.
   - Query the `KnowledgeGraph` for host topology:
     - Total degree of host node: `degree = len(graph.edges_from(node)) + len(graph.edges_to(node))`.
     - Outgoing `HAS_ENDPOINT` edges: `endpoints_count = len([e for e in graph.edges_from(node) if e.type == "HAS_ENDPOINT"])`.
     - Outgoing `HAS_VULNERABILITY` edges: `vulns_count = len([e for e in graph.edges_from(node) if e.type == "HAS_VULNERABILITY"])`.
     - Outgoing `RUNS_TECHNOLOGY` edges: `techs_count = len([e for e in graph.edges_from(node) if e.type == "RUNS_TECHNOLOGY"])`.
   - **Boost Formula**:
     - If `degree > 1` (well-connected host): boost `+0.05` to `+0.10` based on degree (`0.05 + min(degree * 0.01, 0.05)`).
     - Connected endpoint volume: `+ min(endpoints_count * 0.02, 0.08)`.
     - Known vulnerability presence (`HAS_VULNERABILITY`): `+0.05`.
     - Isolated host (`degree <= 1`, 0 endpoints): receives **0.0 boost**.
   - **Mathematical Guarantee**: A hypothesis backed by evidence on a well-connected host (degree > 1, multiple endpoints) will strictly exceed the confidence of an identical hypothesis on an isolated host (degree <= 1).

### 2.2 AutonomousMissionRuntime End-to-End Orchestration
1. **During `PLANNING` & `COLLECTING_EVIDENCE`**:
   - `AttackSurfaceGraphBuilder().build(mission)` builds `mission.attack_surface_graph` and assigns `mission.graph`.
2. **During `CORRELATING`**:
   - Evidence records are wrapped into `Observation`s.
   - When creating `Observation`s, their `graph_nodes`, `endpoints`, `urls`, `technology` should be populated from evidence metadata so correlation rules can match.
   - `CorrelationEngine` and `CorrelationMatcher` must accept and query `mission.attack_surface_graph` so that observations in the same host neighborhood are correlated.
   - `fusion_engine.process_mission_state()` aggregates observations/correlations into `EvidenceBundle`s.
3. **During `BUILDING_INVESTIGATIONS`**:
   - `investigation_builder.build_all()` transforms `EvidenceBundle`s into `Investigation`s.
   - `investigation_builder.prioritize_all(mission)` ranks them using `PriorityEngine`.
4. **During `GENERATING_HYPOTHESES`**:
   - The runtime must iterate through all investigations in `mission.investigations.get_all()` and invoke `self.hypothesis_engine.process_investigation(inv, mission)`.
   - Then `self.hypothesis_engine.evaluate_all(mission)` evaluates confidence (with graph boost) and priority for all registered hypotheses.
   - This ensures `mission.hypotheses` is populated with well-ranked, graph-boosted hypotheses.

### 2.3 E2E Integration Test Assertions (R4)
The E2E test `test_e2e_mission_execution` in `tests/runtime/test_e2e_mission.py` runs against mocked tools (`subfinder`, `httpx`, `katana`, `nuclei`).
To fully validate the Sprint 3 pipeline, `test_e2e_mission.py` must assert:
1. `mission.attack_surface_graph is not None`
2. `asset_counts = mission.attack_surface_graph.get_asset_counts()` with non-zero counts for each category (`target`, `subdomain`, `live_host`, `endpoint`, `technology`, `vulnerability`)
3. `len(mission.correlations.get_all()) > 0`
4. `len(mission.evidence_bundles.get_all()) > 0`
5. `len(mission.investigations.get_all()) > 0`
6. `len(mission.hypotheses.get_all()) > 0`
7. `mission.status == MissionState.COMPLETED`

---

## 3. Caveats

1. **Mission Controller Registry Injection**: `MissionController._create_runtime` initializes `hypothesis_engine = HypothesisEngine(getattr(mission, 'hypotheses', None))`. When `mission` is initialized in `__post_init__`, `mission.hypotheses` is already a `HypothesisRegistry()`. Any hypotheses added via `HypothesisEngine.process_investigation()` are stored directly in `mission.hypotheses`.
2. **Investigation Confidence Threshold for Hypothesis Generation**: `HypothesisGenerator.process_investigation` has a guard: `if investigation.confidence < 0.4 and len(investigation.evidence_bundles) < 2: return None`. Downstream investigations must maintain sufficient confidence/evidence bundles so hypotheses are generated.
3. **Deprecation Warnings**: 12,344 deprecation warnings in pytest related to `datetime.utcnow()`. These do not cause failures (exit code is 0) but should be kept in mind for future hygiene.

---

## 4. Conclusion

1. **Hypothesis Graph Confidence Scoring (R3)**:
   - `HypothesisConfidenceScorer` should be extended with a graph boost method that inspects `mission.attack_surface_graph`.
   - Hosts with degree > 1 and multiple connected endpoints (`HAS_ENDPOINT`) receive a +0.05 to +0.15 confidence boost. Isolated hosts receive no boost.
   - `HypothesisRanker` should incorporate graph centrality and confidence into priority scoring.

2. **Mission Runtime Hypothesis Generation Fix**:
   - In `AutonomousMissionRuntime.step()` under `GENERATING_HYPOTHESES`:
     ```python
     elif mission.status == MissionState.GENERATING_HYPOTHESES:
         if hasattr(mission, "investigations") and hasattr(mission.investigations, "get_all"):
             for inv in mission.investigations.get_all():
                 self.hypothesis_engine.process_investigation(inv, mission)
         self.hypothesis_engine.evaluate_all(mission)
         self.learning_engine.process_mission(mission)
     ```
   - This wires the output of `BUILDING_INVESTIGATIONS` into `HypothesisEngine`.

3. **E2E Integration Verification (R4)**:
   - `tests/runtime/test_e2e_mission.py` must assert graph asset counts, correlation registry count > 0, investigation registry count > 0, and hypothesis registry count > 0.

4. **Zero Regression Baseline (R5)**:
   - Baseline is 543 passing tests in ~21.2s.

---

## 5. Verification Method

### 5.1 Test Commands
- Run E2E test:
  ```bash
  python -m pytest tests/runtime/test_e2e_mission.py -v
  ```
- Run Hypothesis test suite:
  ```bash
  python -m pytest tests/hypothesis/ -v
  ```
- Run full regression suite:
  ```bash
  python -m pytest tests/ --ignore=tests/workspace -x -q
  ```

### 5.2 Specific Unit Tests to Add for R3:
1. `test_confidence_boost_well_connected_host`: Assert confidence is higher for an observation on a host with degree > 1 and endpoints than on an isolated host (degree = 1, 0 endpoints).
2. `test_confidence_isolated_host_no_boost`: Assert isolated host with degree <= 1 receives baseline confidence without extra boost.
3. `test_hypothesis_ranker_graph_priority`: Assert ranker boosts priority score when host has rich graph topology and vulnerability edges.
4. `test_runtime_generating_hypotheses_phase`: Assert `AutonomousMissionRuntime` populates `mission.hypotheses` from `mission.investigations`.
