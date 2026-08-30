import pytest
import uuid
from typing import List, Optional

from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.edge import Edge

from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority
from argus.correlation.evidence import EvidenceBundle
from argus.correlation.matcher import CorrelationMatcher
from argus.correlation.rules import (
    match_shared_graph_nodes,
    match_graph_neighborhood,
    _extract_graph_nodes,
)
from argus.correlation.engine import CorrelationEngine
from argus.correlation.graph import CorrelationGraph
from argus.correlation.registry import (
    ObservationRegistry,
    CorrelationRegistry,
    EvidenceBundleRegistry,
)

from argus.investigation.models import Investigation, InvestigationCategory
from argus.investigation.registry import InvestigationRegistry
from argus.investigation.generator import InvestigationGenerator
from argus.investigation.scoring import ScoreCalculator
from argus.investigation.priority_engine import PriorityEngine
from argus.investigation.confidence import InvestigationConfidenceScorer
from argus.investigation.manual_validation import ManualValidationGenerator
from argus.investigation.explanation import ReasoningTreeBuilder
from argus.investigation.weights import WeightConfig

from argus.hypothesis.models import Hypothesis, HypothesisCategory, HypothesisPriority
from argus.hypothesis.registry import HypothesisRegistry
from argus.hypothesis.confidence import HypothesisConfidenceScorer
from argus.hypothesis.ranking import HypothesisRanker
from argus.hypothesis.generator import HypothesisGenerator
from argus.hypothesis.engine import HypothesisEngine


# ==============================================================================
# Helper Functions to Build Graph Topologies & Entities
# ==============================================================================

def create_isolated_host_graph(host_id: str = "host1.example.com") -> KnowledgeGraph:
    """Creates a graph with a single isolated live_host node."""
    kg = KnowledgeGraph()
    kg.add(Node(id=f"live_host:{host_id}", type="live_host", value=host_id))
    return kg


def create_dense_host_graph(host_id: str = "dense.example.com", endpoint_count: int = 5, with_vuln: bool = False) -> KnowledgeGraph:
    """Creates a densely connected host subgraph with live_host, subdomains, endpoints, tech, and optional vuln."""
    kg = KnowledgeGraph()
    h_node = Node(id=f"live_host:{host_id}", type="live_host", value=host_id)
    s_node = Node(id=f"subdomain:{host_id}", type="subdomain", value=host_id)
    t_node = Node(id="technology:nginx", type="technology", value="Nginx")
    kg.add(h_node)
    kg.add(s_node)
    kg.add(t_node)
    kg.connect(s_node.id, h_node.id, "RESOLVES_TO")
    kg.connect(h_node.id, t_node.id, "RUNS_TECHNOLOGY")

    for i in range(endpoint_count):
        ep_node = Node(id=f"endpoint:{host_id}/api/v{i}", type="endpoint", value=f"http://{host_id}/api/v{i}")
        kg.add(ep_node)
        kg.connect(h_node.id, ep_node.id, "HAS_ENDPOINT")

    if with_vuln:
        v_node = Node(id=f"vulnerability:CVE-2023-{host_id}", type="vulnerability", value="CVE-2023-XXXX")
        kg.add(v_node)
        kg.connect(h_node.id, v_node.id, "HAS_VULNERABILITY")

    return kg


def create_cyclic_graph() -> KnowledgeGraph:
    """Creates a graph with various cycles: A->B->C->A, self-loops, and bidirectional edges."""
    kg = KnowledgeGraph()
    n_a = Node(id="live_host:cycle_a", type="live_host", value="cycle_a.com")
    n_b = Node(id="endpoint:cycle_b", type="endpoint", value="http://cycle_a.com/b")
    n_c = Node(id="endpoint:cycle_c", type="endpoint", value="http://cycle_a.com/c")
    n_d = Node(id="technology:cycle_d", type="technology", value="TechD")

    for n in [n_a, n_b, n_c, n_d]:
        kg.add(n)

    # Simple 3-cycle: A -> B -> C -> A
    kg.connect(n_a.id, n_b.id, "HAS_ENDPOINT")
    kg.connect(n_b.id, n_c.id, "CALLS")
    kg.connect(n_c.id, n_a.id, "REPORTS_TO")

    # Bidirectional edge between B and D
    kg.connect(n_b.id, n_d.id, "USES")
    kg.connect(n_d.id, n_b.id, "USED_BY")

    # Self loop A -> A
    kg.connect(n_a.id, n_a.id, "SELF_REF")

    return kg


def create_disconnected_graph(num_components: int = 5) -> KnowledgeGraph:
    """Creates a graph with multiple disjoint components."""
    kg = KnowledgeGraph()
    for c in range(num_components):
        h = Node(id=f"live_host:comp_{c}.com", type="live_host", value=f"comp_{c}.com")
        ep = Node(id=f"endpoint:comp_{c}.com/api", type="endpoint", value=f"http://comp_{c}.com/api")
        kg.add(h)
        kg.add(ep)
        kg.connect(h.id, ep.id, "HAS_ENDPOINT")
    return kg


def make_obs(title: str, graph_nodes: List[str] = None, endpoints: List[str] = None, tech: List[str] = None) -> Observation:
    return Observation(
        source="test_runner",
        category=ObservationCategory.TECHNOLOGY,
        priority=ObservationPriority.MEDIUM,
        title=title,
        description=f"Description for {title}",
        confidence=0.8,
        graph_nodes=graph_nodes or [],
        endpoints=endpoints or [],
        technology=tech or []
    )


# ==============================================================================
# SECTION 1: Isolated Nodes vs Densely Connected Subgraphs
# ==============================================================================

class TestIsolatedVsDenselyConnected:

    def test_correlation_dense_subgraph_matches_isolated_does_not(self):
        """Observations referencing nodes in a dense subgraph match via graph traversal; isolated do not."""
        kg = KnowledgeGraph()
        # Component 1: Host A with multiple connected endpoints
        h_a = Node(id="live_host:host_a.com", type="live_host", value="host_a.com")
        ep_a1 = Node(id="endpoint:host_a.com/users", type="endpoint", value="http://host_a.com/users")
        ep_a2 = Node(id="endpoint:host_a.com/admin", type="endpoint", value="http://host_a.com/admin")
        kg.add(h_a)
        kg.add(ep_a1)
        kg.add(ep_a2)
        kg.connect(h_a.id, ep_a1.id, "HAS_ENDPOINT")
        kg.connect(h_a.id, ep_a2.id, "HAS_ENDPOINT")

        # Component 2: Isolated Host B
        h_b = Node(id="live_host:host_b.com", type="live_host", value="host_b.com")
        kg.add(h_b)

        # Obs 1 referencing ep_a1, Obs 2 referencing ep_a2 (connected through h_a within 2 hops)
        obs1 = make_obs("Obs1", graph_nodes=[ep_a1.id], endpoints=["http://host_a.com/users"])
        obs2 = make_obs("Obs2", graph_nodes=[ep_a2.id], endpoints=["http://host_a.com/admin"])
        # Obs 3 referencing isolated host B
        obs3 = make_obs("Obs3", graph_nodes=[h_b.id], endpoints=["http://host_b.com/login"])

        # Obs 1 and Obs 2 should match via graph neighborhood (connected via host A)
        assert match_graph_neighborhood(obs1, obs2, graph=kg, max_hops=2) is True
        assert match_shared_graph_nodes(obs1, obs2, graph=kg) is True

        # Obs 1 and Obs 3 are in disconnected components -> should NOT match
        assert match_graph_neighborhood(obs1, obs3, graph=kg, max_hops=2) is False
        assert match_shared_graph_nodes(obs1, obs3, graph=kg) is False

    def test_investigation_clustering_dense_subgraph_merges_isolated_separates(self):
        """Bundles belonging to same host subgraph are clustered; isolated hosts produce separate investigations."""
        kg = KnowledgeGraph()
        h1 = Node(id="live_host:host1.com", type="live_host", value="host1.com")
        ep1 = Node(id="endpoint:host1.com/api", type="endpoint", value="http://host1.com/api")
        kg.add(h1)
        kg.add(ep1)
        kg.connect(h1.id, ep1.id, "HAS_ENDPOINT")

        h2 = Node(id="live_host:host2.com", type="live_host", value="host2.com")
        kg.add(h2)

        inv_reg = InvestigationRegistry()
        bundle_reg = EvidenceBundleRegistry()
        conf_scorer = InvestigationConfidenceScorer(bundle_reg)
        prio_engine = PriorityEngine(bundle_reg)
        val_gen = ManualValidationGenerator()
        reasoning_builder = ReasoningTreeBuilder(bundle_reg, CorrelationRegistry(), ObservationRegistry())
        generator = InvestigationGenerator(inv_reg, conf_scorer, prio_engine, val_gen, reasoning_builder)

        # Bundle 1 on host1
        b1 = EvidenceBundle(
            title="Bundle 1",
            description="Bundle 1 description",
            confidence=0.8,
            strength=80.0,
            graph_nodes=[h1.id],
            metadata={"endpoints": ["http://host1.com/api"]}
        )
        # Bundle 2 on host1 endpoint
        b2 = EvidenceBundle(
            title="Bundle 2",
            description="Bundle 2 description",
            confidence=0.8,
            strength=80.0,
            graph_nodes=[ep1.id],
            metadata={"endpoints": ["http://host1.com/api"]}
        )
        # Bundle 3 on isolated host2
        b3 = EvidenceBundle(
            title="Bundle 3",
            description="Bundle 3 description",
            confidence=0.8,
            strength=80.0,
            graph_nodes=[h2.id],
            metadata={"endpoints": ["http://host2.com/other"]}
        )

        inv1 = generator.process_bundle(b1, graph=kg)
        inv2 = generator.process_bundle(b2, graph=kg)
        inv3 = generator.process_bundle(b3, graph=kg)

        # b1 and b2 should be merged into the same investigation
        assert inv1.id == inv2.id
        # b3 should create a new separate investigation
        assert inv3.id != inv1.id
        assert len(inv_reg.get_all()) == 2

    def test_score_calculator_dense_vs_isolated_host_priority(self):
        """Investigation on dense host (degree >= 3) receives connectivity bonus; isolated host does not."""
        kg_dense = create_dense_host_graph(host_id="dense.com", endpoint_count=4, with_vuln=False)
        kg_iso = create_isolated_host_graph(host_id="iso.com")

        calc = ScoreCalculator()

        inv_dense = Investigation(
            title="Dense Host Investigation",
            summary="Summary",
            description="Description",
            category=InvestigationCategory.API,
            related_graph_nodes=["live_host:dense.com"],
            related_endpoints=["http://dense.com/api/v0"],
            confidence=0.8
        )
        inv_iso = Investigation(
            title="Isolated Host Investigation",
            summary="Summary",
            description="Description",
            category=InvestigationCategory.API,
            related_graph_nodes=["live_host:iso.com"],
            related_endpoints=["http://iso.com/api"],
            confidence=0.8
        )

        score_dense, exp_dense = calc.calculate(inv_dense, graph=kg_dense)
        score_iso, exp_iso = calc.calculate(inv_iso, graph=kg_iso)

        assert score_dense > score_iso
        assert any("connectivity bonus" in e.lower() for e in exp_dense)
        assert not any("connectivity bonus" in e.lower() for e in exp_iso)

    def test_hypothesis_confidence_dense_vs_isolated_host(self):
        """Hypothesis on dense host has strictly higher confidence multiplier than isolated host."""
        kg_dense = create_dense_host_graph(host_id="dense.com", endpoint_count=5)
        kg_iso = create_isolated_host_graph(host_id="iso.com")

        scorer = HypothesisConfidenceScorer()

        ev1_id = uuid.uuid4()
        ev2_id = uuid.uuid4()

        hyp_dense = Hypothesis(
            title="Dense Host Hypothesis",
            summary="Summary",
            description="Description",
            category=HypothesisCategory.API,
            supporting_graph_nodes=["live_host:dense.com"],
            related_evidence=[ev1_id, ev2_id],
            metadata={"max_investigation_confidence": 0.6}
        )
        hyp_iso = Hypothesis(
            title="Isolated Host Hypothesis",
            summary="Summary",
            description="Description",
            category=HypothesisCategory.API,
            supporting_graph_nodes=["live_host:iso.com"],
            related_evidence=[ev1_id, ev2_id],
            metadata={"max_investigation_confidence": 0.6}
        )

        conf_dense = scorer.calculate_confidence(hyp_dense, graph=kg_dense)
        conf_iso = scorer.calculate_confidence(hyp_iso, graph=kg_iso)

        # Dense host has degree >= 5 -> multiplier = 1.20; isolated host degree 0 -> multiplier = 0.85
        assert conf_dense > conf_iso
        assert conf_dense == pytest.approx(0.6 * 1.20, abs=1e-3)
        assert conf_iso == pytest.approx(0.6 * 0.85, abs=1e-3)


# ==============================================================================
# SECTION 2: Nodes With vs Without HAS_VULNERABILITY Edges
# ==============================================================================

class TestVulnerabilityPrioritization:

    def test_strictly_higher_priority_for_vulnerable_hosts(self):
        """Investigation on host with HAS_VULNERABILITY edge strictly outscores host without vulnerability."""
        kg_vuln = create_dense_host_graph(host_id="target.com", endpoint_count=3, with_vuln=True)
        kg_clean = create_dense_host_graph(host_id="target.com", endpoint_count=3, with_vuln=False)

        calc = ScoreCalculator()

        inv = Investigation(
            title="Vulnerability Comparison Investigation",
            summary="Summary",
            description="Description",
            category=InvestigationCategory.TECHNOLOGY,
            related_graph_nodes=["live_host:target.com"],
            confidence=0.75
        )

        score_vuln, exp_vuln = calc.calculate(inv, graph=kg_vuln)
        score_clean, exp_clean = calc.calculate(inv, graph=kg_clean)

        # Vulnerable host gets 1.30x multiplier
        assert score_vuln > score_clean
        assert score_vuln == pytest.approx(min(100.0, score_clean * 1.30), abs=1e-2)
        assert any("vulnerability" in e.lower() for e in exp_vuln)
        assert not any("vulnerability" in e.lower() for e in exp_clean)

    @pytest.mark.parametrize("category", [
        InvestigationCategory.AUTHENTICATION,
        InvestigationCategory.AUTHORIZATION,
        InvestigationCategory.API,
        InvestigationCategory.BUSINESS_LOGIC,
        InvestigationCategory.TECHNOLOGY,
        InvestigationCategory.GRAPHQL,
    ])
    def test_vulnerability_boost_across_all_investigation_categories(self, category):
        """Across all investigation categories, vulnerable host priority is strictly higher."""
        kg_vuln = create_dense_host_graph(host_id="target.com", endpoint_count=3, with_vuln=True)
        kg_clean = create_dense_host_graph(host_id="target.com", endpoint_count=3, with_vuln=False)

        calc = ScoreCalculator()
        inv = Investigation(
            title=f"Category {category.value} Investigation",
            summary="Summary",
            description="Description",
            category=category,
            related_graph_nodes=["live_host:target.com"],
            confidence=0.7
        )

        score_vuln, _ = calc.calculate(inv, graph=kg_vuln)
        score_clean, _ = calc.calculate(inv, graph=kg_clean)

        assert score_vuln > score_clean

    def test_hypothesis_confidence_vulnerability_bonus(self):
        """Hypothesis for a host with HAS_VULNERABILITY receives a 1.10x confidence bonus."""
        # Using endpoint_count=5 so degree multiplier is capped at 1.20 for both, isolating the 1.10x vulnerability bonus
        kg_vuln = create_dense_host_graph(host_id="target.com", endpoint_count=5, with_vuln=True)
        kg_clean = create_dense_host_graph(host_id="target.com", endpoint_count=5, with_vuln=False)

        scorer = HypothesisConfidenceScorer()
        ev1 = uuid.uuid4()
        ev2 = uuid.uuid4()

        hyp = Hypothesis(
            title="Hypothesis Test",
            summary="Summary",
            description="Description",
            category=HypothesisCategory.TECHNOLOGY,
            supporting_graph_nodes=["live_host:target.com"],
            related_evidence=[ev1, ev2],
            metadata={"max_investigation_confidence": 0.5}
        )

        conf_vuln = scorer.calculate_confidence(hyp, graph=kg_vuln)
        conf_clean = scorer.calculate_confidence(hyp, graph=kg_clean)

        assert conf_vuln > conf_clean
        assert conf_vuln == pytest.approx(conf_clean * 1.10, abs=1e-3)


# ==============================================================================
# SECTION 3: Disconnected Graphs, Cyclic Graphs, Missing Metadata
# ==============================================================================

class TestEdgeConditionsAndGraphRobustness:

    def test_disconnected_components_traversal_safety(self):
        """BFS traversal and host subgraph resolution across disconnected components is safe and fast."""
        kg = create_disconnected_graph(num_components=10)

        # Nodes in same component are connected
        assert kg.are_connected("live_host:comp_0.com", "endpoint:comp_0.com/api") is True
        assert kg.in_same_host_subgraph("live_host:comp_0.com", "endpoint:comp_0.com/api") is True

        # Nodes in different components are NOT connected
        assert kg.are_connected("live_host:comp_0.com", "live_host:comp_9.com") is False
        assert kg.in_same_host_subgraph("live_host:comp_0.com", "endpoint:comp_9.com/api") is False

        # Non-existent nodes
        assert kg.are_connected("non_existent_1", "non_existent_2") is False
        assert kg.get_host_for_node("non_existent_node") is None
        assert kg.get_node_degree("non_existent_node") == 0

    def test_cyclic_graph_termination_and_safety(self):
        """Cyclic graphs (3-cycle, self-loop, bidirectional edges) do not cause infinite recursion."""
        kg = create_cyclic_graph()

        # Check connectivity across cycles
        assert kg.are_connected("live_host:cycle_a", "technology:cycle_d", max_depth=3) is True
        assert kg.are_connected("live_host:cycle_a", "endpoint:cycle_c", max_depth=2) is True
        assert kg.in_same_host_subgraph("live_host:cycle_a", "technology:cycle_d") is True

        # Resolution of host for nodes in a cycle
        host_b = kg.get_host_for_node("endpoint:cycle_b")
        assert host_b is not None
        assert host_b.id == "live_host:cycle_a"

        # Correlation matching on cyclic graph
        obs1 = make_obs("Obs Cycle 1", graph_nodes=["endpoint:cycle_b"])
        obs2 = make_obs("Obs Cycle 2", graph_nodes=["technology:cycle_d"])
        assert match_graph_neighborhood(obs1, obs2, graph=kg, max_hops=2) is True

    def test_empty_and_none_graph_handling(self):
        """Empty graph or None graph is handled gracefully by all reasoning components."""
        empty_kg = KnowledgeGraph()
        matcher = CorrelationMatcher(graph=empty_kg)
        obs1 = make_obs("Obs1", graph_nodes=["n1"])
        obs2 = make_obs("Obs2", graph_nodes=["n2"])
        assert matcher.find_matches(obs1, obs2) == []

        # Investigation scoring with None/empty graph
        calc = ScoreCalculator()
        inv = Investigation(
            title="Inv",
            summary="Summary",
            description="Description",
            category=InvestigationCategory.API,
            related_graph_nodes=["n1"]
        )
        score_none, _ = calc.calculate(inv, graph=None)
        score_empty, _ = calc.calculate(inv, graph=empty_kg)
        assert score_none == score_empty
        assert 0.0 <= score_none <= 100.0

        # Hypothesis scoring with None/empty graph
        scorer = HypothesisConfidenceScorer()
        ev1 = uuid.uuid4()
        ev2 = uuid.uuid4()
        hyp = Hypothesis(
            title="Hyp",
            summary="Summary",
            description="Description",
            category=HypothesisCategory.API,
            supporting_graph_nodes=["n1"],
            related_evidence=[ev1, ev2]
        )
        conf_none = scorer.calculate_confidence(hyp, graph=None)
        conf_empty = scorer.calculate_confidence(hyp, graph=empty_kg)
        assert conf_none == conf_empty
        assert 0.0 <= conf_none <= 1.0

    def test_missing_and_malformed_metadata_robustness(self):
        """Adversarial observations with malformed/missing fields do not raise errors."""
        kg = KnowledgeGraph()
        # Add a node with None metadata
        n_none_meta = Node(id="live_host:none_meta.com", type="live_host", value="none_meta.com", metadata=None)
        kg.add(n_none_meta)

        # Observation with None and corrupt elements in lists
        obs_corrupt = Observation(
            source="tester",
            category=ObservationCategory.TECHNOLOGY,
            priority=ObservationPriority.LOW,
            confidence=0.5,
            title="Corrupt Obs",
            description="Description",
            graph_nodes=["live_host:none_meta.com"],
            endpoints=["http://none_meta.com"],
            technology=["nginx"],
            evidence=[]
        )

        extracted = _extract_graph_nodes(obs_corrupt, kg)
        assert "live_host:none_meta.com" in extracted

        # Match against clean observation
        obs_clean = make_obs("Clean Obs", graph_nodes=["live_host:none_meta.com"])
        assert match_shared_graph_nodes(obs_corrupt, obs_clean, graph=kg) is True


# ==============================================================================
# SECTION 4: Monotonic Confidence Scoring in HypothesisConfidenceScorer
# ==============================================================================

class TestMonotonicHypothesisScoring:

    def test_monotonic_confidence_with_increasing_node_degree(self):
        """Confidence score monotonically non-decreases as host degree increases."""
        scorer = HypothesisConfidenceScorer()
        degrees = [0, 1, 2, 3, 4, 5, 6, 10, 20]
        confidences = []
        ev1 = uuid.uuid4()
        ev2 = uuid.uuid4()

        for deg in degrees:
            kg = KnowledgeGraph()
            h = Node(id="live_host:test.com", type="live_host", value="test.com")
            kg.add(h)
            for d in range(deg):
                ep = Node(id=f"endpoint:test.com/{d}", type="endpoint", value=f"http://test.com/{d}")
                kg.add(ep)
                kg.connect(h.id, ep.id, "HAS_ENDPOINT")

            hyp = Hypothesis(
                title=f"Hypothesis deg {deg}",
                summary="Summary",
                description="Description",
                category=HypothesisCategory.API,
                supporting_graph_nodes=["live_host:test.com"],
                related_evidence=[ev1, ev2],
                metadata={"max_investigation_confidence": 0.5}
            )
            conf = scorer.calculate_confidence(hyp, graph=kg)
            confidences.append((deg, conf))

        # Check monotonic non-decreasing
        for i in range(len(confidences) - 1):
            deg_curr, conf_curr = confidences[i]
            deg_next, conf_next = confidences[i + 1]
            assert conf_next >= conf_curr, f"Monotonicity violated: deg {deg_curr}->{conf_curr} vs deg {deg_next}->{conf_next}"

        # Strictly increasing up to degree 5 (where multiplier formula caps at 1.20)
        for i in range(5):
            assert confidences[i + 1][1] > confidences[i][1]

    def test_monotonic_confidence_with_increasing_evidence_volume(self):
        """Confidence strictly increases or stays equal with increasing pieces of corroborating evidence."""
        scorer = HypothesisConfidenceScorer()
        kg = create_dense_host_graph(host_id="evidence_test.com", endpoint_count=3)

        ev1 = uuid.uuid4()
        ev2 = uuid.uuid4()

        # Test fallback / evidence penalty
        hyp_0_ev = Hypothesis(
            title="0 Evidence",
            summary="Summary",
            description="Description",
            category=HypothesisCategory.API,
            supporting_graph_nodes=["live_host:evidence_test.com"],
            related_evidence=[],
            related_observations=[],
            metadata={"max_investigation_confidence": 0.5}
        )
        hyp_1_ev = Hypothesis(
            title="1 Evidence",
            summary="Summary",
            description="Description",
            category=HypothesisCategory.API,
            supporting_graph_nodes=["live_host:evidence_test.com"],
            related_evidence=[ev1],
            metadata={"max_investigation_confidence": 0.5}
        )
        hyp_2_ev = Hypothesis(
            title="2 Evidence",
            summary="Summary",
            description="Description",
            category=HypothesisCategory.API,
            supporting_graph_nodes=["live_host:evidence_test.com"],
            related_evidence=[ev1, ev2],
            metadata={"max_investigation_confidence": 0.5}
        )

        conf_0 = scorer.calculate_confidence(hyp_0_ev, graph=kg)
        conf_1 = scorer.calculate_confidence(hyp_1_ev, graph=kg)
        conf_2 = scorer.calculate_confidence(hyp_2_ev, graph=kg)

        assert conf_0 == 0.0
        assert conf_1 > conf_0
        assert conf_2 > conf_1

    def test_confidence_bounded_in_unit_interval(self):
        """Under extreme adversarial degrees and bonuses, confidence remains strictly bounded in [0.0, 1.0]."""
        scorer = HypothesisConfidenceScorer()

        # Extreme high degree and maximum bonuses
        kg_extreme = KnowledgeGraph()
        h = Node(id="live_host:extreme.com", type="live_host", value="extreme.com")
        kg_extreme.add(h)
        for i in range(100):
            ep = Node(id=f"endpoint:extreme.com/{i}", type="endpoint", value=f"http://extreme.com/{i}")
            kg_extreme.add(ep)
            kg_extreme.connect(h.id, ep.id, "HAS_ENDPOINT")
        v = Node(id="vulnerability:cve", type="vulnerability", value="CVE-HIGH")
        kg_extreme.add(v)
        kg_extreme.connect(h.id, v.id, "HAS_VULNERABILITY")

        hyp_max = Hypothesis(
            title="Max Hypothesis",
            summary="Summary",
            description="Description",
            category=HypothesisCategory.API,
            supporting_graph_nodes=["live_host:extreme.com"],
            related_evidence=[uuid.uuid4() for _ in range(50)],
            metadata={"max_investigation_confidence": 1.0}
        )

        conf_max = scorer.calculate_confidence(hyp_max, graph=kg_extreme)
        assert 0.0 <= conf_max <= 1.0
        assert conf_max == 1.0  # Capped at 1.0


# ==============================================================================
# SECTION 5: End-to-End Dynamic Graph Correlation & Multi-Host Clustering Stress
# ==============================================================================

class TestDynamicGraphCorrelationAndMultiHostClustering:

    def test_correlation_engine_bridges_previously_disconnected_clusters(self):
        """When an observation bridging two graph subgraphs is processed, correlation engine links or merges them."""
        kg = KnowledgeGraph()
        # Cluster 1: Host 1 & Endpoint 1
        h1 = Node(id="live_host:cluster1.com", type="live_host", value="cluster1.com")
        ep1 = Node(id="endpoint:cluster1.com/login", type="endpoint", value="http://cluster1.com/login")
        kg.add(h1)
        kg.add(ep1)
        kg.connect(h1.id, ep1.id, "HAS_ENDPOINT")

        # Cluster 2: Host 2 & Endpoint 2
        h2 = Node(id="live_host:cluster2.com", type="live_host", value="cluster2.com")
        ep2 = Node(id="endpoint:cluster2.com/api", type="endpoint", value="http://cluster2.com/api")
        kg.add(h2)
        kg.add(ep2)
        kg.connect(h2.id, ep2.id, "HAS_ENDPOINT")

        obs_reg = ObservationRegistry()
        corr_reg = CorrelationRegistry()
        corr_graph = CorrelationGraph()
        engine = CorrelationEngine(obs_reg, corr_reg, corr_graph, knowledge_graph=kg)

        obs1 = make_obs("Cluster 1 Obs", graph_nodes=[ep1.id], endpoints=["http://cluster1.com/login"])
        obs2 = make_obs("Cluster 2 Obs", graph_nodes=[ep2.id], endpoints=["http://cluster2.com/api"])

        engine.process_observation(obs1)
        engine.process_observation(obs2)

        # Before bridging, they should not be correlated
        assert len(corr_reg.get_all()) == 0

        # Now introduce a bridge edge in KnowledgeGraph connecting ep1 and ep2
        kg.connect(ep1.id, ep2.id, "REDIRECTS_TO")

        # Process a new observation referencing both or one that traverses the bridge
        obs3 = make_obs("Bridge Obs", graph_nodes=[ep1.id])
        engine.process_observation(obs3)

        # Now obs3 matches obs1 via ep1 and obs2 via ep1->ep2 bridge within 2 hops
        correlations = corr_reg.get_all()
        assert len(correlations) >= 1
        matched_obs_ids = set()
        for c in correlations:
            matched_obs_ids.update(c.observations)

        assert obs1.id in matched_obs_ids
        assert obs3.id in matched_obs_ids

    def test_multi_host_investigation_scoring(self):
        """An investigation touching multiple hosts gets vulnerability bonus if ANY referenced host is vulnerable."""
        kg = KnowledgeGraph()
        h_clean = Node(id="live_host:clean.com", type="live_host", value="clean.com")
        h_vuln = Node(id="live_host:vuln.com", type="live_host", value="vuln.com")
        v_node = Node(id="vulnerability:CVE-MULTI", type="vulnerability", value="CVE-2023-MULTI")

        kg.add(h_clean)
        kg.add(h_vuln)
        kg.add(v_node)
        kg.connect(h_vuln.id, v_node.id, "HAS_VULNERABILITY")

        calc = ScoreCalculator()

        # Multi-host investigation touching both clean and vuln
        inv_multi = Investigation(
            title="Multi-Host Investigation",
            summary="Summary",
            description="Description",
            category=InvestigationCategory.TECHNOLOGY,
            related_graph_nodes=["live_host:clean.com", "live_host:vuln.com"],
            confidence=0.8
        )
        # Single clean host investigation
        inv_single_clean = Investigation(
            title="Single Clean Host Investigation",
            summary="Summary",
            description="Description",
            category=InvestigationCategory.TECHNOLOGY,
            related_graph_nodes=["live_host:clean.com"],
            confidence=0.8
        )

        score_multi, exp_multi = calc.calculate(inv_multi, graph=kg)
        score_clean, exp_clean = calc.calculate(inv_single_clean, graph=kg)

        assert score_multi > score_clean
        assert any("vulnerability" in e.lower() for e in exp_multi)
        assert not any("vulnerability" in e.lower() for e in exp_clean)

    def test_grid_confidence_monotonicity(self):
        """Comprehensive grid stress test: confidence is monotonic across degrees, evidence counts, and confidences."""
        scorer = HypothesisConfidenceScorer()

        for base_conf in [0.1, 0.3, 0.5, 0.7, 0.9]:
            for num_ev in [1, 2, 3, 4]:
                conf_prev = -1.0
                for deg in range(8):
                    kg = KnowledgeGraph()
                    h = Node(id="live_host:grid.com", type="live_host", value="grid.com")
                    kg.add(h)
                    for d in range(deg):
                        ep = Node(id=f"endpoint:grid.com/{d}", type="endpoint", value=f"http://grid.com/{d}")
                        kg.add(ep)
                        kg.connect(h.id, ep.id, "HAS_ENDPOINT")

                    hyp = Hypothesis(
                        title="Grid Hyp",
                        summary="Summary",
                        description="Description",
                        category=HypothesisCategory.API,
                        supporting_graph_nodes=["live_host:grid.com"],
                        related_evidence=[uuid.uuid4() for _ in range(num_ev)],
                        metadata={"max_investigation_confidence": base_conf}
                    )

                    conf = scorer.calculate_confidence(hyp, graph=kg)
                    assert 0.0 <= conf <= 1.0
                    if conf_prev >= 0.0:
                        assert conf >= conf_prev, f"Grid monotonicity failure: base={base_conf}, num_ev={num_ev}, deg={deg}"
                    conf_prev = conf
