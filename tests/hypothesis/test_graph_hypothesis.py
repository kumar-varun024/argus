import uuid
import pytest
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.hypothesis.models import Hypothesis, HypothesisCategory, HypothesisStatus
from argus.hypothesis.confidence import HypothesisConfidenceScorer
from argus.hypothesis.ranking import HypothesisRanker
from argus.hypothesis.engine import HypothesisEngine
from argus.hypothesis.registry import HypothesisRegistry
from argus.runtime.mission import Mission


def build_hypothesis_graph():
    kg = KnowledgeGraph()
    # Connected host: degree = 4, has vulnerability edge
    kg.add(Node(id="live_host:http://connected.example.com", type="live_host", value="http://connected.example.com", metadata={"url": "http://connected.example.com"}))
    kg.add(Node(id="endpoint:http://connected.example.com/api", type="endpoint", value="http://connected.example.com/api"))
    kg.add(Node(id="endpoint:http://connected.example.com/login", type="endpoint", value="http://connected.example.com/login"))
    kg.add(Node(id="technology:Flask", type="technology", value="Flask"))
    kg.add(Node(id="vulnerability:CVE-2023-1111", type="vulnerability", value="CVE-2023-1111"))
    kg.connect("live_host:http://connected.example.com", "endpoint:http://connected.example.com/api", "HAS_ENDPOINT")
    kg.connect("live_host:http://connected.example.com", "endpoint:http://connected.example.com/login", "HAS_ENDPOINT")
    kg.connect("live_host:http://connected.example.com", "technology:Flask", "RUNS_TECHNOLOGY")
    kg.connect("live_host:http://connected.example.com", "vulnerability:CVE-2023-1111", "HAS_VULNERABILITY")

    # Isolated host: degree = 0
    kg.add(Node(id="live_host:http://isolated.example.com", type="live_host", value="http://isolated.example.com", metadata={"url": "http://isolated.example.com"}))
    return kg


def test_hypothesis_confidence_well_connected_vs_isolated():
    kg = build_hypothesis_graph()
    scorer = HypothesisConfidenceScorer()

    hyp_connected = Hypothesis(
        title="Connected Host Hypothesis",
        summary="Test",
        description="Detailed description for connected host hypothesis",
        category=HypothesisCategory.TECHNOLOGY,
        supporting_graph_nodes=["live_host:http://connected.example.com"],
        related_evidence=[uuid.uuid4(), uuid.uuid4()],
        metadata={"max_investigation_confidence": 0.6}
    )
    hyp_isolated = Hypothesis(
        title="Isolated Host Hypothesis",
        summary="Test",
        description="Detailed description for isolated host hypothesis",
        category=HypothesisCategory.TECHNOLOGY,
        supporting_graph_nodes=["live_host:http://isolated.example.com"],
        related_evidence=[uuid.uuid4(), uuid.uuid4()],
        metadata={"max_investigation_confidence": 0.6}
    )

    conf_conn = scorer.calculate_confidence(hyp_connected, graph=kg)
    conf_iso = scorer.calculate_confidence(hyp_isolated, graph=kg)

    # Well-connected host confidence must be strictly higher than isolated node
    assert conf_conn > conf_iso


def test_hypothesis_confidence_vulnerability_bonus():
    kg = KnowledgeGraph()
    # Host A: has vuln
    kg.add(Node(id="live_host:http://a.com", type="live_host", value="http://a.com", metadata={"url": "http://a.com"}))
    kg.add(Node(id="vulnerability:VULN-1", type="vulnerability", value="VULN-1"))
    kg.connect("live_host:http://a.com", "vulnerability:VULN-1", "HAS_VULNERABILITY")

    # Host B: no vuln (same degree 1)
    kg.add(Node(id="live_host:http://b.com", type="live_host", value="http://b.com", metadata={"url": "http://b.com"}))
    kg.add(Node(id="endpoint:http://b.com/x", type="endpoint", value="http://b.com/x"))
    kg.connect("live_host:http://b.com", "endpoint:http://b.com/x", "HAS_ENDPOINT")

    scorer = HypothesisConfidenceScorer()
    hyp_a = Hypothesis(
        title="Host A",
        summary="Test",
        description="Detailed description for host a",
        category=HypothesisCategory.TECHNOLOGY,
        supporting_graph_nodes=["live_host:http://a.com"],
        related_evidence=[uuid.uuid4(), uuid.uuid4()],
        metadata={"max_investigation_confidence": 0.6}
    )
    hyp_b = Hypothesis(
        title="Host B",
        summary="Test",
        description="Detailed description for host b",
        category=HypothesisCategory.TECHNOLOGY,
        supporting_graph_nodes=["live_host:http://b.com"],
        related_evidence=[uuid.uuid4(), uuid.uuid4()],
        metadata={"max_investigation_confidence": 0.6}
    )

    conf_a = scorer.calculate_confidence(hyp_a, graph=kg)
    conf_b = scorer.calculate_confidence(hyp_b, graph=kg)

    assert conf_a > conf_b


def test_hypothesis_ranker_topology_points():
    kg = build_hypothesis_graph()
    ranker = HypothesisRanker()

    hyp_with_topology = Hypothesis(
        title="Topology Hypothesis",
        summary="Test",
        description="Detailed description for topology hypothesis",
        category=HypothesisCategory.TECHNOLOGY,
        confidence=0.5,
        supporting_graph_nodes=["live_host:http://connected.example.com", "endpoint:http://connected.example.com/api"],
        supporting_graph_edges=["HAS_ENDPOINT"]
    )
    hyp_no_topology = Hypothesis(
        title="No Topology Hypothesis",
        summary="Test",
        description="Detailed description for no topology hypothesis",
        category=HypothesisCategory.TECHNOLOGY,
        confidence=0.5,
        supporting_graph_nodes=[],
        supporting_graph_edges=[]
    )

    score_topo = ranker.evaluate_priority(hyp_with_topology, graph=kg)
    score_notopo = ranker.evaluate_priority(hyp_no_topology, graph=kg)

    assert score_topo > score_notopo


def test_hypothesis_engine_evaluate_all_with_mission():
    kg = build_hypothesis_graph()
    mission = Mission(target="example.com")
    mission.attack_surface_graph = kg

    registry = HypothesisRegistry()
    engine = HypothesisEngine(registry)

    hyp = Hypothesis(
        title="Engine Hypothesis",
        summary="Test",
        description="Detailed description for engine hypothesis",
        category=HypothesisCategory.TECHNOLOGY,
        supporting_graph_nodes=["live_host:http://connected.example.com"],
        related_evidence=[uuid.uuid4(), uuid.uuid4()],
        metadata={"max_investigation_confidence": 0.6}
    )
    registry.add(hyp)

    engine.evaluate_all(mission)
    assert hyp.confidence > 0.0
    assert hyp.priority_score > 0.0
