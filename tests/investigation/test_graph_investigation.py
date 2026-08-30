import uuid
import pytest
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.correlation.evidence import EvidenceBundle
from argus.investigation.models import Investigation, InvestigationCategory, InvestigationPriority
from argus.investigation.weights import WeightConfig
from argus.investigation.scoring import ScoreCalculator
from argus.investigation.generator import InvestigationGenerator
from argus.investigation.registry import InvestigationRegistry
from argus.investigation.confidence import InvestigationConfidenceScorer
from argus.investigation.priority_engine import PriorityEngine
from argus.investigation.manual_validation import ManualValidationGenerator
from argus.investigation.explanation import ReasoningTreeBuilder
from argus.correlation.registry import EvidenceBundleRegistry, CorrelationRegistry, ObservationRegistry
from argus.investigation.builder import InvestigationBuilder
from argus.runtime.mission import Mission


def build_test_graph():
    kg = KnowledgeGraph()
    # Host 1: Well-connected and vulnerable (degree 4, has vuln)
    kg.add(Node(id="live_host:http://vuln.example.com", type="live_host", value="http://vuln.example.com", metadata={"url": "http://vuln.example.com"}))
    kg.add(Node(id="endpoint:http://vuln.example.com/api", type="endpoint", value="http://vuln.example.com/api"))
    kg.add(Node(id="technology:Django", type="technology", value="Django"))
    kg.add(Node(id="vulnerability:CVE-2023-9999", type="vulnerability", value="CVE-2023-9999"))
    kg.connect("live_host:http://vuln.example.com", "endpoint:http://vuln.example.com/api", "HAS_ENDPOINT")
    kg.connect("live_host:http://vuln.example.com", "technology:Django", "RUNS_TECHNOLOGY")
    kg.connect("live_host:http://vuln.example.com", "vulnerability:CVE-2023-9999", "HAS_VULNERABILITY")

    # Host 2: Isolated (degree 1, no vuln)
    kg.add(Node(id="live_host:http://clean.example.com", type="live_host", value="http://clean.example.com", metadata={"url": "http://clean.example.com"}))
    kg.add(Node(id="technology:Static", type="technology", value="Static"))
    kg.connect("live_host:http://clean.example.com", "technology:Static", "RUNS_TECHNOLOGY")
    return kg


def test_investigation_vulnerability_bonus():
    kg = build_test_graph()
    calc = ScoreCalculator(WeightConfig())
    
    inv_vuln = Investigation(
        title="Vuln Host Investigation",
        summary="Test",
        description="Detailed description for vuln host investigation",
        category=InvestigationCategory.TECHNOLOGY,
        related_graph_nodes=["live_host:http://vuln.example.com"]
    )
    inv_clean = Investigation(
        title="Clean Host Investigation",
        summary="Test",
        description="Detailed description for clean host investigation",
        category=InvestigationCategory.TECHNOLOGY,
        related_graph_nodes=["live_host:http://clean.example.com"]
    )

    score_vuln, exp_vuln = calc.calculate(inv_vuln, graph=kg)
    score_clean, exp_clean = calc.calculate(inv_clean, graph=kg)

    assert score_vuln > score_clean
    assert any("vulnerability associations" in e for e in exp_vuln)
    assert not any("vulnerability associations" in e for e in exp_clean)


def test_investigation_connectivity_bonus():
    kg = build_test_graph()
    calc = ScoreCalculator(WeightConfig())
    
    inv_connected = Investigation(
        title="Connected Host",
        summary="Test",
        description="Detailed description for connected host",
        category=InvestigationCategory.TECHNOLOGY,
        related_graph_nodes=["live_host:http://vuln.example.com"]
    )
    inv_isolated = Investigation(
        title="Isolated Host",
        summary="Test",
        description="Detailed description for isolated host",
        category=InvestigationCategory.TECHNOLOGY,
        related_graph_nodes=["live_host:http://clean.example.com"]
    )

    score_conn, exp_conn = calc.calculate(inv_connected, graph=kg)
    score_iso, exp_iso = calc.calculate(inv_isolated, graph=kg)

    assert any("connectivity bonus" in e for e in exp_conn)
    assert not any("connectivity bonus" in e for e in exp_iso)


def test_investigation_generator_host_subgraph_clustering():
    kg = build_test_graph()
    inv_reg = InvestigationRegistry()
    bundle_reg = EvidenceBundleRegistry()
    conf_scorer = InvestigationConfidenceScorer(bundle_reg)
    prio_engine = PriorityEngine(bundle_reg)
    val_gen = ManualValidationGenerator()
    corr_reg = CorrelationRegistry()
    obs_reg = ObservationRegistry()
    reasoning_builder = ReasoningTreeBuilder(bundle_reg, corr_reg, obs_reg)

    generator = InvestigationGenerator(inv_reg, conf_scorer, prio_engine, val_gen, reasoning_builder)

    b1 = EvidenceBundle(
        title="Bundle 1",
        description="Endpoint on vuln host",
        strength=80.0,
        confidence=0.8,
        graph_nodes=["endpoint:http://vuln.example.com/api"]
    )
    b2 = EvidenceBundle(
        title="Bundle 2",
        description="Tech on vuln host",
        strength=80.0,
        confidence=0.8,
        graph_nodes=["technology:Django"]
    )

    inv1 = generator.process_bundle(b1, graph=kg)
    inv2 = generator.process_bundle(b2, graph=kg)

    # Both bundles should merge into the same investigation because they are in the same host subgraph
    assert inv1 is not None
    assert inv2 is not None
    assert inv1.id == inv2.id
    assert len(inv_reg.get_all()) == 1


def test_investigation_builder_prioritize_with_mission_graph():
    kg = build_test_graph()
    mission = Mission(target="example.com")
    mission.attack_surface_graph = kg

    inv_reg = InvestigationRegistry()
    bundle_reg = EvidenceBundleRegistry()
    corr_reg = CorrelationRegistry()
    obs_reg = ObservationRegistry()

    builder = InvestigationBuilder(inv_reg, bundle_reg, corr_reg, obs_reg)
    
    inv = Investigation(
        title="Test Investigation",
        summary="Test",
        description="Detailed description for test investigation",
        category=InvestigationCategory.TECHNOLOGY,
        related_graph_nodes=["live_host:http://vuln.example.com"]
    )
    inv_reg.add(inv)

    ranked = builder.prioritize_all(mission)
    assert len(ranked) == 1
    assert ranked[0].priority_score > 0
    assert any("vulnerability" in e.lower() for e in ranked[0].priority_explanation)
