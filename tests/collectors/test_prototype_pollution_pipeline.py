"""
Pipeline Connectivity and Integration Tests for Prototype Pollution Module:
Covers ToolRegistry registration & aliases, PluginExecutorAdapter fallback instantiation,
ScanEngine collector mapping, TaskGenerator DAG recon templates & gap resolution,
AttackSurfaceGraphBuilder Section 29 graph construction, and CVSS CWE/scoring calibration.
"""
from __future__ import annotations

import types
import urllib.parse
from typing import Any, Dict, List, Optional
import pytest

from argus.collectors.prototype_pollution import (
    PrototypePollutionCollector,
    PrototypePollutionVulnerabilityType,
    PrototypePollutionSeverity,
    PrototypePollutionProbe,
    PrototypePollutionProbeResponse,
)
from argus.evidence.model import Evidence, ProvenanceData
from argus.evidence.store import EvidenceStore
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.planning.task_generator import (
    TaskGenerator,
    _RECON_TEMPLATES,
    TaskCategory,
    CoverageGap,
    ResearchTask,
)
from argus.runtime.mission import Mission
from argus.reporting.cvss import CVSSCalculator, ReportSeverity
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry, ToolRegistry
from argus.scanning.engine import ScanEngine


# =============================================================================
# Pipeline Tests: Tool Registry & Aliases (R5)
# =============================================================================

def test_tool_registry_registration():
    tool = registry.get("prototype_pollution")
    assert tool is not None
    assert tool.id == "prototype_pollution"
    assert tool.priority == 95
    assert tool.capability == "prototype_pollution_detector"
    assert "endpoints" in tool.required_inputs
    assert "vulnerabilities" in tool.produced_outputs
    assert "prototype_pollution_detector" in tool.capabilities
    assert "dom_clobbering_detector" in tool.capabilities
    assert "open_redirect_detector" in tool.capabilities
    assert "clickjacking_detector" in tool.capabilities


def test_tool_registry_aliases_resolution():
    aliases = [
        "prototype_pollution",
        "prototype_pollution_collector",
        "prototype_pollution_detector",
        "prototype_pollution_specialist",
        "proto_pollution",
        "server_side_prototype_pollution",
        "client_side_prototype_pollution",
        "client_side_attacks",
        "client_side_collector",
        "client_side_detector",
        "client_side_attack_collector",
        "dom_clobbering",
        "dom_clobbering_detector",
        "dom_clobbering_collector",
        "html_clobbering",
        "open_redirect",
        "open_redirect_collector",
        "open_redirect_detector",
        "open_redirect_chain",
        "clickjacking_detector",
        "ui_redressing",
        "gadget_analyzer",
    ]
    for alias in aliases:
        t = registry.get(alias)
        assert t is not None, f"Alias '{alias}' failed to resolve in ToolRegistry"
        assert t.id == "prototype_pollution"


# =============================================================================
# Pipeline Tests: PluginExecutorAdapter & ScanEngine (R5)
# =============================================================================

def test_plugin_executor_adapter_instantiation():
    adapter = PluginExecutorAdapter()
    for pid in [
        "prototype_pollution",
        "proto_pollution",
        "client_side_attacks",
        "dom_clobbering",
        "html_clobbering",
        "open_redirect",
        "clickjacking",
        "ui_redressing",
    ]:
        collector = adapter._instantiate_specialist_fallback(pid)
        assert collector is not None, f"Failed instantiating fallback for {pid}"
        assert isinstance(collector, PrototypePollutionCollector)


def test_scan_engine_collector_resolution():
    engine = ScanEngine()
    task = types.SimpleNamespace(tool_id="prototype_pollution", key="prototype_pollution")
    collector = engine.resolve_collector(task)
    assert collector is not None
    assert isinstance(collector, PrototypePollutionCollector)

    # Resolve via alias
    task_alias = types.SimpleNamespace(tool_id="dom_clobbering", key="dom_clobbering")
    collector_alias = engine.resolve_collector(task_alias)
    assert collector_alias is not None
    assert isinstance(collector_alias, PrototypePollutionCollector)


# =============================================================================
# Pipeline Tests: TaskGenerator DAG & Gap Resolution (R5)
# =============================================================================

def test_task_generator_dag_recon_template_definition():
    template = _RECON_TEMPLATES.get("prototype_pollution")
    assert template is not None
    assert template["dependencies"] == ["Discover API Endpoints"]
    assert template["required_inputs"] == ["endpoints"]
    assert template["metadata"]["tool_id"] == "prototype_pollution"
    assert template["category"] == TaskCategory.EVIDENCE_CORRELATION


def test_task_generator_gap_resolution_exact_areas():
    generator = TaskGenerator(mission=Mission(target="http://example.com"))
    gap_areas = [
        "prototype pollution",
        "prototype_pollution",
        "proto pollution",
        "client-side prototype pollution",
        "server-side prototype pollution",
        "dom clobbering",
        "html clobbering",
        "open redirect",
        "open redirect chain",
        "client-side attacks",
        "gadget chain",
        "prototype pollution gadgets",
    ]
    for area in gap_areas:
        gap = CoverageGap(
            id=f"gap_{area}",
            category=TaskCategory.EVIDENCE_CORRELATION,
            area=area,
            description=f"Coverage gap for {area}",
            severity=0.8,
        )
        template = generator._resolve_template_for_gap(gap)
        assert template["metadata"]["tool_id"] == "prototype_pollution", f"Area '{area}' did not resolve to prototype_pollution template"


def test_task_generator_gap_resolution_category_fallbacks():
    generator = TaskGenerator(mission=Mission(target="http://example.com"))
    fallbacks = [
        "Identified potential prototype pollution vulnerabilities in json parser",
        "Unvalidated redirect chain observed on login redirection",
        "DOM clobbering vulnerability shadowing window variables",
        "Missing frame busting defenses on sensitive account settings",
    ]
    for desc in fallbacks:
        gap = CoverageGap(
            id="gap_desc",
            category=TaskCategory.EVIDENCE_CORRELATION,
            area="general_audit",
            description=desc,
            severity=0.8,
        )
        template = generator._resolve_template_for_gap(gap)
        assert template["metadata"]["tool_id"] == "prototype_pollution", f"Description '{desc}' did not resolve to prototype_pollution"


def test_task_generator_from_gaps_generation():
    generator = TaskGenerator(mission=Mission(target="http://example.com"))
    generator.mission = types.SimpleNamespace(
        target="http://example.com",
        subdomains=[],
        live_hosts=["http://example.com"],
        endpoints=["http://example.com/api/v1", "http://example.com/login"],
    )
    gap = CoverageGap(
        id="gap_pp",
        category=TaskCategory.EVIDENCE_CORRELATION,
        area="prototype pollution",
        description="Test prototype pollution on API endpoints",
        severity=0.8,
    )
    tasks = generator.from_gaps([gap])
    assert len(tasks) == 1
    task = tasks[0]
    assert task.title == "Validate Prototype Pollution & Client-Side Attacks"
    assert "http://example.com/api/v1" in task.required_inputs
    assert task.metadata.get("tool_id") == "prototype_pollution"


# =============================================================================
# Pipeline Tests: Attack Surface Graph Section 29 Construction (R5)
# =============================================================================

def test_attack_surface_graph_section29_node_creation():
    builder = AttackSurfaceGraphBuilder()
    ev = Evidence(
        category="prototype_pollution",
        value="prototype_pollution:server-side-pp:http://example.com/api/settings:__proto__",
        source="prototype_pollution",
        title="Server-Side Prototype Pollution on http://example.com/api/settings",
        metadata={
            "url": "http://example.com/api/settings",
            "host": "http://example.com",
            "template_id": "server-side-pp",
            "parameter": "__proto__",
            "technique": "server_side_json_prototype_pollution",
            "severity": "high",
        },
    )
    graph = builder.build_from_evidence([ev])
    assert "live_host:http://example.com" in graph.nodes
    assert "endpoint:http://example.com/api/settings" in graph.nodes
    assert "vulnerability:server-side-pp:http://example.com/api/settings:__proto__" in graph.nodes


def test_attack_surface_graph_section29_has_vulnerability_edges():
    builder = AttackSurfaceGraphBuilder()
    ev = Evidence(
        category="dom_clobbering",
        value="dom_clobbering:clobber-cookie:http://example.com/profile:cookie",
        source="prototype_pollution",
        title="DOM Clobbering on http://example.com/profile",
        metadata={
            "url": "http://example.com/profile",
            "host": "http://example.com",
            "template_id": "dom-clobber-cookie",
            "parameter": "cookie",
            "severity": "medium",
        },
    )
    graph = builder.build_from_evidence([ev])
    edge_types = [e.type for e in graph.edges]
    assert "HAS_ENDPOINT" in edge_types
    assert "HAS_VULNERABILITY" in edge_types

    vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(vuln_edges) >= 2  # from live_host and from endpoint


def test_attack_surface_graph_reconstruction_from_evidence_store():
    store = EvidenceStore()
    ev1 = Evidence(
        category="prototype_pollution",
        value="pp_ev1",
        source="prototype_pollution",
        title="PP 1",
        metadata={"url": "http://example.com/api/test", "host": "http://example.com", "parameter": "__proto__"},
    )
    ev2 = Evidence(
        category="open_redirect",
        value="or_ev2",
        source="prototype_pollution",
        title="OR 2",
        metadata={"url": "http://example.com/login", "host": "http://example.com", "parameter": "next"},
    )
    ev3 = Evidence(
        category="clickjacking",
        value="cj_ev3",
        source="prototype_pollution",
        title="CJ 3",
        metadata={"url": "http://example.com/admin", "host": "http://example.com", "parameter": "XFO"},
    )
    store.add(ev1)
    store.add(ev2)
    store.add(ev3)

    builder = AttackSurfaceGraphBuilder()
    graph = builder.build_from_evidence(store.all())
    assert len(graph.nodes) >= 6  # live_host + 3 endpoints + 3 vulns
    assert len(graph.edges) >= 6


# =============================================================================
# Pipeline Tests: CVSS v3.1 & CWE Mappings (R5)
# =============================================================================

def test_cvss_calculator_cwe_mappings():
    calc = CVSSCalculator()
    assert calc.get_cwe_for_category("prototype_pollution").id == "CWE-1321"
    assert calc.get_cwe_for_category("server_side_prototype_pollution").id == "CWE-1321"
    assert calc.get_cwe_for_category("client_side_prototype_pollution").id == "CWE-1321"
    assert calc.get_cwe_for_category("dom_clobbering").id == "CWE-79"
    assert calc.get_cwe_for_category("dom_clobbering_xss").id == "CWE-79"
    assert calc.get_cwe_for_category("open_redirect").id == "CWE-601"
    assert calc.get_cwe_for_category("open_redirect_chain").id == "CWE-601"
    assert calc.get_cwe_for_category("clickjacking").id == "CWE-1021"
    assert calc.get_cwe_for_category("ui_redressing").id == "CWE-1021"


def test_cvss_calculator_preset_vectors_critical_rce():
    calc = CVSSCalculator()
    cvss = calc.derive_cvss_for_vulnerability("prototype_pollution_rce", ReportSeverity.CRITICAL)
    assert cvss.score == 9.8
    assert cvss.severity_rating == "Critical"
    assert cvss.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_cvss_calculator_preset_vectors_high_pollution():
    calc = CVSSCalculator()
    cvss = calc.derive_cvss_for_vulnerability("prototype_pollution", ReportSeverity.HIGH)
    assert cvss.score == 8.2
    assert cvss.severity_rating == "High"


def test_cvss_calculator_preset_vectors_medium_open_redirect_and_clickjacking():
    calc = CVSSCalculator()
    cvss_or = calc.derive_cvss_for_vulnerability("open_redirect", ReportSeverity.MEDIUM)
    assert cvss_or.score in (5.3, 6.1)
    assert cvss_or.severity_rating == "Medium"

    cvss_cj = calc.derive_cvss_for_vulnerability("clickjacking", ReportSeverity.MEDIUM)
    assert cvss_cj.score == 5.3
    assert cvss_cj.severity_rating == "Medium"


def test_controlled_mission_wrapper_compatibility():
    class MockControlledMission:
        def __init__(self, raw_mission: Any):
            self._raw_mission = raw_mission
            self.published: List[Tuple[str, Evidence]] = []

        def publish_finding(self, finding_id: str, evidence: Evidence) -> None:
            self.published.append((finding_id, evidence))

    raw_m = types.SimpleNamespace(
        target="http://example.com",
        endpoints=["http://example.com/api/test"],
        live_hosts=["http://example.com"],
        evidence=EvidenceStore(),
        vulnerabilities=[],
        attack_surface_graph=KnowledgeGraph(),
    )
    ctrl_m = MockControlledMission(raw_m)

    collector = PrototypePollutionCollector()
    collector.generator.generate_all_probes = lambda u: [
        PrototypePollutionProbe(
            probe_id="p_ctrl",
            target_url="http://example.com/api/test",
            method="POST",
            vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
            canary_property="canary_published",
        )
    ]

    # Prober returns valid finding
    collector.prober.execute_probe = lambda m, u, p: PrototypePollutionProbeResponse(
        probe=p, status_code=200, body='{"canary_published": true}', side_effect_observed=True,
    )

    ev_list = collector.collect(ctrl_m)
    assert len(ev_list) == 1
    assert len(ctrl_m.published) == 1
