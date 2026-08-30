"""
Tests for Information Disclosure DAG Task Generation, Gap Analysis, and Tool Dispatching.
"""
import pytest

from argus.planning.models import ResearchTask, CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.planning.gap_analysis import GapAnalyzer
from argus.planning.steps import build_probe_information_disclosure_step, ALL_STEPS_BUILDERS
from argus.runtime.mission import Mission
from argus.runtime.registry import registry
from argus.runtime.dispatcher import ToolDispatcher
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence


def test_recon_templates_contain_info_disclosure():
    """Verifies that _RECON_TEMPLATES contains info_disclosure with correct priority and dependency."""
    assert "info_disclosure" in _RECON_TEMPLATES
    t = _RECON_TEMPLATES["info_disclosure"]
    assert t["title"] == "Probe Information Disclosure"
    assert t["priority"] == 0.82
    assert t["dependencies"] == ["Fingerprint Live Hosts"]
    assert t["metadata"]["tool_id"] == "info_disclosure"
    assert t["category"] == TaskCategory.EVIDENCE_CORRELATION


def test_task_generator_generates_info_disclosure_task():
    """Verifies that generate_recon_tasks creates the info_disclosure task in the recon chain."""
    mission = Mission(target="target.example.com")
    mission.live_hosts = [{"url": "https://target.example.com"}]
    generator = TaskGenerator(mission)
    tasks = generator.generate_recon_tasks()

    info_tasks = [t for t in tasks if t.metadata.get("tool_id") == "info_disclosure"]
    assert len(info_tasks) == 1
    t = info_tasks[0]
    assert t.title == "Probe Information Disclosure"
    assert t.priority == 0.82
    assert t.dependencies == ["Fingerprint Live Hosts"]
    assert "https://target.example.com" in t.required_inputs


def test_gap_analyzer_emits_info_disclosure_gap_when_live_hosts_exist():
    """Verifies that GapAnalyzer flags missing Information Disclosure scan when live hosts are present."""
    mission = Mission(target="example.com")
    mission.live_hosts = [{"url": "https://api.example.com"}]
    mission.endpoints = [{"url": "/api/v1"}]

    analyzer = GapAnalyzer(mission)
    gaps = analyzer.analyze()
    areas = [g.area for g in gaps]

    assert "Information Disclosure" in areas
    info_gap = next(g for g in gaps if g.area == "Information Disclosure")
    assert info_gap.severity == 0.82
    assert info_gap.category == TaskCategory.EVIDENCE_CORRELATION


def test_gap_analyzer_suppresses_gap_when_vulnerabilities_recorded():
    """Verifies that GapAnalyzer suppresses Information Disclosure gap when finding exists."""
    mission = Mission(target="example.com")
    mission.live_hosts = [{"url": "https://api.example.com"}]
    mission.vulnerabilities = [{"template_id": "info-disclosure-env", "name": "Information Disclosure (.env)"}]

    analyzer = GapAnalyzer(mission)
    gaps = analyzer.analyze()
    areas = [g.area for g in gaps]

    assert "Information Disclosure" not in areas


def test_gap_analyzer_suppresses_gap_when_evidence_recorded():
    """Verifies that GapAnalyzer suppresses Information Disclosure gap when evidence is recorded."""
    mission = Mission(target="example.com")
    mission.live_hosts = [{"url": "https://api.example.com"}]
    mission.evidence = EvidenceStore()
    mission.evidence.add(Evidence(category="information_disclosure", value="https://api.example.com/.env"))

    analyzer = GapAnalyzer(mission)
    gaps = analyzer.analyze()
    areas = [g.area for g in gaps]

    assert "Information Disclosure" not in areas


def test_gap_analyzer_suppresses_gap_when_tool_run_completed():
    """Verifies that GapAnalyzer suppresses Information Disclosure gap when tool run succeeded."""
    mission = Mission(target="example.com")
    mission.live_hosts = [{"url": "https://api.example.com"}]
    mission.tool_runs = {
        "run-1": {
            "tool_id": "info_disclosure",
            "status": "COMPLETED",
        }
    }

    analyzer = GapAnalyzer(mission)
    gaps = analyzer.analyze()
    areas = [g.area for g in gaps]

    assert "Information Disclosure" not in areas


def test_from_gaps_converts_info_disclosure_gap_to_task():
    """Verifies that TaskGenerator.from_gaps maps Information Disclosure gap to concrete ResearchTask."""
    mission = Mission(target="example.com")
    mission.live_hosts = [{"url": "https://api.example.com"}]
    gap = CoverageGap(
        area="Information Disclosure",
        description="Probe exposed files",
        severity=0.82,
        category=TaskCategory.EVIDENCE_CORRELATION,
        related_assets=["https://api.example.com"],
    )

    tasks = TaskGenerator(mission).from_gaps([gap])
    assert len(tasks) == 1
    task = tasks[0]
    assert task.title == "Probe Information Disclosure"
    assert task.metadata.get("tool_id") == "info_disclosure"
    assert task.dependencies == ["Fingerprint Live Hosts"]
    assert "https://api.example.com" in task.required_inputs


def test_tool_dispatcher_resolves_info_disclosure():
    """Verifies that ToolDispatcher resolves info_disclosure tool from registry."""
    dispatcher = ToolDispatcher(registry)
    task = ResearchTask(
        title="Probe Information Disclosure",
        description="Probe live hosts for exposed configs",
        goal="Probe for exposed configs",
        category=TaskCategory.EVIDENCE_CORRELATION,
        metadata={"tool_id": "info_disclosure"},
    )

    tool = dispatcher.resolve_tool(task)
    assert tool is not None
    assert tool.id == "info_disclosure"
    assert tool.capability == "information_disclosure_detector"



def test_steps_builder_probe_information_disclosure():
    """Verifies that static step builder exists and is registered in ALL_STEPS_BUILDERS."""
    step = build_probe_information_disclosure_step()
    assert step.name == "Probe Information Disclosure"
    assert "Discover APIs" in step.dependencies
    assert any(b().name == "Probe Information Disclosure" for b in ALL_STEPS_BUILDERS)
