"""Unit and functional tests for TaskGenerator XSS scheduling, ToolRegistry, and PluginExecutorAdapter."""
import pytest
from argus.planning.models import CoverageGap, TaskCategory, ResearchTask
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.runtime.mission import Mission
from argus.runtime.registry import registry
from argus.runtime.plugins import PluginExecutorAdapter
from argus.collectors.xss import XSSCollector


class TestTaskGeneratorXSS:
    """Test suite for TaskGenerator XSS template and gap resolution."""

    def test_xss_template_configuration(self):
        """Verify _RECON_TEMPLATES contains the properly configured xss template."""
        assert "xss" in _RECON_TEMPLATES
        tpl = _RECON_TEMPLATES["xss"]
        assert tpl["title"] == "Fuzz Cross-Site Scripting (XSS)"
        assert tpl["category"] == TaskCategory.EVIDENCE_CORRELATION
        assert tpl["required_inputs"] == ["endpoints"]
        assert tpl["expected_outputs"] == ["vulnerabilities", "observations", "evidence"]
        assert tpl["dependencies"] == ["Discover API Endpoints"]
        assert tpl["metadata"]["tool_id"] == "xss"
        assert tpl["priority"] == 0.81

    @pytest.mark.parametrize("area", [
        "xss",
        "xss detection",
        "cross site scripting",
        "cross-site scripting",
        "stored xss",
        "reflected xss",
        "dom xss",
        "XSS",
        "Cross-Site Scripting",
    ])
    def test_resolve_template_for_gap_xss_areas(self, area):
        """Verify _resolve_template_for_gap maps all XSS area variants to the xss template."""
        mission = Mission(target="example.com")
        tg = TaskGenerator(mission)
        gap = CoverageGap(
            area=area,
            description=f"Missing tests for {area}",
            category=TaskCategory.EVIDENCE_CORRELATION,
            severity=0.85,
        )
        resolved = tg._resolve_template_for_gap(gap)
        assert resolved["title"] == "Fuzz Cross-Site Scripting (XSS)"
        assert resolved["metadata"]["tool_id"] == "xss"

    @pytest.mark.parametrize("desc", [
        "Fuzz endpoints for potential xss issues",
        "Test cross-site reflection in parameters",
        "Detect vulnerable scripting vectors",
    ])
    def test_resolve_template_for_gap_evidence_correlation_fallback(self, desc):
        """Verify EVIDENCE_CORRELATION category with XSS keywords maps to xss template."""
        mission = Mission(target="example.com")
        tg = TaskGenerator(mission)
        gap = CoverageGap(
            area="Unspecified Area",
            description=desc,
            category=TaskCategory.EVIDENCE_CORRELATION,
            severity=0.8,
        )
        resolved = tg._resolve_template_for_gap(gap)
        assert resolved["title"] == "Fuzz Cross-Site Scripting (XSS)"
        assert resolved["metadata"]["tool_id"] == "xss"

    def test_from_gaps_with_endpoints(self):
        """Verify from_gaps extracts endpoint inputs when endpoints are available in mission."""
        mission = Mission(target="example.com")
        mission.endpoints = [
            {"url": "https://example.com/search?q=1"},
            {"url": "https://example.com/profile"},
        ]
        tg = TaskGenerator(mission)
        gap = CoverageGap(
            area="xss",
            description="XSS gap detected on endpoints",
            category=TaskCategory.EVIDENCE_CORRELATION,
            severity=0.9,
        )
        tasks = tg.from_gaps([gap])
        assert len(tasks) == 1
        task = tasks[0]
        assert isinstance(task, ResearchTask)
        assert task.title == "Fuzz Cross-Site Scripting (XSS)"
        assert task.metadata["tool_id"] == "xss"
        assert task.required_inputs == [
            "https://example.com/search?q=1",
            "https://example.com/profile",
        ]
        assert task.priority == 0.9

    def test_from_gaps_fallback_to_live_hosts(self):
        """Verify from_gaps falls back to live_hosts when no endpoints are discovered yet."""
        mission = Mission(target="example.com")
        mission.live_hosts = ["https://example.com"]
        tg = TaskGenerator(mission)
        gap = CoverageGap(
            area="xss",
            description="XSS gap",
            category=TaskCategory.EVIDENCE_CORRELATION,
            severity=0.85,
        )
        tasks = tg.from_gaps([gap])
        assert len(tasks) == 1
        assert tasks[0].required_inputs == ["https://example.com"]


class TestToolRegistryAndPluginAdapterXSS:
    """Test suite for XSS tool registration in registry and plugin fallback instantiation."""

    def test_registry_get_xss_by_id(self):
        """Verify registry.get('xss') retrieves the XSS Tool."""
        tool = registry.get("xss")
        assert tool is not None
        assert tool.id == "xss"
        assert tool.capability == "xss_detector"
        assert "xss_collector" in tool.capabilities
        assert "XSS Detection" in tool.supported_tasks

    def test_registry_get_xss_by_alias_and_capability(self):
        """Verify registry.get resolves 'cross_site_scripting' and 'xss_detector'."""
        tool_alias = registry.get("cross_site_scripting")
        assert tool_alias is not None
        assert tool_alias.id == "xss"

        tool_cap = registry.get("xss_detector")
        assert tool_cap is not None
        assert tool_cap.id == "xss"

        tool_col = registry.get("xss_collector")
        assert tool_col is not None
        assert tool_col.id == "xss"

    def test_plugin_executor_fallback_instantiation(self):
        """Verify PluginExecutorAdapter._instantiate_specialist_fallback instantiates XSSCollector."""
        adapter = PluginExecutorAdapter()
        inst1 = adapter._instantiate_specialist_fallback("xss")
        assert isinstance(inst1, XSSCollector)

        inst2 = adapter._instantiate_specialist_fallback("cross_site_scripting")
        assert isinstance(inst2, XSSCollector)
