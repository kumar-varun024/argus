import pytest
import threading
import time
import json
from unittest.mock import patch

from argus.runtime.mission import Mission, MissionState
from argus.runtime.controller import MissionController
from argus.runtime.checkpoint import MissionCheckpointer
from argus.runtime.registry import registry
from argus.runtime.models import Tool
from argus.evidence.store import EvidenceStore

# Dummy outputs for tools
SUBFINDER_OUTPUT = "api.example.com\nadmin.example.com"
HTTPX_OUTPUT = '{"url":"http://api.example.com","host":"api.example.com","status_code":200,"webserver":"nginx","tech":["Nginx","React"]}\n{"url":"http://admin.example.com","host":"admin.example.com","status_code":403}'
KATANA_OUTPUT = "http://api.example.com/v1/users\nhttp://api.example.com/v1/login"
NUCLEI_OUTPUT = '{"template-id": "CVE-2023-XXXX", "info": {"name": "Example CVE", "severity": "high", "description": "A test CVE"}, "host": "http://api.example.com"}'

def mock_execute_command(self, command, args, timeout=60.0):
    if "subfinder" in command:
        return {"stdout": SUBFINDER_OUTPUT, "stderr": ""}
    elif "httpx" in command:
        return {"stdout": HTTPX_OUTPUT, "stderr": ""}
    elif "katana" in command:
        return {"stdout": KATANA_OUTPUT, "stderr": ""}
    elif "nuclei" in command:
        return {"stdout": NUCLEI_OUTPUT, "stderr": ""}
    return {"stdout": "", "stderr": ""}


from argus.planning.models import TaskCategory

@pytest.fixture
def isolated_tool_registry():
    # Backup original tools
    original_tools = dict(registry.tools)
    # Clear the global registry to prevent built-in internal tools from hijacking
    registry.tools.clear()
    
    # Make sure basic tools are registered so TaskGenerator maps tasks to them
    # Ensure they don't get stuck
    tools = [
        Tool(
            id="subfinder", name="Subfinder", capability="subdomain_discovery",
            description="Finds subdomains", command="subfinder",
            supported_tasks=[TaskCategory.TECHNOLOGY_DISCOVERY], timeout=10.0, priority=10
        ),
        Tool(
            id="httpx", name="HTTPX", capability="http_probing",
            description="Probes HTTP", command="httpx",
            supported_tasks=[TaskCategory.TECHNOLOGY_DISCOVERY], timeout=10.0, priority=10
        ),
        Tool(
            id="katana_crawler", name="Katana", capability="web_crawling",
            description="Crawls endpoints", command="katana",
            supported_tasks=[TaskCategory.API_DISCOVERY], timeout=10.0, priority=10
        ),
        Tool(
            id="nuclei", name="Nuclei", capability="vulnerability_scanning",
            description="Scans vulns", command="nuclei",
            supported_tasks=[TaskCategory.EVIDENCE_CORRELATION], timeout=10.0, priority=10
        )
    ]
    for t in tools:
        registry.register(t)
    yield registry
    
    # Restore original tools
    registry.tools.clear()
    registry.tools.update(original_tools)


@patch("argus.planning.task_generator.TaskGenerator.from_gaps", lambda self, gaps: self.generate_recon_tasks())
@patch("argus.runtime.sandbox.Sandbox.execute_command", new=mock_execute_command)
def test_e2e_mission_execution(isolated_tool_registry):
    """
    E2E test verifying:
    Mission -> Runtime -> Planner -> TaskScheduler -> ToolOrchestrator 
    -> parser -> Evidence -> KnowledgeManager -> Completion.
    """
    mission = Mission(target="example.com")
    mission.scope = ["example.com", "api.example.com"]
    mission.evidence = EvidenceStore()
    
    checkpointer = MissionCheckpointer()
    controller = MissionController(checkpointer)
    
    controller.start(mission)
    
    # Wait for mission to complete or timeout
    max_wait = 20 # seconds
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        # Check if completed
        if mission.status in (MissionState.COMPLETED, MissionState.FAILED, MissionState.CANCELLED):
            break
        time.sleep(0.5)
        
    assert mission.status == MissionState.COMPLETED, f"Mission failed with status {mission.status}"
    
    # Verify the pipeline successfully produced evidence from mocked external outputs
    assert hasattr(mission, "evidence")
    assert mission.evidence is not None
    
    evidence_list = mission.evidence.all()
    assert len(evidence_list) > 0, "Mission failed to collect evidence"
    
    categories = {ev.category for ev in evidence_list}
    expected_categories = {"subdomain", "live_host", "technology", "endpoint", "vulnerability"}
    assert expected_categories.issubset(categories), f"Missing categories: {expected_categories - categories}"

    # Verify metadata on evidence items
    subdomain_evs = [ev for ev in evidence_list if ev.category == "subdomain"]
    assert len(subdomain_evs) > 0
    for ev in subdomain_evs:
        assert "hostname" in ev.metadata
        assert isinstance(ev.metadata["hostname"], str)

    live_host_evs = [ev for ev in evidence_list if ev.category == "live_host"]
    assert len(live_host_evs) > 0
    for ev in live_host_evs:
        assert "url" in ev.metadata
        assert "status" in ev.metadata
        assert "technologies" in ev.metadata

    tech_evs = [ev for ev in evidence_list if ev.category == "technology"]
    assert len(tech_evs) > 0
    for ev in tech_evs:
        assert "name" in ev.metadata
        assert isinstance(ev.metadata["name"], str)

    endpoint_evs = [ev for ev in evidence_list if ev.category == "endpoint"]
    assert len(endpoint_evs) > 0
    for ev in endpoint_evs:
        assert "url" in ev.metadata

    vuln_evs = [ev for ev in evidence_list if ev.category == "vulnerability"]
    assert len(vuln_evs) > 0
    for ev in vuln_evs:
        assert "template_id" in ev.metadata
        assert ev.severity == "high"

    # Verify structured mission state attributes
    assert isinstance(mission.subdomains, list)
    assert all(isinstance(s, str) for s in mission.subdomains)
    assert len(mission.subdomains) > 0

    assert isinstance(mission.live_hosts, list)
    assert all(isinstance(h, dict) for h in mission.live_hosts)
    assert len(mission.live_hosts) > 0

    assert isinstance(mission.endpoints, list)
    assert all(isinstance(ep, dict) for ep in mission.endpoints)
    assert len(mission.endpoints) > 0

    assert isinstance(mission.vulnerabilities, list)
    assert all(isinstance(v, dict) for v in mission.vulnerabilities)
    assert len(mission.vulnerabilities) > 0

    assert isinstance(mission.technologies, list)
    assert len(mission.technologies) > 0

    # Check that execution history / results are recorded
    assert hasattr(mission, "execution_results")

    # Sprint 3 Graph & Reasoning Pipeline assertions
    assert getattr(mission, "attack_surface_graph", None) is not None, "attack_surface_graph is missing"
    assert mission.attack_surface_graph.node_count() > 0, "attack_surface_graph has 0 nodes"
    assert len(mission.attack_surface_graph.nodes_by_type("subdomain")) >= 1, "Graph missing subdomain nodes"
    assert len(mission.attack_surface_graph.nodes_by_type("live_host")) >= 1, "Graph missing live_host nodes"

    assert hasattr(mission, "correlations") and hasattr(mission.correlations, "get_all")
    assert len(mission.correlations.get_all()) >= 1, "Expected at least 1 correlation in mission"

    assert hasattr(mission, "investigations") and hasattr(mission.investigations, "get_all")
    assert len(mission.investigations.get_all()) >= 1, "Expected at least 1 investigation in mission"

    assert hasattr(mission, "hypotheses") and hasattr(mission.hypotheses, "get_all")
    assert len(mission.hypotheses.get_all()) >= 1, "Expected at least 1 hypothesis in mission"
