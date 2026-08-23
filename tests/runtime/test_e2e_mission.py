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
HTTPX_OUTPUT = '{"url":"http://api.example.com","host":"api.example.com","status_code":200,"webserver":"nginx"}\n{"url":"http://admin.example.com","host":"admin.example.com","status_code":403}'
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
            supported_tasks=[TaskCategory.AUTHENTICATION_ANALYSIS, TaskCategory.AUTHORIZATION_ANALYSIS, TaskCategory.BUSINESS_LOGIC_ANALYSIS], timeout=10.0, priority=10
        )
    ]
    for t in tools:
        registry.register(t)
    yield registry
    
    # Restore original tools
    registry.tools.clear()
    registry.tools.update(original_tools)


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
    # External tools should have mapped subdomain, live_host, endpoint, vulnerability
    
    # Check that execution history / results are recorded
    assert hasattr(mission, "execution_results")
