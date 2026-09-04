from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock

from argus.runtime.mission import Mission, MissionState
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence
from argus.collectors.subfinder import SubfinderCollector
from argus.collectors.httpx import HttpxCollector
from argus.collectors.katana import KatanaCollector
from argus.collectors.nuclei import NucleiCollector
from argus.runtime.registry import registry
from argus.scanning.engine import ScanEngine
from argus.scanning.models import CollectorStatus


@pytest.fixture
def clean_mission():
    mission = Mission(target="http://api.example.com:8080/v1/users?role=admin")
    mission.evidence = EvidenceStore()
    return mission


def test_subfinder_collector_fallback_when_binary_missing(clean_mission):
    """SubfinderCollector falls back to extracting host from target when binary is absent."""
    collector = SubfinderCollector()

    with patch("shutil.which", return_value=None):
        evidence_items = collector.collect(clean_mission)

    assert clean_mission.subdomains == ["api.example.com"]
    assert len(evidence_items) == 1
    assert evidence_items[0].category == "subdomain"
    assert evidence_items[0].value == {"subdomain": "api.example.com"}
    assert clean_mission.evidence.count() >= 1
    assert len(clean_mission.evidence.filter("subdomain")) >= 1


def test_subfinder_collector_fallback_when_command_fails(clean_mission):
    """SubfinderCollector falls back to target seeding if command execution raises."""
    collector = SubfinderCollector()

    with patch("shutil.which", return_value="/usr/bin/subfinder"), \
         patch.object(collector.runtime, "run_command", side_effect=RuntimeError("Subfinder error")):
        evidence_items = collector.collect(clean_mission)

    assert clean_mission.subdomains == ["api.example.com"]
    assert len(evidence_items) == 1
    assert evidence_items[0].category == "subdomain"


def test_subfinder_collector_success_when_binary_present():
    """SubfinderCollector parses stdout when binary succeeds."""
    mission = Mission(target="example.com")
    collector = SubfinderCollector()
    mock_output = {"stdout": "sub1.example.com\nsub2.example.com\n", "stderr": "", "exit_code": 0}

    with patch("shutil.which", return_value="/usr/bin/subfinder"), \
         patch.object(collector.runtime, "run_command", return_value=mock_output):
        evidence_items = collector.collect(mission)

    assert "sub1.example.com" in mission.subdomains
    assert "sub2.example.com" in mission.subdomains
    assert len(evidence_items) == 2
    assert all(e.category == "subdomain" for e in evidence_items)


def test_httpx_collector_fallback_when_binary_missing(clean_mission):
    """HttpxCollector falls back to generating structured live_hosts when binary is absent."""
    clean_mission.subdomains = ["api.example.com"]
    collector = HttpxCollector()

    with patch("shutil.which", return_value=None):
        evidence_items = collector.collect(clean_mission)

    assert len(clean_mission.live_hosts) == 1
    host = clean_mission.live_hosts[0]
    assert host["host"] == "api.example.com"
    assert host["scheme"] == "http"
    assert host["port"] == 8080
    assert host["url"] == "http://api.example.com:8080"
    assert host["status"] == 200
    assert "technologies" in host

    assert len(evidence_items) == 1
    assert evidence_items[0].category == "live_host"
    assert len(clean_mission.evidence.filter("live_host")) >= 1


def test_httpx_collector_fallback_when_command_fails(clean_mission):
    """HttpxCollector falls back to seeding live hosts if command execution fails."""
    clean_mission.subdomains = ["api.example.com"]
    collector = HttpxCollector()

    with patch("shutil.which", return_value="/usr/bin/httpx"), \
         patch.object(collector.runtime, "run_command", side_effect=OSError("httpx binary missing")):
        evidence_items = collector.collect(clean_mission)

    assert len(clean_mission.live_hosts) == 1
    assert clean_mission.live_hosts[0]["host"] == "api.example.com"
    assert len(evidence_items) == 1
    assert evidence_items[0].category == "live_host"


def test_httpx_collector_success_when_binary_present():
    """HttpxCollector correctly parses json output when binary is available."""
    mission = Mission(target="example.com")
    mission.subdomains = ["example.com"]
    collector = HttpxCollector()

    mock_json = json.dumps({
        "url": "https://example.com",
        "input": "example.com",
        "status-code": 200,
        "title": "Example Domain",
        "webserver": "ECS",
        "tech": ["Nginx"],
    })
    mock_output = {"stdout": mock_json, "stderr": "", "exit_code": 0}

    with patch("shutil.which", return_value="/usr/bin/httpx"), \
         patch.object(collector.runtime, "run_command", return_value=mock_output):
        evidence_items = collector.collect(mission)

    assert len(mission.live_hosts) == 1
    assert mission.live_hosts[0]["url"] == "https://example.com"
    assert len(evidence_items) == 1
    assert evidence_items[0].category == "live_host"


def test_katana_collector_fallback_when_binary_missing(clean_mission):
    """KatanaCollector falls back to generating structured endpoint records when binary is absent."""
    clean_mission.live_hosts = [{"url": "http://api.example.com:8080", "host": "api.example.com", "port": 8080}]
    collector = KatanaCollector()

    with patch("shutil.which", return_value=None):
        evidence_items = collector.collect(clean_mission)

    assert len(clean_mission.endpoints) == 1
    ep = clean_mission.endpoints[0]
    assert ep["host"] == "http://api.example.com:8080"
    assert ep["path"] == "/v1/users"
    assert ep["params"] == {"role": "admin"}
    assert ep["method"] == "GET"
    assert ep["url"] == "http://api.example.com:8080/v1/users"

    assert len(evidence_items) == 1
    assert evidence_items[0].category == "endpoint"
    assert len(clean_mission.evidence.filter("endpoint")) >= 1


def test_katana_collector_fallback_when_command_fails(clean_mission):
    """KatanaCollector falls back to structured endpoint seeding on runtime failure."""
    clean_mission.live_hosts = [{"url": "http://api.example.com:8080"}]
    collector = KatanaCollector()

    with patch("shutil.which", return_value="/usr/bin/katana"), \
         patch.object(collector.runtime, "run_command", side_effect=Exception("Katana process failure")):
        evidence_items = collector.collect(clean_mission)

    assert len(clean_mission.endpoints) >= 1
    assert len(evidence_items) >= 1
    assert evidence_items[0].category == "endpoint"


def test_katana_collector_success_when_binary_present():
    """KatanaCollector parses endpoints from katana output."""
    mission = Mission(target="example.com")
    mission.live_hosts = [{"url": "https://example.com"}]
    collector = KatanaCollector()

    mock_output = {"stdout": "https://example.com/login\nhttps://example.com/api/v1\n", "stderr": "", "exit_code": 0}

    with patch("shutil.which", return_value="/usr/bin/katana"), \
         patch.object(collector.runtime, "run_command", return_value=mock_output):
        evidence_items = collector.collect(mission)

    assert len(mission.endpoints) == 2
    assert any(ep["url"] == "https://example.com/login" for ep in mission.endpoints)
    assert any(ep["url"] == "https://example.com/api/v1" for ep in mission.endpoints)
    assert len(evidence_items) == 2
    assert all(e.category == "endpoint" for e in evidence_items)


def test_nuclei_collector_clean_exit_when_binary_missing(clean_mission):
    """NucleiCollector completes cleanly with empty list when nuclei binary is not installed."""
    clean_mission.live_hosts = [{"url": "http://api.example.com:8080"}]
    collector = NucleiCollector()

    with patch("shutil.which", return_value=None):
        evidence_items = collector.collect(clean_mission)

    assert evidence_items == []
    assert clean_mission.vulnerabilities == []


def test_nuclei_collector_empty_live_hosts():
    """NucleiCollector returns cleanly if no live hosts exist."""
    mission = Mission(target="example.com")
    mission.live_hosts = []
    collector = NucleiCollector()

    evidence_items = collector.collect(mission)
    assert evidence_items == []


def test_nuclei_collector_success_jsonl_parsing(clean_mission):
    """NucleiCollector correctly parses JSONL findings and generates Evidence."""
    clean_mission.live_hosts = [{"url": "http://api.example.com:8080"}]
    collector = NucleiCollector()

    mock_finding = json.dumps({
        "template-id": "git-config",
        "info": {
            "name": "Git Config Disclosure",
            "severity": "high",
            "description": "Exposed git configuration file found.",
        },
        "matched-at": "http://api.example.com:8080/.git/config",
    })
    mock_output = {"stdout": mock_finding + "\n", "stderr": "", "exit_code": 0}

    with patch("shutil.which", return_value="/usr/bin/nuclei"), \
         patch.object(collector.runtime, "run_command", return_value=mock_output):
        evidence_items = collector.collect(clean_mission)

    assert len(clean_mission.vulnerabilities) == 1
    assert len(evidence_items) == 1
    assert evidence_items[0].category == "vulnerability"
    assert evidence_items[0].severity == "high"
    assert "Git Config Disclosure" in evidence_items[0].title
    assert len(clean_mission.evidence.filter("vulnerability")) >= 1


def test_registry_httpx_aliases_and_resolution():
    """ToolRegistry resolves httpx and its capability aliases and commands."""
    tool = registry.get("httpx")
    assert tool is not None
    assert tool.id == "httpx"

    tool_alias = registry.get("httpx-toolkit")
    assert tool_alias is not None
    assert tool_alias.id == "httpx"

    tool_cap = registry.get("live_host_detector")
    assert tool_cap is not None
    assert tool_cap.id == "httpx"

    cmd = registry.resolve_tool_command("httpx")
    assert cmd is not None


def test_end_to_end_dag_execution_with_all_recon_fallbacks():
    """ScanEngine executes recon tasks using fallbacks and passes data to downstream tasks."""
    from argus.scanning.dag import ScanDAG, ScanTask

    dag = ScanDAG(tasks=[
        ScanTask(key="subfinder", title="Subdomain Enumeration", tool_id="subfinder", dependencies=[]),
        ScanTask(key="httpx", title="Live Host Discovery", tool_id="httpx", dependencies=["subfinder"]),
        ScanTask(key="katana_crawler", title="Endpoint Discovery", tool_id="katana_crawler", dependencies=["httpx"]),
        ScanTask(key="nuclei", title="Nuclei Vulnerability Scan", tool_id="nuclei", dependencies=["httpx"]),
        ScanTask(key="vulnerability_scanner", title="Vulnerability Scan", tool_id="sql_injection", dependencies=["katana_crawler"]),
    ])

    def collector_factory(task):
        if task.key == "vulnerability_scanner":
            class DummyVulnCollector:
                def collect(self, m):
                    assert len(m.endpoints) > 0, "Downstream task should receive endpoints from Katana fallback"
                    ev = Evidence(title="SQLi Found", category="vulnerability", severity="high")
                    m.evidence.add(ev)
                    return [ev]
            return DummyVulnCollector()
        return None  # Use real collector from engine resolution (Subfinder, Httpx, Katana, Nuclei)

    mission = Mission(target="http://api.example.com:8080/test")
    engine = ScanEngine(dag=dag, collector_factory=collector_factory)

    with patch("shutil.which", return_value=None):
        scan_result = engine.run(mission)

    assert scan_result.status == "COMPLETED"
    assert scan_result.collectors_failed == 0
    assert scan_result.collectors_skipped == 0
    assert len(mission.subdomains) > 0
    assert len(mission.live_hosts) > 0
    assert len(mission.endpoints) > 0
    assert mission.evidence.count() >= 4

    # Check collector results for recon tasks
    subfinder_res = scan_result.get_collector_result("subfinder")
    assert subfinder_res is not None
    assert subfinder_res.status == CollectorStatus.COMPLETED

    httpx_res = scan_result.get_collector_result("httpx")
    assert httpx_res is not None
    assert httpx_res.status == CollectorStatus.COMPLETED

    katana_res = scan_result.get_collector_result("katana_crawler")
    assert katana_res is not None
    assert katana_res.status == CollectorStatus.COMPLETED

    nuclei_res = scan_result.get_collector_result("nuclei")
    assert nuclei_res is not None
    assert nuclei_res.status == CollectorStatus.COMPLETED
