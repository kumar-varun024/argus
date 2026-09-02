import os
import tempfile
import pytest
from unittest.mock import MagicMock, patch

from argus.runtime.mission import Mission, MissionState
from argus.runtime.state_machine import MissionStateMachine
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.reporting.generator import ReportGenerator
from argus.scanning.models import ScanResult, CollectorResult, CollectorStatus
from argus.scanning.dag import ScanDAG, ScanTask
from argus.scanning.engine import ScanEngine
from argus.models import (
    ScanResult as ModelsScanResult,
    CollectorResult as ModelsCollectorResult,
    CollectorStatus as ModelsCollectorStatus,
    MissionStatus,
)


class DummyCollector:
    def __init__(self, name="dummy", evidence_to_add=None, delay=0.0):
        self.name = name
        self.evidence_to_add = evidence_to_add or []
        self.delay = delay
        self.invoked = False
        self.invoked_with = None

    def collect(self, mission):
        self.invoked = True
        self.invoked_with = mission
        if self.delay > 0:
            import time
            time.sleep(self.delay)
        for ev in self.evidence_to_add:
            mission.evidence.add(ev)
        return self.evidence_to_add


def test_scan_dag_default_templates_loaded():
    """Verify all default templates from _RECON_TEMPLATES are loaded."""
    dag = ScanDAG()
    assert len(dag.tasks) == 26

    # Check key members exist
    keys = {t.key for t in dag.tasks}
    assert "subfinder" in keys
    assert "httpx" in keys
    assert "katana_crawler" in keys
    assert "nuclei" in keys
    assert "info_disclosure" in keys
    assert "sql_injection" in keys
    assert "xss" in keys
    assert "access_control" in keys
    assert "cors_security" in keys
    assert "file_upload" in keys
    assert "api_security" in keys
    assert "auth_bypass" in keys


def test_scan_dag_execution_order_dependencies():
    """Verify topological sorting places recon tasks before dependent vulnerability modules."""
    dag = ScanDAG()
    order = dag.get_execution_order()
    assert len(order) == 26

    order_keys = [t.key for t in order]

    # subfinder must be first
    assert order_keys[0] == "subfinder"

    # httpx must come after subfinder
    subfinder_idx = order_keys.index("subfinder")
    httpx_idx = order_keys.index("httpx")
    assert subfinder_idx < httpx_idx

    # katana_crawler, nuclei, info_disclosure must come after httpx
    katana_idx = order_keys.index("katana_crawler")
    nuclei_idx = order_keys.index("nuclei")
    info_idx = order_keys.index("info_disclosure")
    assert httpx_idx < katana_idx
    assert httpx_idx < nuclei_idx
    assert httpx_idx < info_idx

    # Vulnerability modules that depend on katana_crawler must appear after katana_crawler
    vuln_keys = [
        "access_control", "path_traversal", "sql_injection", "xss",
        "command_injection", "ssrf", "oauth", "xml_parser_validation",
        "deserialization", "graphql_security", "websocket_security",
        "request_smuggling", "race_conditions", "business_logic", "ssti", "cache_security",
        "cors_security", "file_upload", "api_security", "auth_bypass"
    ]
    for vk in vuln_keys:
        v_idx = order_keys.index(vk)
        assert katana_idx < v_idx, f"{vk} (idx {v_idx}) should come after katana_crawler (idx {katana_idx})"


def test_scan_dag_get_task_by_key_and_title():
    """Verify get_task lookups by key, tool_id, and title."""
    dag = ScanDAG()
    task1 = dag.get_task("subfinder")
    assert task1 is not None
    assert task1.title == "Discover Subdomains"

    task2 = dag.get_task("Discover Subdomains")
    assert task2 is not None
    assert task2.key == "subfinder"

    task3 = dag.get_task("katana_crawler")
    assert task3 is not None
    assert task3.title == "Discover API Endpoints"

    assert dag.get_task("nonexistent_task") is None


def test_scan_dag_custom_tasks():
    """Verify DAG construction with custom ScanTask list."""
    custom_tasks = [
        ScanTask(key="task_c", title="Task C", tool_id="tool_c", dependencies=["Task B"]),
        ScanTask(key="task_a", title="Task A", tool_id="tool_a", dependencies=[]),
        ScanTask(key="task_b", title="Task B", tool_id="tool_b", dependencies=["Task A"]),
    ]
    dag = ScanDAG(tasks=custom_tasks)
    order = dag.get_execution_order()
    order_keys = [t.key for t in order]
    assert order_keys == ["task_a", "task_b", "task_c"]


def test_scan_models_collector_result_properties():
    """Verify CollectorResult properties and serialization."""
    cr = CollectorResult(
        tool_id="sql_injection",
        task_title="Fuzz SQL Injection",
        status=CollectorStatus.COMPLETED,
        evidence_count=3,
        duration_ms=250.5,
        error=None,
        start_time="2026-09-01T12:00:00Z",
        end_time="2026-09-01T12:00:00.25Z",
    )
    assert cr.name == "Fuzz SQL Injection"
    assert cr.duration_seconds == pytest.approx(0.2505, rel=1e-3)
    d = cr.to_dict()
    assert d["tool_id"] == "sql_injection"
    assert d["status"] == "COMPLETED"
    assert d["evidence_count"] == 3


def test_scan_models_scan_result_properties_and_lookup():
    """Verify ScanResult helper methods and serialization."""
    cr1 = CollectorResult(tool_id="subfinder", task_title="Discover Subdomains", status=CollectorStatus.COMPLETED)
    cr2 = CollectorResult(tool_id="httpx", task_title="Fingerprint Live Hosts", status=CollectorStatus.SKIPPED)
    sr = ScanResult(
        scan_id="scan-123",
        target="example.com",
        status="COMPLETED",
        start_time="2026-09-01T12:00:00Z",
        end_time="2026-09-01T12:01:00Z",
        duration_seconds=60.0,
        collectors_total=2,
        collectors_run=1,
        collectors_skipped=1,
        collectors_failed=0,
        total_evidence=5,
        vulnerabilities_by_severity={"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 0},
        collector_results=[cr1, cr2],
        state_transitions=[{"from": "CREATED", "to": "COMPLETED", "timestamp": "2026-09-01T12:00:00Z"}],
    )
    assert sr.get_collector_result("subfinder") == cr1
    assert sr.get_collector_result("Fingerprint Live Hosts") == cr2
    assert sr.get_collector_result("nonexistent") is None

    d = sr.to_dict()
    assert d["scan_id"] == "scan-123"
    assert d["collectors_total"] == 2
    assert len(d["collector_results"]) == 2


def test_scan_models_collector_status_enum():
    """Verify CollectorStatus enum members."""
    assert CollectorStatus.PENDING == "PENDING"
    assert CollectorStatus.RUNNING == "RUNNING"
    assert CollectorStatus.COMPLETED == "COMPLETED"
    assert CollectorStatus.FAILED == "FAILED"
    assert CollectorStatus.SKIPPED == "SKIPPED"


def test_scan_engine_lifecycle_transitions():
    """Verify mission progresses through correct state machine lifecycle with timestamps."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create minimal DAG
        tasks = [
            ScanTask(key="t1", title="Task 1", tool_id="t1", dependencies=[]),
        ]
        dag = ScanDAG(tasks=tasks)
        collectors = {"t1": DummyCollector(name="t1")}
        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: collectors.get(task.tool_id),
        )

        mission = Mission(target="test.local")
        assert mission.status == MissionState.CREATED

        result = engine.run(mission)

        assert mission.status == MissionState.COMPLETED
        assert result.status == "COMPLETED"

        # Check recorded transitions
        recorded_states = [t["to"] for t in mission.state_transitions]
        assert "READY" in recorded_states
        assert "RUNNING" in recorded_states
        assert "COLLECTING_EVIDENCE" in recorded_states
        assert "CORRELATING" in recorded_states
        assert "COMPLETED" in recorded_states

        for t in mission.state_transitions:
            assert "timestamp" in t
            assert "reason" in t


def test_scan_engine_mock_collectors_dispatch():
    """Verify all collectors in DAG are resolved and executed with accumulated mission state."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        ev1 = Evidence(title="Subdomain 1", category="subdomain", severity="info", value="sub.test.local")
        ev2 = Evidence(title="SQL Injection", category="sql_injection", severity="critical", value="id=1'")

        c1 = DummyCollector("subfinder", [ev1])
        c2 = DummyCollector("httpx", [])
        c3 = DummyCollector("sql_injection", [ev2])

        custom_tasks = [
            ScanTask(key="subfinder", title="Discover Subdomains", tool_id="subfinder", dependencies=[]),
            ScanTask(key="httpx", title="Fingerprint Live Hosts", tool_id="httpx", dependencies=["Discover Subdomains"]),
            ScanTask(key="sql_injection", title="Fuzz SQL Injection", tool_id="sql_injection", dependencies=["Fingerprint Live Hosts"]),
        ]
        dag = ScanDAG(tasks=custom_tasks)
        collectors = {"subfinder": c1, "httpx": c2, "sql_injection": c3}

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: collectors.get(task.tool_id),
        )

        mission = Mission(target="test.local")
        result = engine.run(mission)

        assert c1.invoked and c1.invoked_with is mission
        assert c2.invoked and c2.invoked_with is mission
        assert c3.invoked and c3.invoked_with is mission

        assert result.collectors_run == 3
        assert result.collectors_failed == 0
        assert result.collectors_skipped == 0
        assert result.total_evidence == 2
        assert result.vulnerabilities_by_severity["critical"] == 1


def test_scan_engine_evidence_aggregation_in_store():
    """Verify evidence returned by multiple collectors is accumulated in mission.evidence."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        ev_xss = Evidence(title="Reflected XSS", category="xss", severity="high", value="/search?q=<script>")
        ev_sqli = Evidence(title="Error-based SQLi", category="sql_injection", severity="critical", value="/item?id=1'")

        c_xss = DummyCollector("xss", [ev_xss])
        c_sqli = DummyCollector("sql_injection", [ev_sqli])

        custom_tasks = [
            ScanTask(key="xss", title="Fuzz XSS", tool_id="xss", dependencies=[]),
            ScanTask(key="sql_injection", title="Fuzz SQLi", tool_id="sql_injection", dependencies=[]),
        ]
        dag = ScanDAG(tasks=custom_tasks)
        collectors = {"xss": c_xss, "sql_injection": c_sqli}

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: collectors.get(task.tool_id),
        )

        mission = Mission(target="target.local")
        result = engine.run(mission)

        all_ev = mission.evidence.all()
        assert len(all_ev) == 2
        assert ev_xss in all_ev
        assert ev_sqli in all_ev
        assert result.total_evidence == 2


def test_scan_engine_attack_surface_graph_snapshot():
    """Verify mission.attack_surface_graph is populated and graph_summary reflects entities."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        ev_sub = Evidence(title="Subdomain", category="subdomain", severity="info", value="api.example.com", metadata={"hostname": "api.example.com"})
        ev_host = Evidence(title="Live Host", category="live_host", severity="info", value="http://api.example.com", metadata={"url": "http://api.example.com", "host": "api.example.com"})
        ev_vuln = Evidence(title="Path Traversal", category="path_traversal", severity="critical", value="/files?path=../../etc/passwd", metadata={"url": "http://api.example.com/files?path=../../etc/passwd", "host": "http://api.example.com"})

        c_recon = DummyCollector("recon", [ev_sub, ev_host])
        c_vuln = DummyCollector("path_traversal", [ev_vuln])

        custom_tasks = [
            ScanTask(key="recon", title="Recon", tool_id="recon", dependencies=[]),
            ScanTask(key="path_traversal", title="Path Traversal", tool_id="path_traversal", dependencies=["Recon"]),
        ]
        dag = ScanDAG(tasks=custom_tasks)
        collectors = {"recon": c_recon, "path_traversal": c_vuln}

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: collectors.get(task.tool_id),
        )

        mission = Mission(target="example.com")
        result = engine.run(mission)

        assert result.graph_summary["total_nodes"] > 0
        assert result.graph_summary["vulnerabilities"] >= 1
        assert len(mission.attack_surface_graph.nodes) > 0


def test_scan_engine_report_generation_integration():
    """Verify Markdown and JSON reports are generated and attached to ScanResult."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        ev_vuln = Evidence(
            title="SQL Injection in Login",
            category="sql_injection",
            severity="critical",
            value="http://app.local/login",
            metadata={"url": "http://app.local/login", "host": "http://app.local", "parameter": "username"},
        )
        c = DummyCollector("sql_injection", [ev_vuln])
        dag = ScanDAG(tasks=[ScanTask(key="sqli", title="SQLi", tool_id="sqli", dependencies=[])])

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: c,
        )

        mission = Mission(target="app.local")
        result = engine.run(mission)

        assert len(result.report_paths) >= 2
        md_reports = [p for p in result.report_paths if p.endswith(".md")]
        json_reports = [p for p in result.report_paths if p.endswith(".json")]
        assert len(md_reports) == 1
        assert len(json_reports) == 1

        for p in result.report_paths:
            assert os.path.exists(p)
            assert os.path.getsize(p) > 0

        # Check mission.reports
        assert set(result.report_paths).issubset(set(mission.reports))


def test_scan_engine_vulnerability_severity_counts():
    """Verify ScanResult.vulnerabilities_by_severity accurately counts by level."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        ev_crit = Evidence(title="C1", category="vulnerability", severity="critical", value="c1")
        ev_high = Evidence(title="H1", category="vulnerability", severity="high", value="h1")
        ev_med = Evidence(title="M1", category="vulnerability", severity="medium", value="m1")
        ev_low = Evidence(title="L1", category="vulnerability", severity="low", value="l1")
        ev_info = Evidence(title="I1", category="subdomain", severity="info", value="i1")

        c = DummyCollector("vuln_tester", [ev_crit, ev_high, ev_med, ev_low, ev_info])
        dag = ScanDAG(tasks=[ScanTask(key="vuln", title="Vuln", tool_id="vuln", dependencies=[])])

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: c,
        )

        mission = Mission(target="counts.local")
        result = engine.run(mission)

        assert result.vulnerabilities_by_severity["critical"] == 1
        assert result.vulnerabilities_by_severity["high"] == 1
        assert result.vulnerabilities_by_severity["medium"] == 1
        assert result.vulnerabilities_by_severity["low"] == 1
        assert result.vulnerabilities_by_severity["info"] == 1


def test_scan_engine_dynamic_collector_resolution():
    """Verify ScanEngine.resolve_collector correctly resolves actual collectors without factory."""
    engine = ScanEngine()
    task_subfinder = ScanTask(key="subfinder", title="Discover Subdomains", tool_id="subfinder")
    collector = engine.resolve_collector(task_subfinder)
    assert collector is not None
    assert hasattr(collector, "collect")

    task_xss = ScanTask(key="xss", title="Fuzz XSS", tool_id="xss")
    collector_xss = engine.resolve_collector(task_xss)
    assert collector_xss is not None
    assert hasattr(collector_xss, "collect")


def test_scan_engine_tool_registry_aliases():
    """Verify ToolRegistry aliases map to the expected tools in ScanEngine."""
    engine = ScanEngine()
    task_sqli = ScanTask(key="sqli", title="SQL Injection", tool_id="sqli")
    collector = engine.resolve_collector(task_sqli)
    assert collector is not None
    assert hasattr(collector, "collect")


def test_models_reexport_in_argus_models():
    """Verify ScanResult, CollectorResult, CollectorStatus, MissionStatus in argus.models."""
    assert ModelsScanResult is ScanResult
    assert ModelsCollectorResult is CollectorResult
    assert ModelsCollectorStatus is CollectorStatus
    assert MissionStatus is MissionState


def test_scan_engine_full_21_tasks_simulated_execution():
    """Verify ScanEngine runs all 24 tasks from default ScanDAG end-to-end."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        dag = ScanDAG()
        assert len(dag.tasks) == 26

        # Factory providing dummy collector that populates evidence and state appropriately
        def collector_provider(task):
            if task.key == "subfinder":
                ev = Evidence(title="Found sub.test.com", category="subdomain", severity="info", value="sub.test.com")
                c = DummyCollector(task.key, [ev])
                # Also populate mission subdomains
                original_collect = c.collect
                def custom_collect(m):
                    m.subdomains.append("sub.test.com")
                    return original_collect(m)
                c.collect = custom_collect
                return c
            elif task.key == "httpx":
                ev = Evidence(title="Live host https://sub.test.com", category="live_host", severity="info", value="https://sub.test.com")
                c = DummyCollector(task.key, [ev])
                original_collect = c.collect
                def custom_collect(m):
                    m.live_hosts.append({"url": "https://sub.test.com", "host": "sub.test.com"})
                    return original_collect(m)
                c.collect = custom_collect
                return c
            elif task.key == "katana_crawler":
                ev = Evidence(title="Discovered /api/v1/user", category="endpoint", severity="info", value="https://sub.test.com/api/v1/user")
                c = DummyCollector(task.key, [ev])
                original_collect = c.collect
                def custom_collect(m):
                    m.endpoints.append({"url": "https://sub.test.com/api/v1/user", "host": "sub.test.com"})
                    return original_collect(m)
                c.collect = custom_collect
                return c
            else:
                ev = Evidence(title=f"Finding from {task.key}", category="vulnerability", severity="high", value=f"vuln-{task.key}")
                return DummyCollector(task.key, [ev])

        engine = ScanEngine(dag=dag, output_dir=tmp_dir, collector_factory=collector_provider)
        mission = Mission(target="test.com")

        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert result.collectors_total == 26
        assert result.collectors_run == 26
        assert result.collectors_failed == 0
        assert result.collectors_skipped == 0
        assert len(result.collector_results) == 26
        assert result.total_evidence == 26
        assert len(result.report_paths) >= 2


def test_scan_engine_state_machine_starting_in_ready_and_running():
    """Verify ScanEngine handles missions that start already in READY or RUNNING or PLANNING state."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        dag = ScanDAG(tasks=[ScanTask(key="t1", title="T1", tool_id="t1", dependencies=[])])
        engine = ScanEngine(dag=dag, output_dir=tmp_dir, collector_factory=lambda task: DummyCollector())

        mission_ready = Mission(target="ready.local", status=MissionState.READY)
        res1 = engine.run(mission_ready)
        assert res1.status == "COMPLETED"
        assert mission_ready.status == MissionState.COMPLETED

        mission_running = Mission(target="running.local", status=MissionState.RUNNING)
        res2 = engine.run(mission_running)
        assert res2.status == "COMPLETED"
        assert mission_running.status == MissionState.COMPLETED


def test_scan_dag_task_invariants_and_serialization():
    """Verify ScanTask serialization and dictionary representation."""
    task = ScanTask(
        key="xss_fuzzer",
        title="Fuzz Cross-Site Scripting",
        tool_id="xss",
        dependencies=["Discover Endpoints"],
        category="EVIDENCE_CORRELATION",
        phase="vulnerability",
        priority=0.85,
        goal="Detect XSS flaws",
        required_inputs=["endpoints"],
        expected_outputs=["vulnerabilities"],
        metadata={"timeout": 30},
    )
    d = task.to_dict()
    assert d["key"] == "xss_fuzzer"
    assert d["tool_id"] == "xss"
    assert d["dependencies"] == ["Discover Endpoints"]
    assert d["priority"] == 0.85
    assert d["required_inputs"] == ["endpoints"]
    assert d["metadata"]["timeout"] == 30


def test_scan_engine_custom_tool_registry():
    """Verify ScanEngine can use a custom ToolRegistry."""
    from argus.runtime.registry import ToolRegistry
    from argus.runtime.models import Tool

    custom_reg = ToolRegistry()
    custom_reg.register(Tool(id="custom_sqli", name="Custom SQLi Prober", category="vulnerability", command="custom_sqli"))

    engine = ScanEngine(tool_registry=custom_reg)
    assert engine.registry.get("custom_sqli") is not None

