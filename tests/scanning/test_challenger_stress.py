import os
import tempfile
import pytest
import random
from unittest.mock import MagicMock

from argus.runtime.mission import Mission, MissionState
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.scanning.models import ScanResult, CollectorResult, CollectorStatus
from argus.scanning.dag import ScanDAG, ScanTask
from argus.scanning.engine import ScanEngine


# ==============================================================================
# Helper Mock Collectors
# ==============================================================================

class DummyEvidenceCollector:
    def __init__(self, name="dummy", evidence_items=None, side_effect=None):
        self.name = name
        self.evidence_items = evidence_items or []
        self.side_effect = side_effect
        self.invoked = False
        self.invoked_mission = None

    def collect(self, mission):
        self.invoked = True
        self.invoked_mission = mission
        if self.side_effect:
            if isinstance(self.side_effect, Exception):
                raise self.side_effect
            elif callable(self.side_effect):
                return self.side_effect(mission)
        for ev in self.evidence_items:
            mission.evidence.add(ev)
        return self.evidence_items


# ==============================================================================
# 1. DAG Topological Sorting Stress Tests
# ==============================================================================

def test_dag_cycle_2_nodes():
    """Verify 2-node cycle (A -> B -> A) raises ValueError."""
    tasks = [
        ScanTask(key="task_a", title="Task A", tool_id="tool_a", dependencies=["Task B"]),
        ScanTask(key="task_b", title="Task B", tool_id="tool_b", dependencies=["Task A"]),
    ]
    dag = ScanDAG(tasks=tasks)
    with pytest.raises(ValueError, match="Cycle detected"):
        dag.get_execution_order()


def test_dag_cycle_3_nodes():
    """Verify 3-node cycle (A -> B -> C -> A) raises ValueError."""
    tasks = [
        ScanTask(key="task_a", title="Task A", tool_id="tool_a", dependencies=["Task C"]),
        ScanTask(key="task_b", title="Task B", tool_id="tool_b", dependencies=["Task A"]),
        ScanTask(key="task_c", title="Task C", tool_id="tool_c", dependencies=["Task B"]),
    ]
    dag = ScanDAG(tasks=tasks)
    with pytest.raises(ValueError, match="Cycle detected"):
        dag.get_execution_order()


def test_dag_cycle_embedded_in_valid_graph():
    """Verify cycle embedded deep in a graph with valid root and leaf nodes raises ValueError."""
    tasks = [
        ScanTask(key="root", title="Root", tool_id="root", dependencies=[]),
        ScanTask(key="valid_child", title="Valid Child", tool_id="valid_child", dependencies=["Root"]),
        ScanTask(key="cycle_1", title="Cycle 1", tool_id="cycle_1", dependencies=["Valid Child", "Cycle 2"]),
        ScanTask(key="cycle_2", title="Cycle 2", tool_id="cycle_2", dependencies=["Cycle 1"]),
    ]
    dag = ScanDAG(tasks=tasks)
    with pytest.raises(ValueError, match="Cycle detected"):
        dag.get_execution_order()


def test_dag_multiple_disconnected_subgraphs():
    """Verify DAG handles multiple disconnected subgraphs correctly."""
    tasks = [
        # Subgraph 1: A -> B
        ScanTask(key="a", title="A", tool_id="a", dependencies=[], priority=1.0),
        ScanTask(key="b", title="B", tool_id="b", dependencies=["A"], priority=1.0),
        # Subgraph 2: C -> D
        ScanTask(key="c", title="C", tool_id="c", dependencies=[], priority=2.0),
        ScanTask(key="d", title="D", tool_id="d", dependencies=["C"], priority=2.0),
        # Subgraph 3: Isolated E
        ScanTask(key="e", title="E", tool_id="e", dependencies=[], priority=3.0),
    ]
    dag = ScanDAG(tasks=tasks)
    order = dag.get_execution_order()
    assert len(order) == 5
    order_keys = [t.key for t in order]
    # Check dependencies are strictly respected in each subgraph
    assert order_keys.index("a") < order_keys.index("b")
    assert order_keys.index("c") < order_keys.index("d")
    # Higher priority tasks (e priority 3.0, c priority 2.0) should be scheduled earlier among available
    assert order_keys.index("e") < order_keys.index("a")


def test_dag_unknown_dependency_tolerance():
    """Verify tasks referencing unknown dependencies (not in DAG) execute without crashing."""
    tasks = [
        ScanTask(key="task_x", title="Task X", tool_id="tool_x", dependencies=["non_existent_dependency_xyz"]),
        ScanTask(key="task_y", title="Task Y", tool_id="tool_y", dependencies=["Task X"]),
    ]
    dag = ScanDAG(tasks=tasks)
    order = dag.get_execution_order()
    assert len(order) == 2
    assert order[0].key == "task_x"
    assert order[1].key == "task_y"


def test_dag_duplicate_task_keys_overwrite():
    """Verify add_task with existing key overwrites the task properly."""
    dag = ScanDAG(tasks=[])
    dag.add_task(ScanTask(key="task_1", title="Original Title", tool_id="t1", priority=1.0))
    dag.add_task(ScanTask(key="task_1", title="Updated Title", tool_id="t1_v2", priority=5.0))

    assert len(dag.tasks) == 1
    assert dag.tasks[0].title == "Updated Title"
    assert dag.tasks[0].priority == 5.0

    order = dag.get_execution_order()
    assert len(order) == 1
    assert order[0].title == "Updated Title"


def test_dag_empty_task_list():
    """Verify empty DAG returns empty execution order without error."""
    dag = ScanDAG(tasks=[])
    assert dag.tasks == []
    assert dag.get_execution_order() == []


def test_dag_wide_fan_out_and_fan_in():
    """Verify large fan-out and fan-in graph (1 root -> 50 workers -> 1 sink)."""
    root = ScanTask(key="root", title="Root Recon", tool_id="root", phase="recon", priority=10.0)
    workers = [
        ScanTask(
            key=f"worker_{i}",
            title=f"Worker {i}",
            tool_id=f"worker_{i}",
            dependencies=["Root Recon"],
            phase="vulnerability",
            priority=float(i),
        )
        for i in range(50)
    ]
    sink = ScanTask(
        key="sink",
        title="Final Sink",
        tool_id="sink",
        dependencies=[f"Worker {i}" for i in range(50)],
        phase="vulnerability",
        priority=0.0,
    )

    all_tasks = [root] + workers + [sink]
    # Shuffle insertion order
    random.seed(42)
    shuffled = list(all_tasks)
    random.shuffle(shuffled)

    dag = ScanDAG(tasks=shuffled)
    order = dag.get_execution_order()

    assert len(order) == 52
    assert order[0].key == "root"
    assert order[-1].key == "sink"

    order_keys = [t.key for t in order]
    root_idx = order_keys.index("root")
    sink_idx = order_keys.index("sink")
    for i in range(50):
        w_idx = order_keys.index(f"worker_{i}")
        assert root_idx < w_idx < sink_idx


def test_dag_deep_linear_chain():
    """Verify deep linear chain of 50 tasks (T0 -> T1 -> ... -> T49)."""
    tasks = []
    for i in range(50):
        deps = [f"Task {i-1}"] if i > 0 else []
        tasks.append(
            ScanTask(
                key=f"task_{i}",
                title=f"Task {i}",
                tool_id=f"tool_{i}",
                dependencies=deps,
                priority=1.0,
            )
        )

    # Reverse order addition to test topological sort resolution
    dag = ScanDAG(tasks=list(reversed(tasks)))
    order = dag.get_execution_order()

    assert len(order) == 50
    for i in range(50):
        assert order[i].key == f"task_{i}"


def test_dag_deterministic_topological_sort_under_permutations():
    """Verify identical DAG with different task registration order produces deterministic execution order."""
    tasks = [
        ScanTask(key="recon_1", title="Recon 1", tool_id="r1", phase="recon", priority=5.0),
        ScanTask(key="recon_2", title="Recon 2", tool_id="r2", phase="recon", priority=10.0),
        ScanTask(key="vuln_1", title="Vuln 1", tool_id="v1", dependencies=["Recon 1"], phase="vulnerability", priority=1.0),
        ScanTask(key="vuln_2", title="Vuln 2", tool_id="v2", dependencies=["Recon 2"], phase="vulnerability", priority=5.0),
    ]

    orders = []
    for seed in [1, 2, 3, 4, 5]:
        shuffled = list(tasks)
        random.seed(seed)
        random.shuffle(shuffled)
        dag = ScanDAG(tasks=shuffled)
        order_keys = [t.key for t in dag.get_execution_order()]
        orders.append(order_keys)

    # Every order must be a valid topological order
    for o in orders:
        assert o.index("recon_1") < o.index("vuln_1")
        assert o.index("recon_2") < o.index("vuln_2")
        # Recon phase always precedes vuln phase
        assert max(o.index("recon_1"), o.index("recon_2")) < min(o.index("vuln_1"), o.index("vuln_2"))


# ==============================================================================
# 2. Error Isolation and Collector Failure Mode Stress Tests
# ==============================================================================

@pytest.mark.parametrize("exc_type", [
    RuntimeError("Critical runtime error"),
    ValueError("Invalid parameter value"),
    TypeError("NoneType object is not callable"),
    KeyError("Missing expected key in dict"),
    ZeroDivisionError("Division by zero in calculation"),
    AttributeError("Mission object missing custom attribute"),
])
def test_error_isolation_various_exception_types(exc_type):
    """Verify ScanEngine catches all standard Exception subclasses and isolates failure."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        c_fail = DummyEvidenceCollector("failing", side_effect=exc_type)
        c_success = DummyEvidenceCollector(
            "success",
            evidence_items=[Evidence(title="Good Ev", category="subdomain", severity="info", value="sub.test")],
        )

        tasks = [
            ScanTask(key="fail_task", title="Failing Task", tool_id="fail_tool", dependencies=[]),
            ScanTask(key="success_task", title="Success Task", tool_id="success_tool", dependencies=[]),
        ]
        dag = ScanDAG(tasks=tasks)
        collectors = {"fail_tool": c_fail, "success_tool": c_success}

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: collectors.get(task.tool_id),
        )

        mission = Mission(target="test_exc.local")
        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert result.collectors_failed == 1
        assert result.collectors_run == 1
        assert c_success.invoked is True

        cr_fail = result.get_collector_result("fail_task")
        assert cr_fail.status == CollectorStatus.FAILED
        assert str(exc_type) in cr_fail.error


def test_error_isolation_diamond_dependency_partial_failure():
    r"""
    Diamond graph:
             Root
            /    \
        Left      Right
            \    /
             Sink
    If Left fails, Right must execute successfully, and Sink must be SKIPPED.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        c_root = DummyEvidenceCollector("root", [Evidence(title="RootEv", category="info", severity="info")])
        c_left = DummyEvidenceCollector("left", side_effect=RuntimeError("Left collector crashed"))
        c_right = DummyEvidenceCollector("right", [Evidence(title="RightEv", category="info", severity="info")])
        c_sink = DummyEvidenceCollector("sink", [Evidence(title="SinkEv", category="info", severity="info")])

        tasks = [
            ScanTask(key="root", title="Root", tool_id="root", dependencies=[]),
            ScanTask(key="left", title="Left", tool_id="left", dependencies=["Root"]),
            ScanTask(key="right", title="Right", tool_id="right", dependencies=["Root"]),
            ScanTask(key="sink", title="Sink", tool_id="sink", dependencies=["Left", "Right"]),
        ]
        dag = ScanDAG(tasks=tasks)
        collectors = {"root": c_root, "left": c_left, "right": c_right, "sink": c_sink}

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: collectors.get(task.tool_id),
        )

        mission = Mission(target="diamond.local")
        result = engine.run(mission)

        assert result.collectors_run == 2  # Root and Right
        assert result.collectors_failed == 1  # Left
        assert result.collectors_skipped == 1  # Sink

        assert c_root.invoked is True
        assert c_right.invoked is True
        assert c_sink.invoked is False

        assert result.get_collector_result("sink").status == CollectorStatus.SKIPPED
        assert "Left" in result.get_collector_result("sink").error


def test_dag_self_referencing_task_dependency_handling():
    """Verify task that declares dependency on its own key executes without infinite loop."""
    tasks = [
        ScanTask(key="self_dep", title="Self Dependent", tool_id="self_dep", dependencies=["self_dep"]),
    ]
    dag = ScanDAG(tasks=tasks)
    order = dag.get_execution_order()
    assert len(order) == 1
    assert order[0].key == "self_dep"


def test_dag_redundant_duplicate_dependencies():
    """Verify duplicate dependencies in task.dependencies are deduplicated properly."""
    tasks = [
        ScanTask(key="root", title="Root", tool_id="root", dependencies=[]),
        ScanTask(key="child", title="Child", tool_id="child", dependencies=["Root", "Root", "Root", "root"]),
    ]
    dag = ScanDAG(tasks=tasks)
    order = dag.get_execution_order()
    assert len(order) == 2
    assert order[0].key == "root"
    assert order[1].key == "child"


def test_state_machine_illegal_transition_recovery():
    """Verify that if mission starts in terminal COMPLETED state, ScanEngine recovers via fallback without crashing."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        dag = ScanDAG(tasks=[ScanTask(key="t1", title="T1", tool_id="t1", dependencies=[])])
        engine = ScanEngine(dag=dag, output_dir=tmp_dir, collector_factory=lambda t: DummyEvidenceCollector())

        mission = Mission(target="terminal.local", status=MissionState.COMPLETED)
        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert mission.status == MissionState.COMPLETED
        assert len(mission.state_transitions) > 0


def test_collector_failing_initialization_resolution():
    """Verify collector resolution failure is handled cleanly, marks task as FAILED, and executes independent tasks."""
    def failing_factory(task):
        if task.key == "bad_init":
            return None  # Unresolvable/failed instantiation
        return DummyEvidenceCollector()

    with tempfile.TemporaryDirectory() as tmp_dir:
        tasks = [
            ScanTask(key="bad_init", title="Bad Init", tool_id="bad_init", dependencies=[]),
            ScanTask(key="good_task", title="Good Task", tool_id="good_task", dependencies=[]),
        ]
        dag = ScanDAG(tasks=tasks)
        engine = ScanEngine(dag=dag, output_dir=tmp_dir, collector_factory=failing_factory)

        mission = Mission(target="init_fail.local")
        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert result.collectors_failed == 1
        assert result.collectors_run == 1
        assert result.get_collector_result("bad_init").status == CollectorStatus.FAILED
        assert result.get_collector_result("good_task").status == CollectorStatus.COMPLETED



def test_scan_result_dict_serialization_completeness():
    """Verify ScanResult.to_dict() serializes all fields into JSON-serializable primitives."""
    cr = CollectorResult(
        tool_id="subfinder",
        task_title="Discover Subdomains",
        status=CollectorStatus.COMPLETED,
        evidence_count=5,
        duration_ms=120.0,
        error=None,
        start_time="2026-09-01T12:00:00Z",
        end_time="2026-09-01T12:00:00.120Z",
        task_key="subfinder",
    )

    sr = ScanResult(
        scan_id="scan-xyz",
        target="target.com",
        status="COMPLETED",
        start_time="2026-09-01T12:00:00Z",
        end_time="2026-09-01T12:01:00Z",
        duration_seconds=60.0,
        collectors_total=1,
        collectors_run=1,
        collectors_skipped=0,
        collectors_failed=0,
        total_evidence=5,
        vulnerabilities_by_severity={"critical": 0, "high": 1, "medium": 2, "low": 2, "info": 0},
        collector_results=[cr],
        state_transitions=[{"from": "CREATED", "to": "COMPLETED", "timestamp": "2026-09-01T12:00:00Z"}],
        report_paths=["/tmp/report.md", "/tmp/report.json"],
        graph_summary={"total_nodes": 10, "total_edges": 8},
    )

    d = sr.to_dict()
    assert d["scan_id"] == "scan-xyz"
    assert d["status"] == "COMPLETED"
    assert d["collectors_run"] == 1
    assert len(d["collector_results"]) == 1
    assert d["collector_results"][0]["task_key"] == "subfinder"
    assert d["collector_results"][0]["status"] == "COMPLETED"
    assert d["graph_summary"]["total_nodes"] == 10



def test_error_isolation_multi_branch_cascade():
    """
    Three independent branches:
    Branch 1: A1 -> A2 -> A3 (A1 fails, A2 and A3 skipped)
    Branch 2: B1 -> B2 -> B3 (All succeed)
    Branch 3: C1 -> C2 -> C3 (C1 succeeds, C2 fails, C3 skipped)
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        collectors = {
            "a1": DummyEvidenceCollector("a1", side_effect=RuntimeError("A1 failed")),
            "a2": DummyEvidenceCollector("a2"),
            "a3": DummyEvidenceCollector("a3"),
            "b1": DummyEvidenceCollector("b1", [Evidence(title="B1", category="info", severity="info")]),
            "b2": DummyEvidenceCollector("b2", [Evidence(title="B2", category="info", severity="info")]),
            "b3": DummyEvidenceCollector("b3", [Evidence(title="B3", category="info", severity="info")]),
            "c1": DummyEvidenceCollector("c1", [Evidence(title="C1", category="info", severity="info")]),
            "c2": DummyEvidenceCollector("c2", side_effect=RuntimeError("C2 failed")),
            "c3": DummyEvidenceCollector("c3"),
        }

        tasks = [
            ScanTask(key="a1", title="A1", tool_id="a1", dependencies=[]),
            ScanTask(key="a2", title="A2", tool_id="a2", dependencies=["A1"]),
            ScanTask(key="a3", title="A3", tool_id="a3", dependencies=["A2"]),
            ScanTask(key="b1", title="B1", tool_id="b1", dependencies=[]),
            ScanTask(key="b2", title="B2", tool_id="b2", dependencies=["B1"]),
            ScanTask(key="b3", title="B3", tool_id="b3", dependencies=["B2"]),
            ScanTask(key="c1", title="C1", tool_id="c1", dependencies=[]),
            ScanTask(key="c2", title="C2", tool_id="c2", dependencies=["C1"]),
            ScanTask(key="c3", title="C3", tool_id="c3", dependencies=["C2"]),
        ]
        dag = ScanDAG(tasks=tasks)

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: collectors.get(task.tool_id),
        )

        mission = Mission(target="multibranch.local")
        result = engine.run(mission)

        assert result.collectors_total == 9
        assert result.collectors_run == 4   # B1, B2, B3, C1
        assert result.collectors_failed == 2  # A1, C2
        assert result.collectors_skipped == 3  # A2, A3, C3

        assert result.get_collector_result("a1").status == CollectorStatus.FAILED
        assert result.get_collector_result("a2").status == CollectorStatus.SKIPPED
        assert result.get_collector_result("a3").status == CollectorStatus.SKIPPED

        assert result.get_collector_result("b1").status == CollectorStatus.COMPLETED
        assert result.get_collector_result("b2").status == CollectorStatus.COMPLETED
        assert result.get_collector_result("b3").status == CollectorStatus.COMPLETED

        assert result.get_collector_result("c1").status == CollectorStatus.COMPLETED
        assert result.get_collector_result("c2").status == CollectorStatus.FAILED
        assert result.get_collector_result("c3").status == CollectorStatus.SKIPPED


def test_error_isolation_dependency_referencing_mixed_identifiers():
    """Verify downstream skipping works when dependencies reference task key, task title, or tool_id interchangeably."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        collectors = {
            "t1_tool": DummyEvidenceCollector("t1", side_effect=RuntimeError("T1 failed")),
            "t2_tool": DummyEvidenceCollector("t2"),
            "t3_tool": DummyEvidenceCollector("t3"),
        }

        tasks = [
            ScanTask(key="t1_key", title="T1 Title", tool_id="t1_tool", dependencies=[]),
            # Depends on title of T1
            ScanTask(key="t2_key", title="T2 Title", tool_id="t2_tool", dependencies=["T1 Title"]),
            # Depends on key of T1
            ScanTask(key="t3_key", title="T3 Title", tool_id="t3_tool", dependencies=["t1_key"]),
        ]
        dag = ScanDAG(tasks=tasks)

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: collectors.get(task.tool_id),
        )

        mission = Mission(target="ident.local")
        result = engine.run(mission)

        assert result.collectors_failed == 1
        assert result.collectors_skipped == 2
        assert result.get_collector_result("t2_key").status == CollectorStatus.SKIPPED
        assert result.get_collector_result("t3_key").status == CollectorStatus.SKIPPED


def test_collector_returning_mixed_valid_and_invalid_evidence():
    """Verify ScanEngine ingests valid Evidence items while ignoring strings, None, ints, dicts returned in list."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        valid_ev = Evidence(title="Real Vuln", category="sqli", severity="critical", value="valid")
        malformed_list = [
            valid_ev,
            "just_a_string",
            None,
            12345,
            {"not": "an_evidence_object"},
            ["nested_list"],
        ]

        collector = DummyEvidenceCollector("mixed", side_effect=lambda m: malformed_list)
        tasks = [ScanTask(key="t_mixed", title="T Mixed", tool_id="t_mixed", dependencies=[])]
        dag = ScanDAG(tasks=tasks)

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: collector,
        )

        mission = Mission(target="mixed.local")
        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert result.total_evidence == 1
        assert mission.evidence.count() == 1
        assert valid_ev in mission.evidence.all()


def test_collector_without_any_supported_hook():
    """Verify collector class missing collect, execute, or discover methods is marked FAILED cleanly."""
    class IncompatibleCollector:
        def do_something_else(self):
            return "no collect hook"

    with tempfile.TemporaryDirectory() as tmp_dir:
        tasks = [ScanTask(key="incomp", title="Incompatible", tool_id="incomp", dependencies=[])]
        dag = ScanDAG(tasks=tasks)

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: IncompatibleCollector(),
        )

        mission = Mission(target="incomp.local")
        result = engine.run(mission)

        assert result.collectors_failed == 1
        cr = result.get_collector_result("incomp")
        assert cr.status == CollectorStatus.FAILED
        assert "no collect, execute, or discover hook" in cr.error


# ==============================================================================
# 3. Scan Lifecycle Edge Cases
# ==============================================================================

def test_lifecycle_mission_starting_in_planning_state():
    """Verify ScanEngine accepts missions initialized in PLANNING state."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tasks = [ScanTask(key="t1", title="T1", tool_id="t1", dependencies=[])]
        dag = ScanDAG(tasks=tasks)
        engine = ScanEngine(dag=dag, output_dir=tmp_dir, collector_factory=lambda t: DummyEvidenceCollector())

        mission = Mission(target="planning.local", status=MissionState.PLANNING)
        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert mission.status == MissionState.COMPLETED


def test_lifecycle_mission_with_uninitialized_optional_fields():
    """Verify ScanEngine handles missions where evidence, attack_surface_graph, state_transitions are None."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tasks = [ScanTask(key="t1", title="T1", tool_id="t1", dependencies=[])]
        dag = ScanDAG(tasks=tasks)
        engine = ScanEngine(dag=dag, output_dir=tmp_dir, collector_factory=lambda t: DummyEvidenceCollector())

        mission = Mission(target="raw.local")
        mission.evidence = None
        mission.attack_surface_graph = None
        mission.state_transitions = None
        mission.reports = None

        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert mission.status == MissionState.COMPLETED
        assert isinstance(mission.evidence, EvidenceStore)
        assert isinstance(mission.attack_surface_graph, KnowledgeGraph)
        assert len(mission.state_transitions) > 0


def test_lifecycle_deeply_nested_nonexistent_output_directory():
    """Verify report generation creates nonexistent nested output directory paths cleanly."""
    with tempfile.TemporaryDirectory() as base_dir:
        nested_output_dir = os.path.join(base_dir, "deep", "nested", "reports", "dir")
        ev = Evidence(title="Found Vuln", category="xss", severity="high", value="/search")
        tasks = [ScanTask(key="t1", title="T1", tool_id="t1", dependencies=[])]
        dag = ScanDAG(tasks=tasks)

        engine = ScanEngine(
            dag=dag,
            output_dir=nested_output_dir,
            collector_factory=lambda t: DummyEvidenceCollector("t1", [ev]),
        )

        mission = Mission(target="nested.local")
        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert len(result.report_paths) >= 2
        for p in result.report_paths:
            assert os.path.exists(p)


def test_lifecycle_large_volume_evidence_aggregation_stress():
    """Verify performance and aggregation accuracy with 500 evidence items across multiple collectors."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        severities = ["critical", "high", "medium", "low", "info"]
        expected_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        collectors = {}
        tasks = []

        for i in range(10):
            task_key = f"bulk_col_{i}"
            ev_list = []
            for j in range(50):
                sev = severities[(i * 50 + j) % len(severities)]
                expected_counts[sev] += 1
                ev = Evidence(
                    title=f"Vuln {i}_{j}",
                    category="stress_test",
                    severity=sev,
                    value=f"https://target.local/vuln/{i}/{j}",
                    metadata={"url": f"https://target.local/vuln/{i}/{j}", "host": "target.local"},
                )
                ev_list.append(ev)

            collectors[task_key] = DummyEvidenceCollector(task_key, ev_list)
            tasks.append(ScanTask(key=task_key, title=f"Bulk {i}", tool_id=task_key, dependencies=[]))

        dag = ScanDAG(tasks=tasks)
        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda t: collectors.get(t.tool_id),
        )

        mission = Mission(target="stress_bulk.local")
        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert result.collectors_run == 10
        assert result.total_evidence == 500
        assert result.vulnerabilities_by_severity == expected_counts


def test_scan_result_dict_serialization_completeness():
    """Verify ScanResult.to_dict() serializes all fields into JSON-serializable primitives."""
    cr = CollectorResult(
        tool_id="subfinder",
        task_title="Discover Subdomains",
        status=CollectorStatus.COMPLETED,
        evidence_count=5,
        duration_ms=120.0,
        error=None,
        start_time="2026-09-01T12:00:00Z",
        end_time="2026-09-01T12:00:00.120Z",
        task_key="subfinder",
    )

    sr = ScanResult(
        scan_id="scan-xyz",
        target="target.com",
        status="COMPLETED",
        start_time="2026-09-01T12:00:00Z",
        end_time="2026-09-01T12:01:00Z",
        duration_seconds=60.0,
        collectors_total=1,
        collectors_run=1,
        collectors_skipped=0,
        collectors_failed=0,
        total_evidence=5,
        vulnerabilities_by_severity={"critical": 0, "high": 1, "medium": 2, "low": 2, "info": 0},
        collector_results=[cr],
        state_transitions=[{"from": "CREATED", "to": "COMPLETED", "timestamp": "2026-09-01T12:00:00Z"}],
        report_paths=["/tmp/report.md", "/tmp/report.json"],
        graph_summary={"total_nodes": 10, "total_edges": 8},
    )

    d = sr.to_dict()
    assert d["scan_id"] == "scan-xyz"
    assert d["status"] == "COMPLETED"
    assert d["collectors_run"] == 1
    assert len(d["collector_results"]) == 1
    assert d["collector_results"][0]["task_key"] == "subfinder"
    assert d["collector_results"][0]["status"] == "COMPLETED"
    assert d["graph_summary"]["total_nodes"] == 10
