import os
import tempfile
import pytest
from unittest.mock import MagicMock, patch

from argus.runtime.mission import Mission, MissionState
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.scanning.models import ScanResult, CollectorResult, CollectorStatus
from argus.scanning.dag import ScanDAG, ScanTask
from argus.scanning.engine import ScanEngine


class FailingCollector:
    def __init__(self, error_message="Simulated collector crash"):
        self.error_message = error_message

    def collect(self, mission):
        raise RuntimeError(self.error_message)


class SuccessCollector:
    def __init__(self, evidence_items=None):
        self.evidence_items = evidence_items or []
        self.invoked = False

    def collect(self, mission):
        self.invoked = True
        for ev in self.evidence_items:
            mission.evidence.add(ev)
        return self.evidence_items


def test_collector_exception_isolation():
    """Verify that when one collector raises an exception, independent collectors proceed."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        c_fail = FailingCollector("Exploded during port scanning")
        c_success = SuccessCollector([Evidence(title="E1", category="subdomain", severity="info", value="s1.test")])

        # DAG: task_fail and task_success are independent (no dependencies)
        tasks = [
            ScanTask(key="task_fail", title="Task Fail", tool_id="tool_fail", dependencies=[]),
            ScanTask(key="task_success", title="Task Success", tool_id="tool_success", dependencies=[]),
        ]
        dag = ScanDAG(tasks=tasks)
        collectors = {"tool_fail": c_fail, "tool_success": c_success}

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: collectors.get(task.tool_id),
        )

        mission = Mission(target="isolate.local")
        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert result.collectors_total == 2
        assert result.collectors_run == 1
        assert result.collectors_failed == 1
        assert result.collectors_skipped == 0
        assert c_success.invoked is True

        cr_fail = result.get_collector_result("tool_fail")
        assert cr_fail is not None
        assert cr_fail.status == CollectorStatus.FAILED
        assert "Exploded during port scanning" in cr_fail.error


def test_downstream_dependency_skipping():
    """Verify that downstream tasks depending on a failed task are marked SKIPPED."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        c_root = FailingCollector("Root discovery failed")
        c_child = SuccessCollector()
        c_independent = SuccessCollector([Evidence(title="Indep", category="info", severity="low")])

        tasks = [
            ScanTask(key="root", title="Root Recon", tool_id="root", dependencies=[]),
            ScanTask(key="child", title="Child Vuln", tool_id="child", dependencies=["Root Recon"]),
            ScanTask(key="independent", title="Independent Task", tool_id="independent", dependencies=[]),
        ]
        dag = ScanDAG(tasks=tasks)
        collectors = {"root": c_root, "child": c_child, "independent": c_independent}

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: collectors.get(task.tool_id),
        )

        mission = Mission(target="skip.local")
        result = engine.run(mission)

        assert result.collectors_failed == 1
        assert result.collectors_skipped == 1
        assert result.collectors_run == 1

        cr_child = result.get_collector_result("Child Vuln")
        assert cr_child is not None
        assert cr_child.status == CollectorStatus.SKIPPED
        assert "Root Recon" in cr_child.error

        assert c_child.invoked is False
        assert c_independent.invoked is True


def test_cascade_dependency_skipping():
    """Verify multi-level cascade skipping when root fails (A -> B -> C)."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tasks = [
            ScanTask(key="task_a", title="Task A", tool_id="tool_a", dependencies=[]),
            ScanTask(key="task_b", title="Task B", tool_id="tool_b", dependencies=["Task A"]),
            ScanTask(key="task_c", title="Task C", tool_id="tool_c", dependencies=["Task B"]),
        ]
        dag = ScanDAG(tasks=tasks)
        collectors = {"tool_a": FailingCollector("A failed")}

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: collectors.get(task.tool_id),
        )

        mission = Mission(target="cascade.local")
        result = engine.run(mission)

        assert result.collectors_failed == 1
        assert result.collectors_skipped == 2
        assert result.collectors_run == 0

        assert result.get_collector_result("task_b").status == CollectorStatus.SKIPPED
        assert result.get_collector_result("task_c").status == CollectorStatus.SKIPPED


def test_unresolvable_collector_handling():
    """Verify that unresolvable tool_id marks task as FAILED and skips downstream tasks."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tasks = [
            ScanTask(key="mystery", title="Mystery Tool", tool_id="non_existent_tool_xyz", dependencies=[]),
            ScanTask(key="downstream", title="Downstream", tool_id="downstream", dependencies=["Mystery Tool"]),
        ]
        dag = ScanDAG(tasks=tasks)

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: None,  # Unable to resolve
        )

        mission = Mission(target="unresolvable.local")
        result = engine.run(mission)

        assert result.collectors_failed == 1
        assert result.collectors_skipped == 1

        cr_mystery = result.get_collector_result("mystery")
        assert cr_mystery.status == CollectorStatus.FAILED
        assert "could not be resolved" in cr_mystery.error


def test_dag_cycle_detection():
    """Verify that ScanDAG raises ValueError when cyclic dependencies exist."""
    cyclic_tasks = [
        ScanTask(key="task_1", title="Task 1", tool_id="tool_1", dependencies=["Task 2"]),
        ScanTask(key="task_2", title="Task 2", tool_id="tool_2", dependencies=["Task 1"]),
    ]
    dag = ScanDAG(tasks=cyclic_tasks)
    with pytest.raises(ValueError, match="Cycle detected"):
        dag.get_execution_order()


def test_engine_handling_of_cyclic_dag():
    """Verify that ScanEngine handles cyclic DAG gracefully by failing mission and returning FAILED result."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cyclic_tasks = [
            ScanTask(key="task_x", title="Task X", tool_id="tool_x", dependencies=["Task Y"]),
            ScanTask(key="task_y", title="Task Y", tool_id="tool_y", dependencies=["Task X"]),
        ]
        dag = ScanDAG(tasks=cyclic_tasks)
        engine = ScanEngine(dag=dag, output_dir=tmp_dir)

        mission = Mission(target="cyclic.local")
        result = engine.run(mission)

        assert result.status == "FAILED"
        assert mission.status == MissionState.FAILED


def test_collector_returning_non_list_or_empty():
    """Verify engine handles collectors returning None, dict, or empty list without error."""
    class StrangeCollector:
        def __init__(self, return_val):
            self.return_val = return_val

        def collect(self, mission):
            return self.return_val

    with tempfile.TemporaryDirectory() as tmp_dir:
        tasks = [
            ScanTask(key="t_none", title="Returns None", tool_id="t_none", dependencies=[]),
            ScanTask(key="t_dict", title="Returns Dict", tool_id="t_dict", dependencies=[]),
            ScanTask(key="t_empty", title="Returns Empty List", tool_id="t_empty", dependencies=[]),
        ]
        dag = ScanDAG(tasks=tasks)
        collectors = {
            "t_none": StrangeCollector(None),
            "t_dict": StrangeCollector({"status": "ok"}),
            "t_empty": StrangeCollector([]),
        }

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: collectors.get(task.tool_id),
        )

        mission = Mission(target="strange.local")
        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert result.collectors_run == 3
        assert result.collectors_failed == 0


def test_collector_duration_tracking():
    """Verify collector duration_ms and duration_seconds record non-zero time."""
    class SlowCollector:
        def collect(self, mission):
            import time
            time.sleep(0.02)
            return []

    with tempfile.TemporaryDirectory() as tmp_dir:
        tasks = [ScanTask(key="slow", title="Slow Task", tool_id="slow", dependencies=[])]
        dag = ScanDAG(tasks=tasks)
        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: SlowCollector(),
        )

        mission = Mission(target="slow.local")
        result = engine.run(mission)

        cr = result.get_collector_result("slow")
        assert cr.duration_ms >= 15.0
        assert cr.duration_seconds >= 0.015


def test_report_generator_failure_resilience():
    """Verify that report generator errors are handled gracefully without aborting the scan result."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        mock_rg = MagicMock()
        mock_rg.generate_and_save.side_effect = RuntimeError("Disk full / permission denied")

        tasks = [ScanTask(key="task_ok", title="Task OK", tool_id="task_ok", dependencies=[])]
        dag = ScanDAG(tasks=tasks)

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            report_generator=mock_rg,
            collector_factory=lambda task: SuccessCollector(),
        )

        mission = Mission(target="report_fail.local")
        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert result.report_paths == []


def test_graph_builder_resilience_on_malformed_evidence():
    """Verify AttackSurfaceGraphBuilder handles incomplete/malformed evidence gracefully."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        bad_ev = Evidence(title="", category="unknown_category_xyz", severity="invalid_severity", value="")
        c = SuccessCollector([bad_ev])

        tasks = [ScanTask(key="t1", title="T1", tool_id="t1", dependencies=[])]
        dag = ScanDAG(tasks=tasks)

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: c,
        )

        mission = Mission(target="bad_ev.local")
        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert result.total_evidence == 1


def test_empty_dag_execution():
    """Verify execution of an empty DAG completes cleanly."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        dag = ScanDAG(tasks=[])
        engine = ScanEngine(dag=dag, output_dir=tmp_dir)

        mission = Mission(target="empty.local")
        result = engine.run(mission)

        assert result.status == "COMPLETED"
        assert result.collectors_total == 0
        assert result.collectors_run == 0
        assert result.total_evidence == 0


def test_mission_with_preexisting_state_and_evidence():
    """Verify evidence store counting works properly when mission already has pre-existing items."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        existing_ev = Evidence(title="Existing", category="subdomain", severity="info", value="pre.example.com")
        mission = Mission(target="preexist.local")
        mission.evidence.add(existing_ev)

        new_ev = Evidence(title="New Vuln", category="sql_injection", severity="high", value="/api?id=1")
        c = SuccessCollector([new_ev])

        tasks = [ScanTask(key="t_new", title="T New", tool_id="t_new", dependencies=[])]
        dag = ScanDAG(tasks=tasks)

        engine = ScanEngine(
            dag=dag,
            output_dir=tmp_dir,
            collector_factory=lambda task: c,
        )

        result = engine.run(mission)

        assert result.total_evidence == 2
        cr = result.get_collector_result("t_new")
        assert cr.evidence_count == 1
