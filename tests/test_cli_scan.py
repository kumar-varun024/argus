import os
import sys
import json
import tempfile
import subprocess
from unittest.mock import patch, MagicMock
import pytest
from typer.testing import CliRunner

from argus.cli.app import app
from argus.scanning.dag import ScanDAG, ScanTask
from argus.scanning.models import ScanResult, CollectorResult, CollectorStatus
from argus.evidence.model import Evidence
from argus.runtime.manager import mission_manager


runner = CliRunner()


def test_cli_help():
    """Test top-level CLI help contains scan and subcommands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "version" in result.output
    assert "mission" in result.output


def test_cli_version():
    """Test top-level CLI version command."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Argus v0.1.0-alpha" in result.output


def test_cli_scan_help():
    """Test scan command help contains all expected options."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--profile" in result.output or "-p" in result.output
    assert "--output" in result.output or "-o" in result.output
    assert "--threads" in result.output or "-t" in result.output
    assert "--timeout" in result.output
    assert "--scope" in result.output or "-s" in result.output
    assert "--workspace" in result.output or "-w" in result.output
    assert "--format" in result.output or "-f" in result.output
    assert "--verbose" in result.output or "-v" in result.output


def test_scan_dag_create_for_profile_profiles():
    """Verify ScanDAG.create_for_profile creates correctly filtered DAGs."""
    dag_full = ScanDAG.create_for_profile("full")
    assert len(dag_full.tasks) == 26
    assert len(dag_full.get_execution_order()) == 26

    dag_recon = ScanDAG.create_for_profile("recon")
    assert len(dag_recon.tasks) == 5
    for task in dag_recon.tasks:
        assert task.phase == "recon"
    assert len(dag_recon.get_execution_order()) == 5

    dag_vuln = ScanDAG.create_for_profile("vuln")
    assert len(dag_vuln.tasks) == 21
    for task in dag_vuln.tasks:
        assert task.phase == "vulnerability"
    assert len(dag_vuln.get_execution_order()) == 21

    dag_quick = ScanDAG.create_for_profile("quick")
    assert 5 < len(dag_quick.tasks) < 26
    assert len(dag_quick.get_execution_order()) == len(dag_quick.tasks)

    # Alias check
    dag_alias = ScanDAG.from_profile("recon")
    assert len(dag_alias.tasks) == 5

    # Fallback to full for unknown profile
    dag_fallback = ScanDAG.create_for_profile("unknown_profile")
    assert len(dag_fallback.tasks) == 26


def test_cli_scan_default_profile_execution():
    """Test standard argus scan command execution with mocked ScanEngine."""
    mock_collector_result = CollectorResult(
        tool_id="subfinder",
        task_title="Discover Subdomains",
        status=CollectorStatus.COMPLETED,
        evidence_count=3,
        duration_ms=45.0,
        error=None,
        task_key="subfinder",
    )
    mock_scan_result = ScanResult(
        scan_id="mission-12345",
        target="target.local",
        status="COMPLETED",
        start_time="2026-09-02T12:00:00",
        end_time="2026-09-02T12:00:05",
        duration_seconds=5.0,
        collectors_total=1,
        collectors_run=1,
        collectors_skipped=0,
        collectors_failed=0,
        total_evidence=3,
        vulnerabilities_by_severity={"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
        collector_results=[mock_collector_result],
        state_transitions=[],
        report_paths=["/tmp/reports/report_target.local_20260902_120000_12345.md", "/tmp/reports/report_target.local_20260902_120000_12345.json"],
        graph_summary={},
    )

    with patch("argus.scanning.engine.ScanEngine.run", return_value=mock_scan_result) as mock_run:
        result = runner.invoke(app, ["scan", "target.local"])
        assert result.exit_code == 0
        assert mock_run.called

        # Verify output formatting
        assert "ARGUS Autonomous Offensive Security Scanner" in result.output
        assert "target.local" in result.output
        assert "Discover Subdomains" in result.output or "subfinder" in result.output
        assert "COMPLETED" in result.output
        assert "CRITICAL: 1" in result.output
        assert "HIGH: 2" in result.output
        assert "Generated Reports" in result.output
        assert ".md" in result.output
        assert ".json" in result.output


@pytest.mark.parametrize("profile_arg", ["recon", "vuln", "quick", "full"])
def test_cli_scan_profiles(profile_arg):
    """Test CLI scan with different profiles."""
    with patch("argus.scanning.engine.ScanEngine.run") as mock_run:
        mock_run.return_value = ScanResult(
            scan_id="m-test",
            target="profile.test",
            status="COMPLETED",
            start_time="2026-09-02T12:00:00",
            end_time="2026-09-02T12:00:01",
            duration_seconds=1.0,
            collectors_total=5,
            collectors_run=5,
            collectors_skipped=0,
            collectors_failed=0,
            total_evidence=0,
            vulnerabilities_by_severity={},
            collector_results=[],
            state_transitions=[],
            report_paths=[],
            graph_summary={},
        )
        result = runner.invoke(app, ["scan", "profile.test", "--profile", profile_arg])
        assert result.exit_code == 0
        assert profile_arg.upper() in result.output


def test_cli_scan_scope_and_workspace():
    """Test CLI scan scope and workspace options are populated on the Mission."""
    captured_mission = None

    def fake_run(mission):
        nonlocal captured_mission
        captured_mission = mission
        return ScanResult(
            scan_id=mission.id,
            target=mission.target,
            status="COMPLETED",
            start_time="2026-09-02T12:00:00",
            end_time="2026-09-02T12:00:01",
            duration_seconds=1.0,
            collectors_total=1,
            collectors_run=1,
            collectors_skipped=0,
            collectors_failed=0,
            total_evidence=0,
            vulnerabilities_by_severity={},
            collector_results=[],
            state_transitions=[],
            report_paths=[],
            graph_summary={},
        )

    with patch("argus.scanning.engine.ScanEngine.run", side_effect=fake_run):
        result = runner.invoke(
            app,
            [
                "scan",
                "target.domain",
                "-s",
                "extra1.domain",
                "-s",
                "10.0.0.0/24",
                "-w",
                "custom_ws",
                "-t",
                "16",
                "--timeout",
                "300",
            ],
        )
        assert result.exit_code == 0
        assert captured_mission is not None
        assert captured_mission.target == "target.domain"
        assert captured_mission.workspace == "custom_ws"
        assert "extra1.domain" in captured_mission.scope
        assert "10.0.0.0/24" in captured_mission.scope
        assert captured_mission.configuration.get("threads") == 16
        assert captured_mission.configuration.get("timeout") == 300
        # Check mission manager registration
        assert captured_mission.id in mission_manager._active_missions


def test_cli_scan_format_filtering():
    """Test format filtering for markdown and json."""
    mock_scan_result = ScanResult(
        scan_id="m-fmt",
        target="fmt.test",
        status="COMPLETED",
        start_time="2026-09-02T12:00:00",
        end_time="2026-09-02T12:00:01",
        duration_seconds=1.0,
        collectors_total=1,
        collectors_run=1,
        collectors_skipped=0,
        collectors_failed=0,
        total_evidence=0,
        vulnerabilities_by_severity={},
        collector_results=[],
        state_transitions=[],
        report_paths=["/path/to/report.md", "/path/to/report.json"],
        graph_summary={},
    )

    with patch("argus.scanning.engine.ScanEngine.run", return_value=mock_scan_result):
        # Markdown only
        res_md = runner.invoke(app, ["scan", "fmt.test", "--format", "markdown"])
        assert res_md.exit_code == 0
        assert "/path/to/report.md" in res_md.output
        assert "/path/to/report.json" not in res_md.output

        # JSON only
        res_json = runner.invoke(app, ["scan", "fmt.test", "--format", "json"])
        assert res_json.exit_code == 0
        assert "/path/to/report.json" in res_json.output
        assert "/path/to/report.md" not in res_json.output


def test_cli_scan_empty_target_failure():
    """Test empty target raises exit code 1."""
    result = runner.invoke(app, ["scan", "   "])
    assert result.exit_code == 1
    assert "Target cannot be empty" in result.output


def test_cli_scan_engine_failure_status():
    """Test scan returning FAILED status exits with code 1."""
    failed_result = ScanResult(
        scan_id="m-fail",
        target="fail.test",
        status="FAILED",
        start_time="2026-09-02T12:00:00",
        end_time="2026-09-02T12:00:01",
        duration_seconds=1.0,
        collectors_total=1,
        collectors_run=0,
        collectors_skipped=0,
        collectors_failed=1,
        total_evidence=0,
        vulnerabilities_by_severity={},
        collector_results=[],
        state_transitions=[],
        report_paths=[],
        graph_summary={},
    )

    with patch("argus.scanning.engine.ScanEngine.run", return_value=failed_result):
        result = runner.invoke(app, ["scan", "fail.test"])
        assert result.exit_code == 1
        assert "FAILED" in result.output


def test_cli_scan_engine_exception():
    """Test unhandled engine exception exits with code 1."""
    with patch("argus.scanning.engine.ScanEngine.run", side_effect=RuntimeError("Engine exploded")):
        result = runner.invoke(app, ["scan", "crash.test"])
        assert result.exit_code == 1
        assert "Scan execution error" in result.output or "Engine exploded" in result.output


def test_cli_scan_end_to_end_with_report_generation():
    """End-to-end test of argus scan CLI with mock collector creating genuine reports on disk."""
    with tempfile.TemporaryDirectory() as temp_dir:
        class FastMockCollector:
            def collect(self, mission):
                ev = Evidence(
                    category="vulnerability",
                    severity="high",
                    target=mission.target,
                    value={"title": "Test SQLi", "description": "SQL Injection found"},
                    task_id="sql_injection",
                )
                mission.evidence.add(ev)
                return [ev]

        single_task = ScanTask(
            key="test_task",
            title="Test Vulnerability Collector",
            tool_id="sql_injection",
            phase="vulnerability",
        )
        custom_dag = ScanDAG(tasks=[single_task])

        with patch("argus.scanning.dag.ScanDAG.create_for_profile", return_value=custom_dag):
            with patch("argus.scanning.engine.ScanEngine.resolve_collector", return_value=FastMockCollector()):
                result = runner.invoke(app, ["scan", "app.local", "--output", temp_dir, "--verbose"])
                assert result.exit_code == 0
                assert "Test Vulnerability Collector" in result.output or "sql_injection" in result.output
                assert "COMPLETED" in result.output

                # Verify reports exist on disk
                files = os.listdir(temp_dir)
                md_files = [f for f in files if f.endswith(".md")]
                json_files = [f for f in files if f.endswith(".json")]
                assert len(md_files) >= 1
                assert len(json_files) >= 1

                # Verify JSON report contents
                with open(os.path.join(temp_dir, json_files[0]), "r") as f:
                    data = json.load(f)
                    assert data["target"] == "app.local"


def test_python_m_argus_subprocess():
    """Test running python -m argus via subprocess."""
    proc = subprocess.run(
        [sys.executable, "-m", "argus", "version"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "Argus v0.1.0-alpha" in proc.stdout
