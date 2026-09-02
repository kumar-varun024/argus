from __future__ import annotations

import os
import json
import pytest
from argus.evidence.model import Evidence
from argus.runtime.lifecycle import MissionLifecycle
from argus.runtime.mission import Mission, MissionState
from argus.runtime.state_machine import MissionStateMachine
from argus.runtime.checkpoint import MissionCheckpointer
from argus.runtime.mission_runtime import AutonomousMissionRuntime


class MockEngine:
    def __getattr__(self, name):
        if name in ("queue_manager",):
            return MockEngine()
        def _mock(*args, **kwargs):
            if name == "is_complete":
                return True
            return None
        return _mock


def test_mission_lifecycle_complete_triggers_report_generation(tmp_path):
    out_dir = str(tmp_path / "lifecycle_reports")
    mission = MissionLifecycle.create("lifecycle.target.com")
    MissionLifecycle.start(mission)

    ev = Evidence(
        evidence_id="ev-life-1",
        category="sql_injection",
        severity="critical",
        title="Critical SQL Injection",
        metadata={
            "host": "lifecycle.target.com",
            "endpoint": "/api/v1/auth",
            "parameter": "user",
            "payload": "' OR '1'='1",
        },
    )
    mission.evidence.add(ev)

    MissionLifecycle.complete(mission, output_dir=out_dir)

    assert mission.status == MissionState.COMPLETED
    assert len(mission.reports) == 2

    md_path = next(p for p in mission.reports if p.endswith(".md"))
    json_path = next(p for p in mission.reports if p.endswith(".json"))

    assert os.path.exists(md_path)
    assert os.path.exists(json_path)

    # Validate json content
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["target"] == "lifecycle.target.com"
    assert data["summary"]["total_findings"] == 1
    assert data["findings"][0]["severity"] == "critical"
    assert data["findings"][0]["cvss"]["score"] >= 9.0


def test_autonomous_mission_runtime_completion_triggers_reporting(tmp_path):
    mission = Mission(target="runtime.target.com")
    mission.status = MissionState.GENERATING_HYPOTHESES
    sm = MissionStateMachine(mission)
    checkpointer = MissionCheckpointer()

    ev = Evidence(
        evidence_id="ev-rt-1",
        category="reflected_xss",
        severity="medium",
        title="Reflected XSS in Comments",
        metadata={
            "host": "runtime.target.com",
            "endpoint": "/comments",
            "parameter": "msg",
            "payload": "<svg onload=alert(1)>",
        },
    )
    mission.evidence.add(ev)

    runtime = AutonomousMissionRuntime(
        mission=mission,
        state_machine=sm,
        checkpointer=checkpointer,
        mission_planner=MockEngine(),
        research_planner=MockEngine(),
        task_scheduler=MockEngine(),
        tool_orchestrator=MockEngine(),
        correlation_engine=MockEngine(),
        fusion_engine=MockEngine(),
        investigation_builder=MockEngine(),
        priority_engine=MockEngine(),
        hypothesis_engine=MockEngine(),
        learning_engine=MockEngine(),
    )

    runtime.step()

    assert mission.status == MissionState.COMPLETED
    assert len(mission.reports) == 2
    for path in mission.reports:
        assert os.path.exists(path)
