from __future__ import annotations

import os
import tempfile
import pytest
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.reporting.generator import ReportGenerator
from argus.runtime.mission import Mission, MissionState


def test_generator_from_mission(tmp_path):
    mission = Mission(target="secure.example.com")
    mission.id = "mission-gen-001"

    ev1 = Evidence(
        evidence_id="ev-g1",
        category="sql_injection",
        severity="critical",
        title="Admin SQL Injection",
        metadata={"host": "secure.example.com", "endpoint": "/api/admin", "parameter": "token"},
    )
    ev2 = Evidence(
        evidence_id="ev-g2",
        category="broken_access_control",
        severity="high",
        title="Tenant Isolation Bypass",
        metadata={"host": "secure.example.com", "endpoint": "/api/tenant", "parameter": "id"},
    )
    mission.evidence.add(ev1)
    mission.evidence.add(ev2)

    generator = ReportGenerator(output_dir=str(tmp_path))
    report = generator.generate(mission)

    assert report.target == "secure.example.com"
    assert report.mission_id == "mission-gen-001"
    assert report.summary.total_findings == 2
    assert report.findings[0].severity == "critical"
    assert report.findings[1].severity == "high"


def test_generator_from_evidence_items():
    ev = Evidence(
        evidence_id="ev-adhoc",
        category="reflected_xss",
        severity="medium",
        metadata={"host": "adhoc.com", "endpoint": "/view"},
    )
    generator = ReportGenerator()
    report = generator.generate_from_evidence([ev], target="adhoc.com", mission_id="adhoc-1")

    assert report.target == "adhoc.com"
    assert report.mission_id == "adhoc-1"
    assert report.summary.total_findings == 1
    assert report.findings[0].category == "reflected_xss"


def test_generate_and_save_persists_files_and_updates_mission(tmp_path):
    mission = Mission(target="save.target.com")
    mission.id = "mission-save-99"

    ev = Evidence(
        evidence_id="ev-s1",
        category="command_injection",
        severity="critical",
        metadata={"host": "save.target.com", "endpoint": "/exec", "payload": "cat /etc/passwd"},
    )
    mission.evidence.add(ev)

    out_dir = str(tmp_path / "reports_out")
    generator = ReportGenerator(output_dir=out_dir)
    report_paths = generator.generate_and_save(mission)

    assert len(report_paths) == 2
    md_path = next(p for p in report_paths if p.endswith(".md"))
    json_path = next(p for p in report_paths if p.endswith(".json"))

    assert os.path.exists(md_path)
    assert os.path.exists(json_path)

    # Check that mission.reports received the paths
    assert md_path in mission.reports
    assert json_path in mission.reports

    # Validate file contents
    with open(md_path, "r", encoding="utf-8") as f:
        md_content = f.read()
    assert "# Vulnerability Assessment Report" in md_content
    assert "save.target.com" in md_content
    assert "cat /etc/passwd" in md_content

    with open(json_path, "r", encoding="utf-8") as f:
        json_content = f.read()
    assert '"target": "save.target.com"' in json_content
    assert '"command_injection"' in json_content
