from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, List, Optional, Union

from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.reporting.json import JSONReportRenderer
from argus.reporting.markdown import HackerOneMarkdownRenderer
from argus.reporting.models import VulnerabilityReport
from argus.reporting.processor import EvidenceProcessor


class ReportGenerator:
    """Orchestrates vulnerability report generation, formatting, and file persistence."""

    DEFAULT_OUTPUT_DIR = ".argus/reports"

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or self.DEFAULT_OUTPUT_DIR
        self.processor = EvidenceProcessor()
        self.md_renderer = HackerOneMarkdownRenderer()
        self.json_renderer = JSONReportRenderer()

    def generate(self, mission: Any) -> VulnerabilityReport:
        """Generates a structured VulnerabilityReport from a Mission instance."""
        target = getattr(mission, "target", "Unknown Target")
        mission_id = getattr(mission, "id", "ad-hoc")
        evidence_source = getattr(mission, "evidence", None)

        # Fallback if evidence is empty but vulnerabilities exist
        if (
            (evidence_source is None or len(evidence_source) == 0)
            and hasattr(mission, "vulnerabilities")
            and mission.vulnerabilities
        ):
            evidence_source = mission.vulnerabilities

        return self.processor.process(
            evidence_source=evidence_source or [],
            target=target,
            mission_id=mission_id,
        )

    def generate_from_evidence(
        self,
        evidence_items: Union[EvidenceStore, list[Evidence], Any],
        target: str = "Unknown Target",
        mission_id: str = "ad-hoc",
    ) -> VulnerabilityReport:
        """Generates a VulnerabilityReport directly from an EvidenceStore or collection of Evidence."""
        return self.processor.process(
            evidence_source=evidence_items,
            target=target,
            mission_id=mission_id,
        )

    def render_markdown(self, report: VulnerabilityReport) -> str:
        """Renders report into HackerOne-style Markdown."""
        return self.md_renderer.render(report)

    def render_json(self, report: VulnerabilityReport, indent: int = 2) -> str:
        """Renders report into machine-readable JSON."""
        return self.json_renderer.render(report, indent=indent)

    def save_report(
        self,
        report: VulnerabilityReport,
        output_dir: Optional[str] = None,
    ) -> list[str]:
        """Persists a generated report to Markdown and JSON files on disk."""
        target_dir = output_dir or self.output_dir
        os.makedirs(target_dir, exist_ok=True)

        safe_target = re.sub(r"[^a-zA-Z0-9_\-]", "_", report.target or "target").strip("_")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_short_id = (report.report_id or "rep")[:8]

        base_filename = f"report_{safe_target}_{timestamp}_{report_short_id}"
        md_path = os.path.join(target_dir, f"{base_filename}.md")
        json_path = os.path.join(target_dir, f"{base_filename}.json")

        md_content = self.render_markdown(report)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        json_content = self.render_json(report)
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(json_content)

        return [md_path, json_path]

    def generate_and_save(
        self,
        mission: Any,
        output_dir: Optional[str] = None,
    ) -> list[str]:
        """Generates the vulnerability report from mission and saves Markdown & JSON to disk.
        
        Also registers the resulting file paths in mission.reports.
        """
        report = self.generate(mission)
        file_paths = self.save_report(report, output_dir=output_dir)

        # Register in mission state
        if hasattr(mission, "reports") and isinstance(mission.reports, list):
            for path in file_paths:
                if path not in mission.reports:
                    mission.reports.append(path)

        return file_paths
