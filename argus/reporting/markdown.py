from __future__ import annotations

from typing import Optional
from argus.reporting.models import Finding, VulnerabilityReport


class HackerOneMarkdownRenderer:
    """Renders a VulnerabilityReport into a structured, professional HackerOne-style Markdown report."""

    def render(self, report: VulnerabilityReport) -> str:
        """Generates complete Markdown document from report data."""
        lines: list[str] = []

        # 1. Document Header
        lines.append(f"# Vulnerability Assessment Report — {report.target or 'ARGUS Assessment'}")
        lines.append("")
        lines.append(f"> **Mission ID:** `{report.mission_id or 'ad-hoc'}`  ")
        lines.append(f"> **Generated At:** `{report.generated_at}`  ")
        lines.append(f"> **Engine:** `ARGUS Vulnerability Reporting Engine v{report.generator_version}`  ")
        lines.append(f"> **Total Deduplicated Findings:** `{report.summary.total_findings}` (from `{report.summary.total_evidence_items}` evidence items)")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 2. Executive Summary
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append(
            f"An authorized defensive security assessment was conducted against **{report.target or 'the designated scope'}**. "
            f"The assessment identified a total of **{report.summary.total_findings}** unique vulnerabilities "
            f"after consolidating **{report.summary.total_evidence_items}** evidence observations."
        )
        lines.append("")
        lines.append("### Severity Distribution")
        lines.append("")
        lines.append("| Severity Rating | Finding Count |")
        lines.append("| :--- | :---: |")
        lines.append(f"| 🔴 **Critical** | {report.summary.severity_counts.get('critical', 0)} |")
        lines.append(f"| 🟠 **High** | {report.summary.severity_counts.get('high', 0)} |")
        lines.append(f"| 🟡 **Medium** | {report.summary.severity_counts.get('medium', 0)} |")
        lines.append(f"| 🔵 **Low** | {report.summary.severity_counts.get('low', 0)} |")
        lines.append(f"| ⚪ **Info** | {report.summary.severity_counts.get('info', 0)} |")
        lines.append(f"| **Total Findings** | **{report.summary.total_findings}** |")
        lines.append("")

        # Category & Host summaries
        if report.summary.category_counts:
            lines.append("### Category Breakdown")
            lines.append("")
            lines.append("| Category | Findings |")
            lines.append("| :--- | :---: |")
            for cat, count in sorted(report.summary.category_counts.items(), key=lambda x: -x[1]):
                lines.append(f"| `{cat}` | {count} |")
            lines.append("")

        lines.append("---")
        lines.append("")

        # 3. Findings Scorecard / Table
        lines.append("## 2. Findings Scorecard")
        lines.append("")
        if not report.findings:
            lines.append("*No vulnerabilities or security findings were identified.*")
            lines.append("")
        else:
            lines.append("| # | Title | Severity | CVSS v3.1 | CWE | Target Host | Endpoint |")
            lines.append("| :-: | :--- | :---: | :---: | :---: | :--- | :--- |")
            for idx, f in enumerate(report.findings, start=1):
                sev_badge = self._severity_badge(f.severity)
                cvss_str = f"{f.cvss.score:.1f}" if f.cvss else "N/A"
                cwe_str = f.cwe.id if f.cwe else "N/A"
                host_str = f"`{f.host}`" if f.host else "N/A"
                ep_str = f"`{f.endpoint}`" if f.endpoint else "`/`"
                lines.append(f"| {idx} | [{f.title}](#finding-{idx}) | {sev_badge} | **{cvss_str}** | {cwe_str} | {host_str} | {ep_str} |")
            lines.append("")

        lines.append("---")
        lines.append("")

        # 4. Detailed Finding Sections
        lines.append("## 3. Detailed Vulnerability Findings")
        lines.append("")

        for idx, f in enumerate(report.findings, start=1):
            lines.extend(self._render_finding_section(idx, f))
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def _render_finding_section(self, index: int, f: Finding) -> list[str]:
        """Renders an individual finding with HackerOne-style breakdown."""
        sec: list[str] = []
        sec.append(f"<a id=\"finding-{index}\"></a>")
        sec.append(f"### Finding {index}: {f.title}")
        sec.append("")

        # Metadata table
        sec.append("| Property | Detail |")
        sec.append("| :--- | :--- |")
        sec.append(f"| **Severity** | {self._severity_badge(f.severity)} |")
        if f.cvss:
            sec.append(f"| **CVSS v3.1 Score** | **{f.cvss.score:.1f}** (`{f.cvss.vector}`) |")
        if f.cwe:
            sec.append(f"| **Weakness (CWE)** | **{f.cwe.id}**: {f.cwe.name} |")
        sec.append(f"| **Target Host** | `{f.host}` |")
        sec.append(f"| **Vulnerable Endpoint** | `{f.endpoint}` |")
        if f.parameter:
            param_detail = f"`{f.parameter}`"
            if f.parameter_type:
                param_detail += f" ({f.parameter_type})"
            sec.append(f"| **Vulnerable Parameter** | {param_detail} |")
        sec.append(f"| **Confidence** | {int(f.confidence * 100)}% ({f.status}) |")
        sec.append(f"| **Consolidated Evidence** | {f.duplicate_count} occurrence(s) |")
        sec.append("")

        # Description
        sec.append("#### Summary & Description")
        sec.append("")
        sec.append(f.description)
        sec.append("")

        # Steps to Reproduce
        sec.append("#### Steps to Reproduce")
        sec.append("")
        if f.steps_to_reproduce:
            for s_idx, step in enumerate(f.steps_to_reproduce, start=1):
                sec.append(f"{s_idx}. {step}")
        else:
            sec.append("1. Send a request to the target endpoint.")
            sec.append("2. Observe the vulnerable behavior.")
        sec.append("")

        # Payload / Proof of Concept
        if f.payload:
            sec.append("#### Proof of Concept Payload")
            sec.append("")
            sec.append("```http")
            sec.append(f.payload)
            sec.append("```")
            sec.append("")

        # Impact
        sec.append("#### Impact Analysis")
        sec.append("")
        sec.append(f.impact or "Impact details not specified.")
        sec.append("")

        # Remediation
        sec.append("#### Recommended Remediation")
        sec.append("")
        sec.append(f.remediation or "Remediation details not specified.")
        sec.append("")

        # Supporting Evidence & References
        if f.evidence_ids or f.references:
            sec.append("#### Supporting Evidence & References")
            sec.append("")
            if f.evidence_ids:
                sec.append(f"- **Evidence IDs:** {', '.join(f'`{eid}`' for eid in f.evidence_ids)}")
            if f.references:
                for ref in f.references:
                    sec.append(f"- [{ref}]({ref})")
            sec.append("")

        return sec

    @staticmethod
    def _severity_badge(severity: str) -> str:
        s = severity.lower()
        if s == "critical":
            return "**CRITICAL**"
        elif s == "high":
            return "**HIGH**"
        elif s == "medium":
            return "**MEDIUM**"
        elif s == "low":
            return "**LOW**"
        return "**INFO**"
