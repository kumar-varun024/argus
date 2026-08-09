from argus.benchmark.reports.renderers import BaseRenderer
from argus.benchmark.reports.models import BenchmarkReport
from argus.benchmark.reports.charts import ChartGenerator

class MarkdownRenderer(BaseRenderer):
    """Renders the report as Markdown suitable for GitHub/GitLab."""
    
    def render(self, report: BenchmarkReport) -> str:
        lines = []
        
        # Header
        lines.append(f"# Benchmark Report: {report.benchmark_id}")
        lines.append(f"**Dataset:** {report.dataset} (v{report.dataset_version}) | **Argus Version:** {report.argus_version}")
        lines.append(f"**Date:** {report.timestamp}")
        lines.append("")
        
        # Executive Summary
        lines.append("## Executive Summary")
        lines.append(f"**Overall Score:** {report.summary.overall_score:.2f}/100")
        lines.append("")
        lines.append(report.summary.comparison_summary)
        lines.append("")
        lines.append(f"- **Strongest Areas:** {', '.join([c.replace('_', ' ').title() for c in report.summary.strongest_categories]) or 'None'}")
        lines.append(f"- **Weakest Areas:** {', '.join([c.replace('_', ' ').title() for c in report.summary.weakest_categories]) or 'None'}")
        lines.append(f"- **False Positive Rate:** {report.summary.false_positive_rate:.2f}%")
        lines.append(f"- **False Negative Rate:** {report.summary.false_negative_rate:.2f}%")
        lines.append("")
        
        # Scorecard
        lines.append("## Category Scorecard")
        lines.append("| Category | Score | Progress |")
        lines.append("|----------|-------|----------|")
        for cat, score in sorted(report.category_scores.items()):
            bar = ChartGenerator.generate_ascii_bar(score, 100.0, 20)
            lines.append(f"| {cat.replace('_', ' ').title()} | {score:.2f} | `{bar}` |")
        lines.append("")
        
        # False Positives / Negatives
        lines.append("## Analysis")
        lines.append("### False Positives (Unexpected Findings)")
        if report.false_positives:
            for fp in report.false_positives:
                lines.append(f"- **{fp.get('category', 'Unknown')}**: {fp.get('actual', '')}")
        else:
            lines.append("No unexpected findings.")
        lines.append("")
        
        lines.append("### False Negatives (Missed Findings)")
        if report.false_negatives:
            for fn in report.false_negatives:
                lines.append(f"- **{fn.get('category', 'Unknown')}**: {fn.get('expected', '')}")
        else:
            lines.append("No missed findings.")
        lines.append("")
        
        # Recommendations
        lines.append("## Recommendations")
        if report.recommendations:
            for rec in report.recommendations:
                lines.append(f"- {rec}")
        else:
            lines.append("No specific recommendations at this time.")
            
        return "\n".join(lines)
