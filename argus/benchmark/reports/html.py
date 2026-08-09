from argus.benchmark.reports.renderers import BaseRenderer
from argus.benchmark.reports.models import BenchmarkReport
from argus.benchmark.reports.charts import ChartGenerator

class HTMLRenderer(BaseRenderer):
    """Renders the report as a standalone HTML dashboard."""
    
    def render(self, report: BenchmarkReport) -> str:
        
        # Build category rows
        category_rows = ""
        for cat, score in sorted(report.category_scores.items()):
            bar = ChartGenerator.generate_html_bar(score)
            category_rows += f"<tr><td>{cat.replace('_', ' ').title()}</td><td>{score:.2f}</td><td>{bar}</td></tr>"
            
        # Build False Positives
        fp_list = "".join([f"<li><strong>{fp.get('category', 'Unknown')}</strong>: {fp.get('actual', '')}</li>" for fp in report.false_positives])
        if not fp_list: fp_list = "<li>No unexpected findings.</li>"
        
        # Build False Negatives
        fn_list = "".join([f"<li><strong>{fn.get('category', 'Unknown')}</strong>: {fn.get('expected', '')}</li>" for fn in report.false_negatives])
        if not fn_list: fn_list = "<li>No missed findings.</li>"
        
        # Build Recommendations
        rec_list = "".join([f"<li>{rec}</li>" for rec in report.recommendations])
        if not rec_list: rec_list = "<li>No specific recommendations at this time.</li>"
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Argus Benchmark Report: {report.benchmark_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .header {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; border-left: 5px solid #007bff; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; }}
        .score-large {{ font-size: 3em; font-weight: bold; color: #007bff; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
    </style>
</head>
<body>

    <div class="header">
        <h1>Benchmark Report: {report.benchmark_id}</h1>
        <p><strong>Dataset:</strong> {report.dataset} (v{report.dataset_version}) | <strong>Argus Version:</strong> {report.argus_version}</p>
        <p><strong>Date:</strong> {report.timestamp}</p>
    </div>
    
    <div class="grid">
        <div class="card">
            <h2>Executive Summary</h2>
            <div class="score-large">{report.summary.overall_score:.2f} / 100</div>
            <p>{report.summary.comparison_summary}</p>
            <ul>
                <li><strong>Strongest Areas:</strong> {', '.join([c.replace('_', ' ').title() for c in report.summary.strongest_categories]) or 'None'}</li>
                <li><strong>Weakest Areas:</strong> {', '.join([c.replace('_', ' ').title() for c in report.summary.weakest_categories]) or 'None'}</li>
                <li><strong>False Positive Rate:</strong> {report.summary.false_positive_rate:.2f}%</li>
                <li><strong>False Negative Rate:</strong> {report.summary.false_negative_rate:.2f}%</li>
            </ul>
        </div>
        
        <div class="card">
            <h2>Recommendations</h2>
            <ul>
                {rec_list}
            </ul>
        </div>
    </div>
    
    <div class="card">
        <h2>Category Scorecard</h2>
        <table>
            <tr><th>Category</th><th>Score</th><th>Progress</th></tr>
            {category_rows}
        </table>
    </div>
    
    <div class="grid">
        <div class="card">
            <h2>False Positives (Unexpected)</h2>
            <ul>{fp_list}</ul>
        </div>
        <div class="card">
            <h2>False Negatives (Missed)</h2>
            <ul>{fn_list}</ul>
        </div>
    </div>

</body>
</html>
"""
        return html
