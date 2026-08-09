import pytest
from argus.benchmark.reports.generator import ReportGenerator
from argus.benchmark.runner.models import EvaluationResult
from argus.benchmark.metrics.models import BenchmarkScore
from argus.benchmark.reports.markdown import MarkdownRenderer
from argus.benchmark.reports.html import HTMLRenderer
from argus.benchmark.reports.json import JSONRenderer
from argus.benchmark.reports.pdf import PDFRenderer, HAS_WEASYPRINT

def test_markdown_renderer():
    eval_result = EvaluationResult(id="e1", benchmark_id="b1", dataset="d1", runtime=10.0, score=BenchmarkScore(overall_score=99.0))
    report = ReportGenerator.generate(eval_result)
    md = MarkdownRenderer().render(report)
    
    assert "# Benchmark Report: b1" in md
    assert "99.00/100" in md
    
def test_html_renderer():
    eval_result = EvaluationResult(id="e1", benchmark_id="b1", dataset="d1", runtime=10.0, score=BenchmarkScore(overall_score=99.0))
    report = ReportGenerator.generate(eval_result)
    html = HTMLRenderer().render(report)
    
    assert "<title>Argus Benchmark Report: b1</title>" in html
    assert "99.00 / 100" in html
    
def test_json_renderer():
    eval_result = EvaluationResult(id="e1", benchmark_id="b1", dataset="d1", runtime=10.0, score=BenchmarkScore(overall_score=99.0))
    report = ReportGenerator.generate(eval_result)
    json_out = JSONRenderer().render(report)
    
    assert '"benchmark_id": "b1"' in json_out
    assert '"overall_score": 99.0' in json_out

@pytest.mark.skipif(not HAS_WEASYPRINT, reason="WeasyPrint not installed")
def test_pdf_renderer():
    eval_result = EvaluationResult(id="e1", benchmark_id="b1", dataset="d1", runtime=10.0, score=BenchmarkScore(overall_score=99.0))
    report = ReportGenerator.generate(eval_result)
    pdf = PDFRenderer().render(report)
    
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
