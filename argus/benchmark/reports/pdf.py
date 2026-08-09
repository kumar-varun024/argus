import tempfile
from argus.benchmark.reports.renderers import BaseRenderer
from argus.benchmark.reports.models import BenchmarkReport
from argus.benchmark.reports.html import HTMLRenderer

try:
    from weasyprint import HTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False

class PDFRenderer(BaseRenderer):
    """Renders the report as a PDF document using WeasyPrint (via HTML)."""
    
    def render(self, report: BenchmarkReport) -> bytes:
        if not HAS_WEASYPRINT:
            raise RuntimeError("WeasyPrint is not installed. Cannot generate PDF.")
            
        html_content = HTMLRenderer().render(report)
        pdf_bytes = HTML(string=html_content).write_pdf()
        return pdf_bytes
