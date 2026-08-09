import json
import dataclasses
from argus.benchmark.reports.renderers import BaseRenderer
from argus.benchmark.reports.models import BenchmarkReport

class JSONRenderer(BaseRenderer):
    """Renders the report as a JSON string."""
    
    def render(self, report: BenchmarkReport) -> str:
        return json.dumps(dataclasses.asdict(report), indent=2)
