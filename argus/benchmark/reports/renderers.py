from abc import ABC, abstractmethod
from argus.benchmark.reports.models import BenchmarkReport

class BaseRenderer(ABC):
    """Base class for all report renderers."""
    
    @abstractmethod
    def render(self, report: BenchmarkReport) -> str:
        """Renders the benchmark report into a string format."""
        pass
