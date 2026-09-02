from typing import Any
from .models import ScanResult, CollectorResult, CollectorStatus
from .dag import ScanDAG, ScanTask

__all__ = [
    "ScanEngine",
    "ScanResult",
    "CollectorResult",
    "CollectorStatus",
    "ScanDAG",
    "ScanTask",
]


def __getattr__(name: str) -> Any:
    if name == "ScanEngine":
        from .engine import ScanEngine
        return ScanEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
