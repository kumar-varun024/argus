"""Deterministic scan pipeline — the DAG-based scan strategy of the runtime spine.

Relocated from the former top-level ``argus.scanning`` package so the scan
pipeline lives under the runtime it serves. ``ScanEngine`` is loaded lazily (it
pulls in reporting/graph/evidence dependencies) exactly as the old package did.
``argus.scanning`` remains as a thin re-export shim for existing importers.
"""
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
        from .scan_pipeline import ScanEngine
        return ScanEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
