"""Backward-compatibility shim for the relocated scan pipeline.

The scan pipeline now lives at :mod:`argus.runtime.pipeline`. This package
re-exports its public surface so ``from argus.scanning import ...`` and the
``argus.scanning.{engine,dag,models}`` submodule paths keep resolving.
"""
from typing import Any

from argus.runtime.pipeline.models import ScanResult, CollectorResult, CollectorStatus
from argus.runtime.pipeline.dag import ScanDAG, ScanTask

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
        from argus.runtime.pipeline.scan_pipeline import ScanEngine
        return ScanEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
