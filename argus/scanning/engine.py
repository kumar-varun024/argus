"""Backward-compatibility shim. Canonical location: argus.runtime.pipeline.scan_pipeline.

The scan pipeline moved under the runtime package. This module re-exports the
same ``ScanEngine`` class so ``from argus.scanning.engine import ScanEngine``
(and the string patch target ``argus.scanning.engine.ScanEngine.run``) keeps
working — the class object is shared, so method-level patches apply everywhere.
"""
from argus.runtime.pipeline.scan_pipeline import ScanEngine

__all__ = ["ScanEngine"]
