"""Backward-compatibility shim. Canonical location: argus.runtime.pipeline.dag.

The scan pipeline moved under the runtime package. This module re-exports the
same classes so ``from argus.scanning.dag import ...`` (and the string patch
target ``argus.scanning.dag.ScanDAG``) keeps working.
"""
from argus.runtime.pipeline.dag import ScanDAG, ScanTask

__all__ = ["ScanDAG", "ScanTask"]
