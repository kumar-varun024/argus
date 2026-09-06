"""Backward-compatibility shim. Canonical location: argus.runtime.pipeline.models.

The scan pipeline moved under the runtime package. This module re-exports the
same objects so ``from argus.scanning.models import ...`` keeps working.
"""
from argus.runtime.pipeline.models import (
    CollectorStatus,
    CollectorResult,
    ScanResult,
)

__all__ = ["CollectorStatus", "CollectorResult", "ScanResult"]
