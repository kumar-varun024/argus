from typing import Any
from .authentication import AuthenticationModel
from .test_identity import TestIdentity, AuthType
from argus.runtime.pipeline.models import ScanResult, CollectorResult, CollectorStatus

__all__ = [
    "AuthenticationModel",
    "TestIdentity",
    "AuthType",
    "MissionState",
    "MissionStatus",
    "ScanResult",
    "CollectorResult",
    "CollectorStatus",
]


def __getattr__(name: str) -> Any:
    if name in ("MissionState", "MissionStatus"):
        from argus.runtime.mission import MissionState
        return MissionState
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
