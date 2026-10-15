"""Shared enums for collectors.

The canonical vulnerability ``Severity`` scale. Every collector previously
declared its own identical 5-level enum (``SSTISeverity``, ``AuthBypassSeverity``,
plain ``Severity``, ...); those now alias this single definition so severity
values are defined once and compare/serialize identically across collectors.
"""
from enum import Enum


class Severity(str, Enum):
    """Canonical finding severity scale (string-valued for stable serialization)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
