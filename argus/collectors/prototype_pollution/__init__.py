"""Prototype Pollution & Client-Side Attack Detection Module for ARGUS.

Split into a sub-package; all public names re-exported for import-path compatibility.
"""
from argus.collectors.prototype_pollution.models import (
    ClientSideAttackResult,
    ClientSideMutationStrategy,
    ClientSideSeverity,
    ClientSideStrategy,
    ClientSideTechnique,
    ClientSideVulnerabilityType,
    GadgetFramework,
    PrototypePollutionMutationStrategy,
    PrototypePollutionProbe,
    PrototypePollutionProbeResponse,
    PrototypePollutionResult,
    PrototypePollutionSeverity,
    PrototypePollutionStrategy,
    PrototypePollutionTechnique,
    PrototypePollutionVulnerabilityType,
    Severity,
)
from argus.collectors.prototype_pollution.payloads import (
    PrototypePollutionPayloadGenerator,
)
from argus.collectors.prototype_pollution.probes import (
    PrototypePollutionProber,
)
from argus.collectors.prototype_pollution.analyzer import (
    PrototypePollutionAnalyzer,
)
from argus.collectors.prototype_pollution.collector import (
    ClickjackingCollector,
    ClientSideAttackCollector,
    DOMClobberingCollector,
    OpenRedirectCollector,
    ProtoPollutionCollector,
    PrototypePollutionCollector,
)
__all__ = [
    "ClickjackingCollector",
    "ClientSideAttackCollector",
    "ClientSideAttackResult",
    "ClientSideMutationStrategy",
    "ClientSideSeverity",
    "ClientSideStrategy",
    "ClientSideTechnique",
    "ClientSideVulnerabilityType",
    "DOMClobberingCollector",
    "GadgetFramework",
    "OpenRedirectCollector",
    "ProtoPollutionCollector",
    "PrototypePollutionAnalyzer",
    "PrototypePollutionCollector",
    "PrototypePollutionMutationStrategy",
    "PrototypePollutionPayloadGenerator",
    "PrototypePollutionProbe",
    "PrototypePollutionProbeResponse",
    "PrototypePollutionProber",
    "PrototypePollutionResult",
    "PrototypePollutionSeverity",
    "PrototypePollutionStrategy",
    "PrototypePollutionTechnique",
    "PrototypePollutionVulnerabilityType",
    "Severity",
]
