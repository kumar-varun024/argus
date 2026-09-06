"""Server-Side Template Injection (SSTI) collector (split into a sub-package).

Re-exports every public name (classes, enums, dataclasses, signature maps,
``Severity``/``SSTISeverity``, and the legacy collector alias) so all existing
``from argus.collectors.ssti import ...`` paths resolve unchanged.
"""
from argus.collectors.toolkit.enums import Severity
from argus.collectors.ssti.models import (
    SSTISeverity,
    SSTITechnique,
    SSTIEngineFamily,
    SSTIMutationStrategy,
    SSTIProbe,
    SSTIProbeResponse,
    SSTIResult,
    SSTI_ERROR_SIGNATURES,
    SSTI_RCE_OUTPUT_SIGNATURES,
)
from argus.collectors.ssti.payloads import SSTIPayloadGenerator
from argus.collectors.ssti.analyzer import SSTISecurityAnalyzer
from argus.collectors.ssti.probes import SSTIProber
from argus.collectors.ssti.collector import (
    SSTICollector,
    ServerSideTemplateInjectionCollector,
)

__all__ = [
    "SSTICollector",
    "ServerSideTemplateInjectionCollector",
    "SSTIPayloadGenerator",
    "SSTISecurityAnalyzer",
    "SSTIProber",
    "SSTIProbe",
    "SSTIProbeResponse",
    "SSTIResult",
    "SSTITechnique",
    "SSTIEngineFamily",
    "SSTIMutationStrategy",
    "SSTI_ERROR_SIGNATURES",
    "SSTI_RCE_OUTPUT_SIGNATURES",
    "Severity",
    "SSTISeverity",
]
