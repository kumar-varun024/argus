"""HTTP Request Smuggling Detection Collector for ARGUS.

Split into a sub-package; all public names re-exported for import-path compatibility.
"""
from argus.collectors.request_smuggling.models import (
    CANARY_DESYNC_SIGNATURES,
    HARDENED_DEFENSE_SIGNATURES,
    RawHttpResponse,
    RequestSmugglingMutationStrategy,
    RequestSmugglingResult,
    RequestSmugglingSeverity,
    RequestSmugglingTechnique,
    Severity,
)
from argus.collectors.request_smuggling.payloads import (
    RequestSmugglingPayloadGenerator,
)
from argus.collectors.request_smuggling.probes import (
    RawHttpStreamProber,
)
from argus.collectors.request_smuggling.analyzer import (
    RequestSmugglingSecurityAnalyzer,
)
from argus.collectors.request_smuggling.collector import (
    HTTPRequestSmugglingCollector,
    RequestSmugglingCollector,
)
__all__ = [
    "CANARY_DESYNC_SIGNATURES",
    "HARDENED_DEFENSE_SIGNATURES",
    "HTTPRequestSmugglingCollector",
    "RawHttpResponse",
    "RawHttpStreamProber",
    "RequestSmugglingCollector",
    "RequestSmugglingMutationStrategy",
    "RequestSmugglingPayloadGenerator",
    "RequestSmugglingResult",
    "RequestSmugglingSecurityAnalyzer",
    "RequestSmugglingSeverity",
    "RequestSmugglingTechnique",
    "Severity",
]
