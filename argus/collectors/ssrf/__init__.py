"""Server-Side Request Forgery (SSRF) Detection Engine and Collector.

Split into a sub-package; all public names re-exported for import-path compatibility.
"""
from argus.collectors.ssrf.models import (
    CLOUD_METADATA_SIGNATURES,
    COMMON_SSRF_PARAMS,
    DEFAULT_INTERNAL_SERVICE_TARGETS,
    DEFAULT_SSRF_PROBE_ROUTES,
    DEFAULT_SSRF_TARGETS,
    DEFAULT_TIMING_TARGETS,
    INTERNAL_SERVICE_SIGNATURES,
    SSRFCloudProvider,
    SSRFResult,
    SSRFTechnique,
)
from argus.collectors.ssrf.payloads import (
    SSRFPayloadGenerator,
)
from argus.collectors.ssrf.analyzer import (
    SSRFAnalyzer,
)
from argus.collectors.ssrf.collector import (
    SSRFCollector,
)
from argus.collectors.toolkit.enums import Severity
__all__ = [
    "Severity",
    "CLOUD_METADATA_SIGNATURES",
    "COMMON_SSRF_PARAMS",
    "DEFAULT_INTERNAL_SERVICE_TARGETS",
    "DEFAULT_SSRF_PROBE_ROUTES",
    "DEFAULT_SSRF_TARGETS",
    "DEFAULT_TIMING_TARGETS",
    "INTERNAL_SERVICE_SIGNATURES",
    "SSRFAnalyzer",
    "SSRFCloudProvider",
    "SSRFCollector",
    "SSRFPayloadGenerator",
    "SSRFResult",
    "SSRFTechnique",
]
