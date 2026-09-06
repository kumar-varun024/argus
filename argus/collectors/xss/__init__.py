"""Cross-Site Scripting (XSS) detection collector.

Split from the former single-file module into a cohesive sub-package
(models / payloads / analyzer / collector). Public names are re-exported
here so ``from argus.collectors.xss import ...`` keeps working unchanged.
"""
from argus.collectors.xss.models import (
    XSSContext,
    DEFAULT_XSS_PROBE_ROUTES,
    COMMON_XSS_PARAMS,
)
from argus.collectors.xss.payloads import XSSPayloadGenerator
from argus.collectors.xss.analyzer import XSSAnalyzer
from argus.collectors.xss.collector import XSSCollector

__all__ = [
    "XSSCollector",
    "XSSAnalyzer",
    "XSSPayloadGenerator",
    "XSSContext",
    "DEFAULT_XSS_PROBE_ROUTES",
    "COMMON_XSS_PARAMS",
]
