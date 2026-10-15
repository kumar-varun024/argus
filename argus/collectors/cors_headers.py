"""
Deprecated CORS/security-header module (compatibility shim).

The former ~1800-line ``cors_headers`` collector was an unused rewrite: nothing
imported it except the package ``__init__`` re-export, and it had no tests, while
the runtime resolver, the DAG task ``cors_security``, and the test suite all use
the canonical implementation in :mod:`argus.collectors.cors_security`.

This module now re-exports the canonical names so any lingering
``from argus.collectors.cors_headers import ...`` keeps working during migration.
Import from :mod:`argus.collectors.cors_security` (or the ``argus.collectors``
package) directly; this shim will be removed in a future cleanup.
"""
from argus.collectors.cors_security import (
    CORSSecurityCollector,
    CORSSecurityAnalyzer,
    CORSPayloadGenerator,
    CORSProbe,
    CORSProbeResponse,
    CORSSecurityResult,
    HeaderAuditResult,
    CORSVulnerabilityType,
    HeaderVulnerabilityType,
    CORSMutationStrategy,
)

# Historical collector-variant names all map to the single canonical collector.
CORSHeadersCollector = CORSSecurityCollector
CORSCollector = CORSSecurityCollector
CORSMisconfigurationCollector = CORSSecurityCollector
HTTPHeaderAuditorCollector = CORSSecurityCollector
SecurityHeadersCollector = CORSSecurityCollector
HTTPHeaderCollector = CORSSecurityCollector

# Historical analyzer/generator/strategy aliases -> canonical equivalents.
CORSAnalyzer = CORSSecurityAnalyzer
HTTPHeaderAuditor = CORSSecurityAnalyzer
HeaderAuditor = CORSSecurityAnalyzer
CORSMutationGenerator = CORSPayloadGenerator
CORSStrategy = CORSMutationStrategy

__all__ = [
    "CORSSecurityCollector",
    "CORSSecurityAnalyzer",
    "CORSPayloadGenerator",
    "CORSProbe",
    "CORSProbeResponse",
    "CORSSecurityResult",
    "HeaderAuditResult",
    "CORSVulnerabilityType",
    "HeaderVulnerabilityType",
    "CORSMutationStrategy",
    "CORSHeadersCollector",
    "CORSCollector",
    "CORSMisconfigurationCollector",
    "HTTPHeaderAuditorCollector",
    "SecurityHeadersCollector",
    "HTTPHeaderCollector",
    "CORSAnalyzer",
    "HTTPHeaderAuditor",
    "HeaderAuditor",
    "CORSMutationGenerator",
    "CORSStrategy",
]
