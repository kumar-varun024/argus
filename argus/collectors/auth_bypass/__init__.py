"""Authentication Bypass & Credential Attack Detection Module for ARGUS.

Split into a sub-package; all public names re-exported for import-path compatibility.
"""
from argus.collectors.auth_bypass.models import (
    AuthBypassMutationStrategy,
    AuthBypassProbe,
    AuthBypassProbeResponse,
    AuthBypassResult,
    AuthBypassSeverity,
    AuthBypassTechnique,
    AuthMutationStrategy,
    AuthSeverity,
    AuthStrategy,
    AuthTechnique,
    AuthVulnerabilityType,
    Severity,
)
from argus.collectors.auth_bypass.payloads import (
    AuthBypassPayloadGenerator,
)
from argus.collectors.auth_bypass.probes import (
    AuthBypassProber,
)
from argus.collectors.auth_bypass.analyzer import (
    AuthBypassAnalyzer,
    TokenEntropyAnalyzer,
)
from argus.collectors.auth_bypass.collector import (
    AuthBypassCollector,
    AuthCollector,
    AuthenticationBypassCollector,
    BruteForceCollector,
    CredentialAttackCollector,
    DefaultCredentialsCollector,
    JWTMisconfigurationCollector,
    MFABypassCollector,
    SessionFixationCollector,
)
__all__ = [
    "AuthBypassAnalyzer",
    "AuthBypassCollector",
    "AuthBypassMutationStrategy",
    "AuthBypassPayloadGenerator",
    "AuthBypassProbe",
    "AuthBypassProbeResponse",
    "AuthBypassProber",
    "AuthBypassResult",
    "AuthBypassSeverity",
    "AuthBypassTechnique",
    "AuthCollector",
    "AuthMutationStrategy",
    "AuthSeverity",
    "AuthStrategy",
    "AuthTechnique",
    "AuthVulnerabilityType",
    "AuthenticationBypassCollector",
    "BruteForceCollector",
    "CredentialAttackCollector",
    "DefaultCredentialsCollector",
    "JWTMisconfigurationCollector",
    "MFABypassCollector",
    "SessionFixationCollector",
    "Severity",
    "TokenEntropyAnalyzer",
]
