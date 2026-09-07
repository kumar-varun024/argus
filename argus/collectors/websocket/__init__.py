"""WebSocket Security Detection Collector for ARGUS.

Split into a sub-package; all public names re-exported for import-path compatibility.
"""
from argus.collectors.websocket.models import (
    COMMAND_OUTPUT_SIGNATURES,
    CSWSH_VULNERABLE_SIGNATURES,
    DOS_CRASH_SIGNATURES,
    HARDENED_WS_DEFENSE_SIGNATURES,
    PROTOTYPE_POLLUTION_SIGNATURES,
    SQL_ERROR_SIGNATURES,
    Severity,
    WebSocketMutationStrategy,
    WebSocketSecurityResult,
    WebSocketSeverity,
    WebSocketTechnique,
    XSS_OUTPUT_SIGNATURES,
)
from argus.collectors.websocket.payloads import (
    WebSocketPayloadGenerator,
)
from argus.collectors.websocket.analyzer import (
    WebSocketSecurityAnalyzer,
)
from argus.collectors.websocket.collector import (
    WebSocketCollector,
    WebSocketSecurityCollector,
)
__all__ = [
    "COMMAND_OUTPUT_SIGNATURES",
    "CSWSH_VULNERABLE_SIGNATURES",
    "DOS_CRASH_SIGNATURES",
    "HARDENED_WS_DEFENSE_SIGNATURES",
    "PROTOTYPE_POLLUTION_SIGNATURES",
    "SQL_ERROR_SIGNATURES",
    "Severity",
    "WebSocketCollector",
    "WebSocketMutationStrategy",
    "WebSocketPayloadGenerator",
    "WebSocketSecurityAnalyzer",
    "WebSocketSecurityCollector",
    "WebSocketSecurityResult",
    "WebSocketSeverity",
    "WebSocketTechnique",
    "XSS_OUTPUT_SIGNATURES",
]
