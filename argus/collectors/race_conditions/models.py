"""race_conditions: Data models, enums, and constants."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Set

from argus.collectors.toolkit.enums import Severity


RaceConditionSeverity = Severity

Severity = RaceConditionSeverity

class RaceConditionTechnique(str, Enum):
    """Enumeration of race condition vulnerability detection techniques."""
    LIMIT_OVERRUN = "limit_overrun"
    TOCTOU = "toctou"
    SESSION_CONCURRENCY = "session_concurrency"
    MULTI_ENDPOINT_RACE = "multi_endpoint_race"
    DIFFERENTIAL_STATE_VERIFICATION = "differential_state_verification"

class ConcurrencyStrategy(str, Enum):
    """Enumeration of synchronization and concurrency probing strategies."""
    HTTP2_SINGLE_PACKET = "http2_single_packet"
    CONNECTION_PREWARMING = "connection_prewarming"
    MICROSECOND_BARRIER = "microsecond_barrier"
    TCP_PADDING = "tcp_padding"
    DYNAMIC_CONCURRENCY_SCALING = "dynamic_concurrency_scaling"

@dataclass
class ConcurrencyProbeResponse:
    """Represents an individual response captured during a synchronized burst probe."""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    json_data: Optional[Any] = None
    timestamp_sent: float = 0.0
    timestamp_received: float = 0.0
    elapsed: float = 0.0
    error: Optional[str] = None
    request_index: int = 0
    endpoint_url: str = ""
    raw_response: Optional[Any] = None

@dataclass
class RaceConditionResult:
    """Represents the outcome of a race condition validation probe."""
    technique: str
    strategy: str
    severity: str
    confidence: float
    payload: Any
    matched_signature: str
    evidence_snippet: str
    endpoint_url: str
    parameter: Optional[str] = None
    parameter_type: str = "concurrency_probe"
    status_code: int = 200
    is_valid_finding: bool = True
    error_message: Optional[str] = None
    template_id: str = "race-conditions"
    vulnerability_type: Optional[str] = None
    cwe_id: str = "CWE-362"
    cvss_score: float = 8.6
    concurrency_burst_size: int = 10
    successful_overruns: int = 0
    pre_state: Any = None
    post_state: Any = None
    state_delta: Any = None
    latency_jitter_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.vulnerability_type:
            self.vulnerability_type = self.technique
        if not self.metadata:
            self.metadata = {
                "concurrency_burst_size": self.concurrency_burst_size,
                "successful_overruns": self.successful_overruns,
                "pre_state": self.pre_state,
                "post_state": self.post_state,
                "state_delta": self.state_delta,
                "latency_jitter_ms": self.latency_jitter_ms,
                "strategy": self.strategy,
                "technique": self.technique,
            }

HARDENED_DEFENSE_SIGNATURES: Dict[str, re.Pattern] = {
    "conflict_rejection": re.compile(
        r"(?:409\s+Conflict|idempotency\s+conflict|already\s+redeemed|already\s+used|resource\s+already\s+consumed|coupon\s+exhausted|balance\s+lock|duplicate\s+request|concurrent\s+mutation\s+prevented|mutex|optimistic\s+lock)",
        re.IGNORECASE,
    ),
    "insufficient_funds": re.compile(
        r"(?:insufficient\s+funds|insufficient\s+balance|balance\s+exceeded|not\s+enough\s+funds|overdraft\s+prevented)",
        re.IGNORECASE,
    ),
    "token_invalid": re.compile(
        r"(?:invalid\s+or\s+expired|token\s+already\s+used|otp\s+already\s+consumed|session\s+expired|single-use\s+token\s+exhausted)",
        re.IGNORECASE,
    ),
    "rate_limited": re.compile(
        r"(?:429\s+Too\s+Many\s+Requests|rate\s+limit\s+exceeded|too\s+many\s+requests|throttled)",
        re.IGNORECASE,
    ),
}

SUCCESS_STATUS_CODES: Set[int] = {200, 201, 202, 204}

REJECTION_STATUS_CODES: Set[int] = {400, 401, 403, 404, 409, 422, 423, 429, 500}
