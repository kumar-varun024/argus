"""request_smuggling: Data models, enums, and constants."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from argus.collectors.toolkit.enums import Severity


RequestSmugglingSeverity = Severity

Severity = RequestSmugglingSeverity

class RequestSmugglingTechnique(str, Enum):
    """Enumeration of HTTP request smuggling detection techniques."""
    CL_TE = "cl_te"
    TE_CL = "te_cl"
    TE_TE = "te_te"
    H2_CL = "h2_cl"
    H2_TE = "h2_te"
    H2_CRLF = "h2_crlf"
    DIFFERENTIAL_TIMING = "differential_timing"
    PIPELINE_POISONING = "pipeline_poisoning"

class RequestSmugglingMutationStrategy(str, Enum):
    """Enumeration of HTTP header obfuscation and mutation strategies."""
    STANDARD = "standard"
    HEADER_CASING_WHITESPACE = "header_casing_whitespace"
    DUAL_HEADER = "dual_header"
    HOP_BY_HOP = "hop_by_hop"
    CHUNK_EXTENSION = "chunk_extension"
    HEX_MUTATION = "hex_mutation"
    H2_PSEUDO_HEADER = "h2_pseudo_header"
    COMMA_DELIMITED = "comma_delimited"

@dataclass
class RawHttpResponse:
    """Represents a low-level HTTP response captured from a raw byte stream / socket."""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    raw_headers: List[Tuple[str, str]] = field(default_factory=list)
    body: str = ""
    raw_bytes: bytes = b""
    elapsed: float = 0.0
    error: Optional[str] = None
    timed_out: bool = False
    protocol: str = "HTTP/1.1"
    url: str = ""

@dataclass
class RequestSmugglingResult:
    """Represents the outcome of an HTTP request smuggling validation probe."""
    technique: str
    mutation_strategy: str
    severity: str
    confidence: float
    payload: str
    matched_signature: str
    evidence_snippet: str
    endpoint_url: str
    parameter: Optional[str] = None
    parameter_type: str = "http_header"
    status_code: int = 200
    delay_delta: float = 0.0
    baseline_elapsed: float = 0.0
    injected_elapsed: float = 0.0
    is_valid_finding: bool = True
    error_message: Optional[str] = None
    template_id: str = "request-smuggling"
    vulnerability_type: Optional[str] = None
    cwe_id: str = "CWE-444"
    cvss_score: float = 8.9
    follow_up_status: Optional[int] = None

    def __post_init__(self):
        if not self.vulnerability_type:
            self.vulnerability_type = self.technique

HARDENED_DEFENSE_SIGNATURES: Dict[str, re.Pattern] = {
    "bad_request": re.compile(
        r"(?:400\s+Bad\s+Request|invalid\s+request\s+line|malformed\s+http\s+header|illegal\s+request|unsupported\s+transfer\s+encoding|duplicate\s+content-length|transfer-encoding\s+not\s+supported|rfc\s+compliance\s+error)",
        re.IGNORECASE,
    ),
    "not_implemented": re.compile(
        r"(?:501\s+Not\s+Implemented|unsupported\s+method|chunked\s+encoding\s+not\s+supported)",
        re.IGNORECASE,
    ),
    "h2_protocol_error": re.compile(
        r"(?:PROTOCOL_ERROR|HTTP_1_1_REQUIRED|FRAME_SIZE_ERROR|REFUSED_STREAM|invalid\s+pseudo\s+header)",
        re.IGNORECASE,
    ),
}

CANARY_DESYNC_SIGNATURES: Dict[str, re.Pattern] = {
    "canary_marker": re.compile(r"ARGUS_SMUGGLE_CANARY", re.IGNORECASE),
    "canary_path": re.compile(r"/argus_smuggled_canary", re.IGNORECASE),
    "unrecognized_method": re.compile(r"(?:GPOST|PGET|SMUGGLE|CANARY|XGET)\b", re.IGNORECASE),
    "status_inversion_404": re.compile(r"(?:404\s+Not\s+Found|cannot\s+find|no\s+such\s+resource)", re.IGNORECASE),
    "status_inversion_405": re.compile(r"(?:405\s+Method\s+Not\s+Allowed)", re.IGNORECASE),
}
