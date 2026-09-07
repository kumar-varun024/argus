"""websocket: Data models, enums, and constants."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional

from argus.collectors.toolkit.enums import Severity


WebSocketSeverity = Severity

Severity = WebSocketSeverity

class WebSocketTechnique(str, Enum):
    """Enumeration of WebSocket security detection techniques."""
    CSWSH = "cswsh"
    BROKEN_AUTHENTICATION = "broken_authentication"
    TOKEN_IN_QUERY_PARAM = "token_in_query_param"
    INJECTION_SQLI = "injection_sqli"
    INJECTION_CMDI = "injection_cmdi"
    INJECTION_XSS = "injection_xss"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    UNMASKED_FRAME_DOS = "unmasked_frame_dos"
    OVERSIZED_FRAME_DOS = "oversized_frame_dos"
    RATE_LIMIT_FLOOD = "rate_limit_flood"

class WebSocketMutationStrategy(str, Enum):
    """Enumeration of WebSocket handshake & payload mutation strategies."""
    STANDARD = "standard"
    ORIGIN_MANIPULATION = "origin_manipulation"
    SUBPROTOCOL_TAMPERING = "subprotocol_tampering"
    HOP_BY_HOP_SMUGGLING = "hop_by_hop_smuggling"
    CASING_WHITESPACE_MUTATION = "casing_whitespace_mutation"
    EXTENSION_DEFLATE_FUZZING = "extension_deflate_fuzzing"
    PARAMETER_AUTHENTICATION_BYPASS = "parameter_authentication_bypass"

@dataclass
class WebSocketSecurityResult:
    """Represents the parsed outcome of a WebSocket security validation probe."""
    technique: str
    mutation_strategy: str
    severity: str
    confidence: float
    payload: str
    matched_signature: str
    evidence_snippet: str
    endpoint_url: str
    parameter: Optional[str] = None
    parameter_type: str = "websocket_handshake"
    status_code: int = 101
    delay_delta: float = 0.0
    baseline_elapsed: float = 0.0
    injected_elapsed: float = 0.0
    is_valid_finding: bool = True
    error_message: Optional[str] = None
    template_id: str = "websocket-security"
    vulnerability_type: Optional[str] = None
    cwe_id: str = "CWE-1385"
    cvss_score: float = 8.1
    close_code: Optional[int] = None

    def __post_init__(self):
        if not self.vulnerability_type:
            self.vulnerability_type = self.technique

CSWSH_VULNERABLE_SIGNATURES: Dict[str, re.Pattern] = {
    "upgrade_accepted": re.compile(r"101\s+Switching\s+Protocols", re.IGNORECASE),
    "websocket_upgrade": re.compile(r"websocket", re.IGNORECASE),
}

HARDENED_WS_DEFENSE_SIGNATURES: Dict[str, re.Pattern] = {
    "origin_forbidden": re.compile(
        r"(?:origin\s+(?:not\s+allowed|forbidden|invalid|mismatch|rejected)|invalid\s+origin|cross-origin\s+websocket\s+forbidden|unauthorized\s+origin|origin\s+header\s+required)",
        re.IGNORECASE,
    ),
    "unauthorized_handshake": re.compile(
        r"(?:unauthorized|missing\s+authentication|invalid\s+token|token\s+expired|authentication\s+required|unauthenticated\s+session|credentials\s+missing)",
        re.IGNORECASE,
    ),
    "upgrade_required": re.compile(
        r"(?:upgrade\s+required|426\s+upgrade\s+required|websocket\s+upgrade\s+required)",
        re.IGNORECASE,
    ),
    "rate_limit_rejection": re.compile(
        r"(?:too\s+many\s+requests|rate\s+limit\s+exceeded|message\s+rate\s+limit|flood\s+detected|policy\s+violation)",
        re.IGNORECASE,
    ),
}

SQL_ERROR_SIGNATURES: Dict[str, re.Pattern] = {
    "postgresql": re.compile(
        r"(?:syntax error at or near|pg_query\(\)|org\.postgresql\.util\.PSQLException|PostgreSQL query failed)",
        re.IGNORECASE,
    ),
    "mysql": re.compile(
        r"(?:You have an error in your SQL syntax|mysql_fetch|com\.mysql\.jdbc|MySQLSyntaxErrorException)",
        re.IGNORECASE,
    ),
    "sqlite": re.compile(
        r"(?:SQLite3::SQLException|near\s+['\"][^'\"]+['\"]: syntax error|sqlite_error|SQLITE_ERROR)",
        re.IGNORECASE,
    ),
    "oracle": re.compile(
        r"(?:ORA-01756|ORA-00933|ORA-00907|Oracle error)",
        re.IGNORECASE,
    ),
    "mssql": re.compile(
        r"(?:Unclosed quotation mark before the character string|Microsoft OLE DB Provider for SQL Server|com\.microsoft\.sqlserver\.jdbc)",
        re.IGNORECASE,
    ),
    "generic_sql": re.compile(
        r"(?:SQL syntax.*error|SQLSTATE\[[0-9A-Z]+\]|unterminated quoted string|quoted string not properly terminated)",
        re.IGNORECASE,
    ),
}

COMMAND_OUTPUT_SIGNATURES: Dict[str, re.Pattern] = {
    "passwd_entry": re.compile(
        r"(?:root:.*?:0:0:|daemon:.*?:1:1:|[a-zA-Z0-9_\-]+:[^:\n]+:\d+:\d+:[^:\n]*:[^:\n]*:[^:\n]*)",
        re.IGNORECASE,
    ),
    "id_command": re.compile(
        r"uid=\d+\([a-zA-Z0-9_\-]+\)\s+gid=\d+\([a-zA-Z0-9_\-]+\)|uid=\d+\s+gid=\d+",
        re.IGNORECASE,
    ),
    "windows_system": re.compile(
        r"(?:Windows IP Configuration|Directory of [A-Z]:\\|Volume in drive [A-Z] is)",
        re.IGNORECASE,
    ),
}

XSS_OUTPUT_SIGNATURES: Dict[str, re.Pattern] = {
    "script_tag": re.compile(
        r"<script>alert\(['\"]?(?:ARGUS_WS_XSS|1)['\"]?\)</script>",
        re.IGNORECASE,
    ),
    "img_onerror": re.compile(
        r"<img\s+src=x\s+onerror=alert\(['\"]?1['\"]?\)>",
        re.IGNORECASE,
    ),
    "svg_onload": re.compile(
        r"<svg\s+onload=alert\(['\"]?1['\"]?\)>",
        re.IGNORECASE,
    ),
}

PROTOTYPE_POLLUTION_SIGNATURES: Dict[str, re.Pattern] = {
    "polluted_property": re.compile(
        r'(?:["\']polluted["\']\s*:\s*true|["\']isAdmin["\']\s*:\s*true|["\']prototype_polluted["\']\s*:\s*true)',
        re.IGNORECASE,
    ),
    "prototype_echo": re.compile(
        r"(?:Object\.prototype\.(?:polluted|isAdmin)|polluted:\s*true)",
        re.IGNORECASE,
    ),
}

DOS_CRASH_SIGNATURES: Dict[str, re.Pattern] = {
    "server_error_500": re.compile(r"500\s+Internal\s+Server\s+Error", re.IGNORECASE),
    "service_unavailable": re.compile(r"503\s+Service\s+Unavailable", re.IGNORECASE),
    "connection_reset": re.compile(r"(?:connection\s+reset|broken\s+pipe|server\s+closed\s+connection\s+without\s+response)", re.IGNORECASE),
}
