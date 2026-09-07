"""request_smuggling: HTTP probe dispatch."""
from __future__ import annotations

import socket
import ssl
import time
import urllib.parse
from typing import Callable, Dict, List, Optional, Tuple, Union

from argus.collectors.request_smuggling.models import RawHttpResponse


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
