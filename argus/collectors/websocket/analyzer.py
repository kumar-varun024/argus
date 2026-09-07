"""websocket: Response analysis."""
from __future__ import annotations

import urllib.parse
from typing import Dict, Optional

from argus.http.client import HttpResponse
from argus.collectors.websocket.models import COMMAND_OUTPUT_SIGNATURES, HARDENED_WS_DEFENSE_SIGNATURES, PROTOTYPE_POLLUTION_SIGNATURES, SQL_ERROR_SIGNATURES, WebSocketMutationStrategy, WebSocketSecurityResult, WebSocketSeverity, WebSocketTechnique, XSS_OUTPUT_SIGNATURES
from argus.collectors.websocket.payloads import WebSocketPayloadGenerator


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
