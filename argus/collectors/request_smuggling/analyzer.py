"""request_smuggling: Response analysis."""
from __future__ import annotations

from typing import Dict, Optional

from argus.collectors.request_smuggling.models import CANARY_DESYNC_SIGNATURES, HARDENED_DEFENSE_SIGNATURES, RawHttpResponse, RequestSmugglingResult, RequestSmugglingSeverity


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
