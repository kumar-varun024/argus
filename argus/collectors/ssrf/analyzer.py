"""ssrf: Response analysis."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from argus.collectors.toolkit.enums import Severity
from argus.http.client import HttpResponse
from argus.collectors.ssrf.models import CLOUD_METADATA_SIGNATURES, INTERNAL_SERVICE_SIGNATURES, SSRFCloudProvider, SSRFTechnique


class SSRFAnalyzer:
    """
    Evaluates HTTP responses for genuine Server-Side Request Forgery vulnerabilities across:
    1. Cloud Metadata Response Detection (AWS, GCP, Azure, DigitalOcean, Oracle, Alibaba).
    2. Internal Service Response Detection (Redis, MySQL, PostgreSQL, Elasticsearch, MongoDB, Memcached, RabbitMQ, Admin).
    3. Differential Timing Analysis (latency delta >= 4.0s vs baseline).
    4. False Positive & Reflection Suppression.
    """

    GENERIC_BENIGN_TITLES = re.compile(
        r"<title>[^<]*(?:error|exception|not found|bad request|forbidden|server error|search)[^<]*</title>",
        re.IGNORECASE,
    )

    def analyze_cloud_metadata(
        self,
        response: Optional[HttpResponse],
        baseline: Optional[HttpResponse] = None,
        target_info: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Analyzes response body for cloud metadata signatures (AWS IMDS, GCP metadata, Azure IMDS, etc.).
        """
        if not response or not response.raw_body:
            return None

        body_str = str(response.raw_body)
        baseline_body = str(baseline.raw_body) if baseline and baseline.raw_body else ""
        payload = (target_info or {}).get("url", "")
        expected_sig = (target_info or {}).get("signature", "")

        signatures_to_check: List[Tuple[str, Dict[str, Any]]] = []
        if expected_sig and expected_sig in CLOUD_METADATA_SIGNATURES:
            signatures_to_check.append((expected_sig, CLOUD_METADATA_SIGNATURES[expected_sig]))
        for sig_name, sig_meta in CLOUD_METADATA_SIGNATURES.items():
            if (sig_name, sig_meta) not in signatures_to_check:
                signatures_to_check.append((sig_name, sig_meta))

        for sig_name, sig_meta in signatures_to_check:
            pattern: re.Pattern = sig_meta["pattern"]
            provider: str = sig_meta.get("provider", SSRFCloudProvider.GENERIC.value)
            match = pattern.search(body_str)
            if match:
                snippet = match.group(0)

                # 1. Baseline Subtraction: suppress if the baseline response already contained this match
                if baseline_body and pattern.search(baseline_body):
                    continue

                # 2. Verbatim Reflection Guard: suppress if this is merely an echo of the search/input query
                if self._is_verbatim_reflection(body_str, payload, snippet):
                    continue

                return {
                    "technique": SSRFTechnique.CLOUD_METADATA.value,
                    "template_id": f"ssrf_cloud_{provider}",
                    "severity": Severity.CRITICAL,
                    "confidence": 0.95,
                    "cloud_provider": provider,
                    "target_service": f"{provider}_metadata",
                    "matched_pattern": sig_name,
                    "snippet": snippet[:250],
                    "payload": payload,
                    "extra": {
                        "provider": provider,
                        "description": sig_meta.get("description", ""),
                        "status_code": getattr(response, "status_code", 200),
                    },
                }

        return None

    def analyze_internal_service(
        self,
        response: Optional[HttpResponse],
        baseline: Optional[HttpResponse] = None,
        target_info: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Analyzes response body for internal service signatures (Redis, MySQL, PostgreSQL, Elasticsearch, MongoDB, Memcached, Admin).
        """
        if not response or not response.raw_body:
            return None

        body_str = str(response.raw_body)
        baseline_body = str(baseline.raw_body) if baseline and baseline.raw_body else ""
        payload = (target_info or {}).get("url", "")
        expected_sig = (target_info or {}).get("signature", "")

        signatures_to_check: List[Tuple[str, Dict[str, Any]]] = []
        if expected_sig and expected_sig in INTERNAL_SERVICE_SIGNATURES:
            signatures_to_check.append((expected_sig, INTERNAL_SERVICE_SIGNATURES[expected_sig]))
        for sig_name, sig_meta in INTERNAL_SERVICE_SIGNATURES.items():
            if (sig_name, sig_meta) not in signatures_to_check:
                signatures_to_check.append((sig_name, sig_meta))


        for sig_name, sig_meta in signatures_to_check:
            pattern: re.Pattern = sig_meta["pattern"]
            service: str = sig_meta.get("service", "generic")
            match = pattern.search(body_str)
            if match:
                snippet = match.group(0)

                # Baseline Subtraction
                if baseline_body and pattern.search(baseline_body):
                    continue

                # Reflection Guard
                if self._is_verbatim_reflection(body_str, payload, snippet):
                    continue

                severity = sig_meta.get("severity", Severity.HIGH)
                return {
                    "technique": SSRFTechnique.INTERNAL_SERVICE.value,
                    "template_id": f"ssrf_internal_{service}",
                    "severity": severity,
                    "confidence": 0.92,
                    "target_service": service,
                    "matched_pattern": sig_name,
                    "snippet": snippet[:250],
                    "payload": payload,
                    "extra": {
                        "service": service,
                        "description": sig_meta.get("description", ""),
                        "status_code": getattr(response, "status_code", 200),
                    },
                }

        return None

    def analyze_differential_timing(
        self,
        injected_resp: Optional[HttpResponse],
        baseline_resp: Optional[HttpResponse] = None,
        threshold: float = 4.0,
    ) -> Optional[Dict[str, Any]]:
        """
        Analyzes timing differentials for time-based blind SSRF against unroutable / dropping IP endpoints.
        Requires delay delta >= threshold (default 4.0s) and total injected elapsed >= threshold.
        """
        if not injected_resp:
            return None

        baseline_elapsed = getattr(baseline_resp, "elapsed", 0.0) if baseline_resp else 0.0
        injected_elapsed = getattr(injected_resp, "elapsed", 0.0)
        delay_delta = round(injected_elapsed - baseline_elapsed, 4)

        if delay_delta >= threshold and injected_elapsed >= threshold:

            return {
                "technique": SSRFTechnique.DIFFERENTIAL_TIMING.value,
                "template_id": "ssrf_timing_blind",
                "severity": Severity.HIGH,
                "confidence": 0.90,
                "delay_delta": delay_delta,
                "baseline_elapsed": baseline_elapsed,
                "injected_elapsed": injected_elapsed,
                "target_service": "unroutable_network",
                "matched_pattern": "differential_timing_latency_delta",
                "snippet": (
                    f"Server-side request latency increased by {delay_delta:.2f}s "
                    f"(baseline: {baseline_elapsed:.2f}s, injected: {injected_elapsed:.2f}s, threshold: {threshold:.1f}s)"
                ),
            }

        return None


    def is_false_positive(
        self,
        response: Optional[HttpResponse],
        payload: str = "",
        baseline: Optional[HttpResponse] = None,
    ) -> bool:
        """
        Determines if a response is a false positive (empty response, identical to baseline,
        or purely reflected query string in benign error pages).
        """
        if not response or not response.raw_body:
            return True

        body_str = str(response.raw_body).strip()
        if len(body_str) < 5:
            return True

        if baseline and baseline.raw_body:
            if body_str == str(baseline.raw_body).strip():
                return True

        return False

    def _is_verbatim_reflection(self, body: str, payload: str, snippet: str) -> bool:
        """
        Checks if the matched snippet is solely due to the payload being echoed back
        in an HTML search heading, input field, or documentation string without internal response execution.
        """
        if not payload or not snippet:
            return False
        clean_payload = payload.strip()
        clean_snippet = snippet.strip()

        # If snippet exactly equals payload and no actual service response markers exist
        if clean_snippet == clean_payload and not any(
            marker in clean_snippet
            for marker in (
                "AccessKeyId", "computeMetadata", "vmId", "+PONG",
                "redis_version", "mysql_native_password", "You Know, for Search",
                "droplet_id", "ocid1.instance.", "<title>Admin Dashboard</title>",
            )
        ):
            return True

        # Check for search echo wrappers: e.g. <p>Results for "..."</p>
        search_echo_pattern = re.compile(
            r"(?:results\s+for|searched\s+for|query\s*:|echo\s*:)\s*[\"']?" + re.escape(clean_snippet),
            re.IGNORECASE,
        )
        if search_echo_pattern.search(body) and len(body.split(clean_snippet)) == 2:
            # Check if there is genuine metadata/service content outside the reflection
            has_genuine_signature = any(
                sig_meta["pattern"].search(body.replace(clean_snippet, ""))
                for sig_meta in {**CLOUD_METADATA_SIGNATURES, **INTERNAL_SERVICE_SIGNATURES}.values()
            )
            if not has_genuine_signature:
                return True

        return False
