"""SSTI response analysis and RCE/error signature matching."""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, Optional

from argus.collectors.ssti.models import (
    SSTIProbe,
    SSTIProbeResponse,
    SSTIResult,
    SSTITechnique,
    SSTIEngineFamily,
    SSTIMutationStrategy,
    SSTI_ERROR_SIGNATURES,
    SSTI_RCE_OUTPUT_SIGNATURES,
    SSTISeverity,
)


class SSTISecurityAnalyzer:
    """
    Analyzes probe responses to detect arithmetic evaluation, RCE execution,
    template engine disambiguation, blind time delays, and error stack traces
    while strictly suppressing false-positive reflections.
    """

    @staticmethod
    def is_static_reflection(response_body: str, payload: str) -> bool:
        """
        Returns True if the raw unrendered payload (or HTML/URL encoded version)
        appears verbatim in the response body without evaluation.
        """
        if not response_body or not payload:
            return False

        # Raw payload reflection
        if payload in response_body:
            return True

        # HTML entity escaped reflection
        html_escaped = (
            payload.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )
        if html_escaped in response_body:
            return True

        # URL encoded reflection
        url_encoded = urllib.parse.quote(payload)
        if url_encoded in response_body:
            return True

        url_plus = urllib.parse.quote_plus(payload)
        if url_plus in response_body:
            return True

        return False

    @staticmethod
    def strip_payload_reflections(response_body: str, payload: str) -> str:
        """
        Strips verbatim, HTML-escaped, and URL-encoded occurrences of payload
        from response body to isolate evaluated template output.
        """
        if not response_body or not payload:
            return response_body
        cleaned = response_body.replace(payload, "")
        html_escaped = (
            payload.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )
        cleaned = cleaned.replace(html_escaped, "")
        cleaned = cleaned.replace(urllib.parse.quote(payload), "")
        cleaned = cleaned.replace(urllib.parse.quote_plus(payload), "")
        return cleaned

    @staticmethod
    def analyze_arithmetic_evaluation(
        response_body: str,
        canary_expected: str,
        baseline_body: str = "",
        payload: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Verifies that an arithmetic canary evaluated in the template and is present
        in the response body while NOT naturally existing in the baseline response.
        """
        if not response_body or not canary_expected:
            return None

        # Check if expected mathematical result exists in body
        # We use regex word boundaries or token checking to prevent substring false positives
        pattern = re.compile(r"(?<!\d)" + re.escape(canary_expected) + r"(?!\d)")
        match = pattern.search(response_body)
        if not match:
            # Fallback simple substring
            if canary_expected not in response_body:
                return None

        # Check if the same number was already present in baseline body
        if baseline_body:
            baseline_count = len(pattern.findall(baseline_body))
            response_count = len(pattern.findall(response_body))
            if response_count <= baseline_count and canary_expected in baseline_body:
                return None

        # Extract snippet around match
        idx = response_body.find(canary_expected)
        start = max(0, idx - 40)
        end = min(len(response_body), idx + len(canary_expected) + 40)
        snippet = response_body[start:end].strip()

        return {
            "canary": canary_expected,
            "snippet": snippet,
            "confidence": 0.92,
        }

    @staticmethod
    def analyze_rce_execution(response_body: str) -> Optional[Dict[str, Any]]:
        """
        Scans the response body against known command output and process execution signatures.
        """
        if not response_body:
            return None

        for sig_name, pattern in SSTI_RCE_OUTPUT_SIGNATURES.items():
            match = pattern.search(response_body)
            if match:
                snippet = match.group(0)
                return {
                    "signature": sig_name,
                    "matched_text": snippet,
                    "snippet": snippet[:200],
                    "severity": SSTISeverity.CRITICAL,
                    "confidence": 0.98,
                    "cwe_id": "CWE-94",
                    "cvss_score": 9.8,
                }
        return None

    @staticmethod
    def analyze_error_fingerprint(response_body: str) -> Optional[Dict[str, Any]]:
        """
        Matches error stack traces to fingerprint the underlying template engine.
        """
        if not response_body:
            return None

        for engine_key, (engine_name, pattern) in SSTI_ERROR_SIGNATURES.items():
            match = pattern.search(response_body)
            if match:
                snippet = match.group(0)
                return {
                    "engine": engine_name,
                    "signature": engine_key,
                    "snippet": snippet[:200],
                    "severity": SSTISeverity.LOW,
                    "confidence": 0.85,
                    "cwe_id": "CWE-1336",
                    "cvss_score": 5.3,
                }
        return None

    @staticmethod
    def analyze_blind_timing(
        elapsed: float,
        baseline_elapsed: float = 0.0,
        delay_threshold: float = 4.0,
    ) -> bool:
        """
        Asserts that the probe response elapsed time satisfies the timing delay threshold.
        """
        delta = elapsed - baseline_elapsed
        return delta >= delay_threshold and elapsed >= delay_threshold

    def analyze_probe_response(
        self,
        probe: SSTIProbe,
        response: SSTIProbeResponse,
        baseline_body: str = "",
        baseline_elapsed: float = 0.0,
    ) -> Optional[SSTIResult]:
        """
        Performs full security analysis on an executed SSTI probe response.
        """
        body = response.body or ""
        elapsed = response.elapsed

        # Strip payload reflections from response body to isolate evaluated content
        cleaned_body = self.strip_payload_reflections(body, probe.payload)
        cleaned_baseline = self.strip_payload_reflections(baseline_body, probe.payload)

        # 1. Check RCE Execution (highest priority: CRITICAL)
        rce_match = self.analyze_rce_execution(cleaned_body)
        if rce_match:
            return SSTIResult(
                technique=SSTITechnique.SANDBOX_ESCAPE_RCE.value,
                engine=str(probe.engine.value if isinstance(probe.engine, SSTIEngineFamily) else probe.engine),
                payload=probe.payload,
                parameter=probe.parameter,
                parameter_type=probe.parameter_type,
                target_url=probe.url,
                status_code=response.status_code,
                matched_signature=rce_match["signature"],
                evidence_snippet=rce_match["snippet"],
                severity=SSTISeverity.CRITICAL.value,
                confidence=rce_match["confidence"],
                template_id="ssti_rce",
                cwe_id="CWE-94",
                cvss_score=9.8,
                mutation_strategy=str(probe.mutation_strategy.value if isinstance(probe.mutation_strategy, SSTIMutationStrategy) else probe.mutation_strategy) if probe.mutation_strategy else None,
                injected_elapsed=elapsed,
                baseline_elapsed=baseline_elapsed,
            )

        # 2. Check Decision Tree Differential Routing
        if probe.technique == SSTITechnique.DECISION_TREE_ROUTING:
            extra = probe.extra or {}
            # Type coercion check: {{7*'7'}}
            if "rules" in extra:
                rules = extra["rules"]
                for expected_str, detected_engine in rules.items():
                    if expected_str in cleaned_body and expected_str not in cleaned_baseline:
                        eng_name = detected_engine.value if isinstance(detected_engine, SSTIEngineFamily) else detected_engine
                        return SSTIResult(
                            technique=SSTITechnique.DECISION_TREE_ROUTING.value,
                            engine=str(eng_name),
                            payload=probe.payload,
                            parameter=probe.parameter,
                            parameter_type=probe.parameter_type,
                            target_url=probe.url,
                            status_code=response.status_code,
                            matched_signature=f"differential_match:{expected_str}",
                            evidence_snippet=f"Engine disambiguation resolved to {eng_name} via output '{expected_str}'",
                            severity=SSTISeverity.HIGH.value,
                            confidence=0.95,
                            template_id="ssti",
                            cwe_id="CWE-1336",
                            cvss_score=8.2,
                            expected_canary=expected_str,
                            injected_elapsed=elapsed,
                            baseline_elapsed=baseline_elapsed,
                        )
            elif "expected_signature" in extra:
                sig_pat = re.compile(extra["expected_signature"], re.IGNORECASE)
                if sig_pat.search(cleaned_body) and not sig_pat.search(cleaned_baseline):
                    eng_name = probe.engine.value if isinstance(probe.engine, SSTIEngineFamily) else probe.engine
                    return SSTIResult(
                        technique=SSTITechnique.DECISION_TREE_ROUTING.value,
                        engine=str(eng_name),
                        payload=probe.payload,
                        parameter=probe.parameter,
                        parameter_type=probe.parameter_type,
                        target_url=probe.url,
                        status_code=response.status_code,
                        matched_signature=extra.get("discriminator", "decision_tree"),
                        evidence_snippet=f"Disambiguation matched signature for {eng_name}",
                        severity=SSTISeverity.HIGH.value,
                        confidence=0.90,
                        template_id="ssti",
                        cwe_id="CWE-1336",
                        cvss_score=8.2,
                        injected_elapsed=elapsed,
                        baseline_elapsed=baseline_elapsed,
                    )
            elif "expected_canary" in extra:
                canary = extra["expected_canary"]
                if canary in cleaned_body and canary not in cleaned_baseline:
                    eng_name = probe.engine.value if isinstance(probe.engine, SSTIEngineFamily) else probe.engine
                    return SSTIResult(
                        technique=SSTITechnique.DECISION_TREE_ROUTING.value,
                        engine=str(eng_name),
                        payload=probe.payload,
                        parameter=probe.parameter,
                        parameter_type=probe.parameter_type,
                        target_url=probe.url,
                        status_code=response.status_code,
                        matched_signature=extra.get("discriminator", "decision_tree"),
                        evidence_snippet=f"Disambiguation confirmed {eng_name} with canary '{canary}'",
                        severity=SSTISeverity.HIGH.value,
                        confidence=0.90,
                        template_id="ssti",
                        cwe_id="CWE-1336",
                        cvss_score=8.2,
                        injected_elapsed=elapsed,
                        baseline_elapsed=baseline_elapsed,
                    )


        # 3. Check Arithmetic Expression Canary Evaluation
        if probe.expected_canary:
            arith_eval = self.analyze_arithmetic_evaluation(
                cleaned_body,
                probe.expected_canary,
                baseline_body=cleaned_baseline,
                payload=probe.payload,
            )
            if arith_eval:
                eng_name = probe.engine.value if isinstance(probe.engine, SSTIEngineFamily) else probe.engine
                return SSTIResult(
                    technique=SSTITechnique.ARITHMETIC_PROBE.value,
                    engine=str(eng_name),
                    payload=probe.payload,
                    parameter=probe.parameter,
                    parameter_type=probe.parameter_type,
                    target_url=probe.url,
                    status_code=response.status_code,
                    matched_signature=f"canary_evaluation:{probe.expected_canary}",
                    evidence_snippet=arith_eval["snippet"],
                    severity=SSTISeverity.HIGH.value,
                    confidence=arith_eval["confidence"],
                    template_id="ssti",
                    cwe_id="CWE-1336",
                    cvss_score=8.2,
                    mutation_strategy=str(probe.mutation_strategy.value if isinstance(probe.mutation_strategy, SSTIMutationStrategy) else probe.mutation_strategy) if probe.mutation_strategy else None,
                    expected_canary=probe.expected_canary,
                    injected_elapsed=elapsed,
                    baseline_elapsed=baseline_elapsed,
                )

        # 4. Check Blind Time-Based Latency Delay
        if probe.technique == SSTITechnique.BLIND_TIME_BASED:
            threshold = float(probe.extra.get("delay_seconds", 4.0)) if probe.extra else 4.0
            if self.analyze_blind_timing(elapsed, baseline_elapsed, delay_threshold=threshold - 0.5):
                eng_name = probe.engine.value if isinstance(probe.engine, SSTIEngineFamily) else probe.engine
                delta = elapsed - baseline_elapsed
                return SSTIResult(
                    technique=SSTITechnique.BLIND_TIME_BASED.value,
                    engine=str(eng_name),
                    payload=probe.payload,
                    parameter=probe.parameter,
                    parameter_type=probe.parameter_type,
                    target_url=probe.url,
                    status_code=response.status_code,
                    matched_signature=f"blind_time_delay:{delta:.2f}s",
                    evidence_snippet=f"Time delay probe induced {delta:.2f}s latency delta (elapsed={elapsed:.2f}s vs baseline={baseline_elapsed:.2f}s)",
                    severity=SSTISeverity.HIGH.value,
                    confidence=0.90,
                    template_id="ssti_blind",
                    cwe_id="CWE-1336",
                    cvss_score=8.5,
                    delay_delta=delta,
                    injected_elapsed=elapsed,
                    baseline_elapsed=baseline_elapsed,
                )

        # 5. Check Error-Based Engine Fingerprinting
        err_match = self.analyze_error_fingerprint(cleaned_body)
        if err_match:
            return SSTIResult(
                technique=SSTITechnique.ERROR_BASED_FINGERPRINT.value,
                engine=err_match["engine"],
                payload=probe.payload,
                parameter=probe.parameter,
                parameter_type=probe.parameter_type,
                target_url=probe.url,
                status_code=response.status_code,
                matched_signature=err_match["signature"],
                evidence_snippet=err_match["snippet"],
                severity=err_match["severity"].value if isinstance(err_match["severity"], SSTISeverity) else err_match["severity"],
                confidence=err_match["confidence"],
                template_id="ssti_error",
                cwe_id=err_match["cwe_id"],
                cvss_score=err_match["cvss_score"],
                injected_elapsed=elapsed,
                baseline_elapsed=baseline_elapsed,
            )

        return None



# =============================================================================
# SSTI Prober (HTTP Dispatcher)
# =============================================================================

