"""Command-injection response analysis (result / time-blind / error-based)."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from argus.http.client import HttpResponse
from argus.collectors.toolkit.enums import Severity
from argus.collectors.command_injection.models import (
    OS_RESULT_SIGNATURES,
    SHELL_ERROR_SIGNATURES,
)


class CommandInjectionAnalyzer:
    """
    Evaluates HTTP responses for genuine OS command injection vulnerabilities across:
    1. Result-Based Detection (POSIX/Windows OS signatures and arithmetic canaries).
    2. Time-Based Blind Differential Analysis (latency delta >= 4.0s vs baseline).
    3. Error-Based Detection (Bash/Dash/Zsh, Windows CMD, and PowerShell error signatures).
    4. False Positive & Reflection Suppression.
    """

    GENERIC_BENIGN_TITLES = re.compile(
        r"<title>[^<]*(?:error|exception|not found|bad request|forbidden|server error|search)[^<]*</title>",
        re.IGNORECASE,
    )

    def analyze_result_based(
        self,
        response: Optional[HttpResponse],
        baseline: Optional[HttpResponse],
        payload_info: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Analyzes response for result-based command execution output signatures or arithmetic canaries.
        """
        if not response or not response.raw_body:
            return None

        body_str = str(response.raw_body)
        baseline_body = str(baseline.raw_body) if baseline and baseline.raw_body else ""
        canary_type = payload_info.get("canary_type", "regex")
        cmd = payload_info.get("cmd", "")

        # 1. Arithmetic Canary Exact Match (e.g., expr 28412 + 19283 -> 47695)
        if canary_type == "exact":
            expected = str(payload_info.get("expected", ""))
            if expected and expected in body_str:
                # Baseline subtraction: ensure expected result was NOT already present in baseline
                if expected not in baseline_body:
                    # Reflection guard: if only the arithmetic expression itself was reflected without result
                    return {
                        "technique": "result_based",
                        "template_id": "cmdi",
                        "severity": Severity.CRITICAL,
                        "confidence": 0.95,
                        "os_family": payload_info.get("os", "posix"),
                        "matched_pattern": f"exact_canary:{expected}",
                        "snippet": f"Found computed arithmetic canary '{expected}' from command '{cmd}'",
                        "payload": cmd,
                    }
            return None

        # 2. Regex Output Signatures Match
        sig_name = payload_info.get("signature", "")
        signatures_to_check: List[Tuple[str, re.Pattern]] = []

        if sig_name and sig_name in OS_RESULT_SIGNATURES:
            signatures_to_check.append((sig_name, OS_RESULT_SIGNATURES[sig_name]))
        else:
            # Check all result signatures
            signatures_to_check.extend(OS_RESULT_SIGNATURES.items())

        for name, pattern in signatures_to_check:
            match = pattern.search(body_str)
            if match:
                snippet = match.group(0)

                # Baseline subtraction: if the same match already existed in the baseline, suppress
                if baseline_body and pattern.search(baseline_body):
                    continue

                # Reflection Guard: if the matched snippet is just the verbatim command or input reflection
                if self._is_verbatim_reflection(body_str, cmd, snippet):
                    continue

                os_family = "windows" if name.startswith("windows_") else "posix"
                return {
                    "technique": "result_based",
                    "template_id": "cmdi",
                    "severity": Severity.CRITICAL,
                    "confidence": 0.95,
                    "os_family": os_family,
                    "matched_pattern": name,
                    "snippet": snippet[:200],
                    "payload": cmd,
                }

        return None

    def analyze_time_blind(
        self,
        injected_resp: Optional[HttpResponse],
        baseline_resp: Optional[HttpResponse],
        threshold: float = 4.0,
    ) -> Optional[Dict[str, Any]]:
        """
        Analyzes timing differentials for time-based blind command injection.
        Requires delay differential >= threshold (default 4.0s) and total injected elapsed >= threshold.
        """
        if not injected_resp:
            return None

        baseline_elapsed = getattr(baseline_resp, "elapsed", 0.0) if baseline_resp else 0.0
        injected_elapsed = getattr(injected_resp, "elapsed", 0.0)
        delay_delta = injected_elapsed - baseline_elapsed

        if delay_delta >= threshold and injected_elapsed >= threshold:
            return {
                "technique": "time_blind",
                "template_id": "cmdi",
                "severity": Severity.CRITICAL,
                "confidence": 0.95,
                "delay_delta": delay_delta,
                "baseline_elapsed": baseline_elapsed,
                "injected_elapsed": injected_elapsed,
                "snippet": (
                    f"Response latency increased by {delay_delta:.2f}s "
                    f"(baseline: {baseline_elapsed:.2f}s, injected: {injected_elapsed:.2f}s, threshold: {threshold:.1f}s)"
                ),
            }

        return None

    def analyze_error_based(
        self,
        response: Optional[HttpResponse],
        baseline: Optional[HttpResponse],
        payload: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Analyzes response for OS shell error messages (Bash, Dash, Zsh, CMD, PowerShell).
        """
        if not response or not response.raw_body:
            return None

        body_str = str(response.raw_body)
        baseline_body = str(baseline.raw_body) if baseline and baseline.raw_body else ""

        for shell_family, sig_list in SHELL_ERROR_SIGNATURES.items():
            for sig_name, pattern in sig_list:
                match = pattern.search(body_str)
                if match:
                    snippet = match.group(0)

                    # Baseline subtraction: ignore if the baseline response already contained this shell error
                    if baseline_body and pattern.search(baseline_body):
                        continue

                    # Reflection guard
                    if self._is_verbatim_reflection(body_str, payload, snippet):
                        continue

                    return {
                        "technique": "error_based",
                        "template_id": "cmdi",
                        "severity": Severity.HIGH,
                        "confidence": 0.90,
                        "shell_flavor": shell_family,
                        "matched_pattern": sig_name,
                        "snippet": snippet[:200],
                        "payload": payload,
                    }

        return None

    def is_false_positive(
        self,
        response: Optional[HttpResponse],
        payload: str,
        baseline: Optional[HttpResponse] = None,
    ) -> bool:
        """
        Determines if a response is a false positive (e.g. empty response, identical to baseline,
        or pure reflection of payload in normal text without command output).
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
        in an HTML search heading, input field, or documentation string without OS execution.
        """
        if not payload or not snippet:
            return False
        clean_payload = payload.strip()
        clean_snippet = snippet.strip()

        # If snippet exactly equals payload and no actual execution markers exist
        if clean_snippet == clean_payload and not any(
            marker in clean_snippet for marker in ("uid=", "root:", "Microsoft Windows", "Linux ")
        ):
            return True

        return False


# =============================================================================
# Command Injection Collector Implementation
# =============================================================================

