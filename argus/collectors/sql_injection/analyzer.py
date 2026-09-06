"""SQL injection response analysis (error / boolean-blind / time-blind)."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from argus.http.client import HttpResponse
from argus.collectors.sql_injection.models import DBMS_ERROR_SIGNATURES


class SQLInjectionAnalyzer:
    """
    Evaluates HTTP responses for genuine SQL injection vulnerabilities across:
    1. Error-Based Detection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite).
    2. Boolean-Based Blind Differential Analysis (TRUE vs FALSE length/content).
    3. Time-Based Blind Delay Measurement (delta >= 4.0s vs baseline).
    4. False Positive & Reflection Suppression.
    """

    GENERIC_ERROR_TITLES = re.compile(
        r"<title>[^<]*(?:error|exception|not found|bad request|forbidden|server error)[^<]*</title>",
        re.IGNORECASE,
    )

    def is_false_positive(self, response: HttpResponse, payload: str) -> bool:
        """
        Determines if a response is a false positive (e.g. generic application error
        or plain reflection of payload text without database error execution).
        """
        if not response or not response.raw_body:
            return True

        body_str = str(response.raw_body)
        clean_payload = str(payload).strip()

        # If the body is very small or empty
        if len(body_str.strip()) < 5:
            return True

        # If payload is reflected in an HTML title or search query echo, check if there is an actual DBMS error
        has_dbms_sig = False
        for dbms, sigs in DBMS_ERROR_SIGNATURES.items():
            for _, pattern in sigs:
                if pattern.search(body_str):
                    has_dbms_sig = True
                    break
            if has_dbms_sig:
                break

        # If no DBMS signature matched, and it's just generic error words or query reflection
        if not has_dbms_sig:
            if clean_payload and clean_payload in body_str:
                return True
            # Check for generic error words without DB context
            if any(w in body_str.lower() for w in ["error", "syntax", "sql", "database"]):
                # Generic application error without DBMS syntax signature is a false positive
                return True

        # Reflection discard: if matched text is only found inside the literal echoed payload
        if clean_payload and clean_payload in body_str:
            # Check if any DBMS error occurs OUTSIDE the reflected payload span
            payload_occurrences = [m.start() for m in re.finditer(re.escape(clean_payload), body_str)]
            error_outside_reflection = False
            for dbms, sigs in DBMS_ERROR_SIGNATURES.items():
                for _, pattern in sigs:
                    for match in pattern.finditer(body_str):
                        m_start = match.start()
                        m_end = match.end()
                        inside_reflection = any(p_start <= m_start and m_end <= (p_start + len(clean_payload)) for p_start in payload_occurrences)
                        if not inside_reflection:
                            error_outside_reflection = True
                            break
                    if error_outside_reflection:
                        break
                if error_outside_reflection:
                    break

            if not error_outside_reflection and has_dbms_sig:
                # The signature occurred only inside the reflected user input
                return True

        return False

    def analyze_error_based(
        self,
        response: HttpResponse,
        baseline: Optional[HttpResponse] = None,
        payload: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates response body for DBMS-specific syntax error signatures.
        Returns match metadata dictionary if genuine error-based SQLi is confirmed, else None.
        """
        if not response:
            return None

        body_str = getattr(response, "raw_body", None) or getattr(response, "body", "") or ""
        if not body_str or len(body_str.strip()) < 5:
            return None

        baseline_body = ""
        if baseline:
            baseline_body = getattr(baseline, "raw_body", None) or getattr(baseline, "body", "") or ""

        # Check all DBMS signature catalogs
        for dbms, sigs in DBMS_ERROR_SIGNATURES.items():
            for sig_name, pattern in sigs:
                match = pattern.search(body_str)
                if not match:
                    continue

                # Baseline differential check: if the baseline already contained this exact DBMS error, ignore
                if baseline_body and pattern.search(baseline_body):
                    continue

                matched_text = match.group(0)

                # Reflection Guard: if matched text is just an echo of the injected payload string
                clean_payload = payload.strip()
                if clean_payload and clean_payload in body_str:
                    if matched_text in clean_payload and len(matched_text) < len(clean_payload):
                        # Verify whether error occurs outside the payload string reflection
                        if self.is_false_positive(response, payload):
                            continue

                # Extract context snippet around match
                start_pos = max(0, match.start() - 30)
                end_pos = min(len(body_str), match.end() + 100)
                snippet = body_str[start_pos:end_pos].strip()

                template_id = f"sqli-error-{dbms}"

                return {
                    "technique": "error_based",
                    "dbms": dbms,
                    "matched_signature": sig_name,
                    "matched_text": matched_text,
                    "snippet": snippet,
                    "template_id": template_id,
                    "severity": "critical",
                    "confidence": 0.95,
                }

        return None

    def analyze_boolean_blind(
        self,
        true_resp: HttpResponse,
        false_resp: HttpResponse,
        baseline: Optional[HttpResponse] = None,
        true_payload: str = "",
        false_payload: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Performs differential analysis between TRUE and FALSE payload responses.
        Returns match metadata if differential behavior indicates SQL injection.
        """
        if not true_resp or not false_resp:
            return None

        true_status = getattr(true_resp, "status_code", None)
        false_status = getattr(false_resp, "status_code", None)

        true_body = getattr(true_resp, "raw_body", None) or getattr(true_resp, "body", "") or ""
        false_body = getattr(false_resp, "raw_body", None) or getattr(false_resp, "body", "") or ""

        len_true = len(true_body)
        len_false = len(false_body)
        len_delta = abs(len_true - len_false)

        baseline_status = getattr(baseline, "status_code", None) if baseline else None
        baseline_body = (getattr(baseline, "raw_body", None) or getattr(baseline, "body", "") or "") if baseline else ""
        len_baseline = len(baseline_body)

        # 1. Status Code Differential:
        # TRUE returns 200 OK (or baseline status), FALSE returns 404, 500, 400, 403, 302
        if true_status is not None and false_status is not None:
            if true_status != false_status:
                # Confirm TRUE aligns with normal behavior (2xx or baseline) while FALSE deviates
                if (true_status == 200 or (baseline_status and true_status == baseline_status)) and false_status in (404, 500, 400, 403, 302, 422):
                    return {
                        "technique": "boolean_blind",
                        "subtype": "status_code_differential",
                        "true_status": true_status,
                        "false_status": false_status,
                        "true_length": len_true,
                        "false_length": len_false,
                        "length_delta": len_delta,
                        "template_id": "sqli-boolean-blind",
                        "severity": "high",
                        "confidence": 0.90,
                        "snippet": f"Status differential: TRUE={true_status} vs FALSE={false_status}",
                    }

        # 2. Content Length Differential Analysis:
        # Require meaningful byte delta (> 25 bytes or > 10% delta) and stability with baseline if available
        min_delta_threshold = 25

        if len_delta >= min_delta_threshold:
            # Check noise tolerance: if baseline is present, TRUE should resemble baseline more than FALSE
            if baseline and len_baseline > 0:
                delta_true_base = abs(len_true - len_baseline)
                delta_false_base = abs(len_false - len_baseline)

                # If TRUE response is close to baseline and FALSE diverges significantly
                if delta_false_base >= min_delta_threshold and delta_true_base < delta_false_base:
                    return {
                        "technique": "boolean_blind",
                        "subtype": "length_differential",
                        "true_status": true_status or 200,
                        "false_status": false_status or 200,
                        "true_length": len_true,
                        "false_length": len_false,
                        "length_delta": len_delta,
                        "template_id": "sqli-boolean-blind",
                        "severity": "high",
                        "confidence": 0.90,
                        "snippet": f"Differential length: TRUE={len_true} bytes, FALSE={len_false} bytes (delta={len_delta})",
                    }
            else:
                # Without baseline, significant difference between TRUE and FALSE with 2xx status codes
                if true_status == 200 and false_status == 200:
                    return {
                        "technique": "boolean_blind",
                        "subtype": "length_differential",
                        "true_status": true_status,
                        "false_status": false_status,
                        "true_length": len_true,
                        "false_length": len_false,
                        "length_delta": len_delta,
                        "template_id": "sqli-boolean-blind",
                        "severity": "high",
                        "confidence": 0.85,
                        "snippet": f"Differential length: TRUE={len_true} bytes, FALSE={len_false} bytes (delta={len_delta})",
                    }

        return None

    def analyze_time_blind(
        self,
        injected_resp: HttpResponse,
        baseline_elapsed: float,
        threshold: float = 4.0,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates request latency against baseline request timing.
        Returns match metadata if injected latency exceeds baseline by threshold (default >= 4.0s).
        """
        if not injected_resp:
            return None

        injected_elapsed = getattr(injected_resp, "elapsed", 0.0) or 0.0
        base_elapsed = max(0.0, float(baseline_elapsed or 0.0))
        delay_delta = injected_elapsed - base_elapsed

        # Confirm that injected request took at least threshold seconds longer than baseline,
        # and total injected elapsed time is at least threshold seconds
        if delay_delta >= threshold and injected_elapsed >= threshold:
            return {
                "technique": "time_blind",
                "injected_elapsed": round(injected_elapsed, 3),
                "baseline_elapsed": round(base_elapsed, 3),
                "delay_delta": round(delay_delta, 3),
                "template_id": "sqli-time-blind",
                "severity": "critical",
                "confidence": 0.95,
                "snippet": f"Time delay confirmed: elapsed={injected_elapsed:.2f}s, baseline={base_elapsed:.2f}s (delta={delay_delta:.2f}s >= {threshold}s)",
            }

        return None

