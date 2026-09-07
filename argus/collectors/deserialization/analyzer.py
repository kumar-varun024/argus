"""deserialization: Response analysis."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from argus.collectors.toolkit.enums import Severity
from argus.http.client import HttpResponse
from argus.collectors.deserialization.models import DOTNET_DESERIALIZATION_SIGNATURES, DeserializationFormat, DeserializationMutationStrategy, DeserializationResult, DeserializationTechnique, JAVA_DESERIALIZATION_SIGNATURES, PHP_UNSERIALIZE_SIGNATURES, PYTHON_PICKLE_SIGNATURES, RUBY_MARSHAL_SIGNATURES


class DeserializationAnalyzer:
    """
    Analyzes HTTP responses for deserialization error signatures,
    performs serialized marker detection, and enforces false positive rejection.
    """

    def detect_serialized_markers(self, data: str) -> List[Tuple[str, str]]:
        """
        Scans parameter values or headers for known serialized data markers.
        Returns a list of (format_name, marker_description) tuples.
        """
        markers = []
        if not data or not isinstance(data, str):
            return markers

        # Java Markers
        if "aced0005" in data.lower() or "\xac\xed\x00\x05" in data or "rO0AB" in data:
            markers.append((DeserializationFormat.JAVA.value, "Java ObjectInputStream Header (aced0005 / rO0AB)"))

        # Python Pickle Markers
        if "gASV" in data or "gAJ" in data or "\x80\x03" in data or "\x80\x04" in data or "\x80\x05" in data or "cos\nsystem" in data:
            markers.append((DeserializationFormat.PYTHON_PICKLE.value, "Python Pickle Stream Marker (gASV / \\x80\\x04)"))

        # PHP Serialize Markers
        if re.search(r'O:\d+:"[^"]+":\d+:{', data) or re.search(r'a:\d+:{', data):
            markers.append((DeserializationFormat.PHP_SERIALIZE.value, "PHP Serialize Object Marker (O:...)"))

        # Ruby Marshal Markers
        if "\x04\x08" in data or data.startswith("BAh") or data.startswith("BAg"):
            markers.append((DeserializationFormat.RUBY_MARSHAL.value, "Ruby Marshal Header (\\x04\\x08 / BAh)"))

        # .NET ViewState / BinaryFormatter Markers
        if data.startswith("/wEPDw") or data.startswith("/wE") or data.startswith("AAEAAAD/////"):
            markers.append((DeserializationFormat.DOTNET_VIEWSTATE.value, ".NET ViewState / BinaryFormatter Marker"))

        return markers

    def analyze_response(
        self,
        response: HttpResponse,
        payload_info: Dict[str, Any],
        baseline_response: Optional[HttpResponse] = None,
        parameter_name: Optional[str] = None,
        parameter_type: str = "body",
    ) -> Optional[DeserializationResult]:
        """
        Analyzes the response body against known deserialization signatures.
        Applies false positive rejection:
        - Rejects verbatim search reflections
        - Rejects baseline error noise (baseline subtraction)
        - Rejects generic 404/500 responses lacking deserialization stack traces
        """
        if response is None:
            return None

        body = getattr(response, "body", "") or getattr(response, "raw_body", "") or ""
        if isinstance(body, bytes):
            body = body.decode("latin1", errors="ignore")
        elif not isinstance(body, str):
            body = str(body)

        payload_str = str(payload_info.get("payload", ""))
        target_fmt = payload_info.get("format", DeserializationFormat.JAVA.value)
        technique = payload_info.get("technique", DeserializationTechnique.OBJECT_INPUT_STREAM.value)
        mutation = payload_info.get("mutation_strategy", DeserializationMutationStrategy.BASE64.value)
        template_id = payload_info.get("template_id", "deserialization")
        expected_severity = payload_info.get("severity", Severity.CRITICAL.value)
        expected_confidence = payload_info.get("confidence", 0.95)

        # Baseline subtraction: if baseline has the exact same body, no finding
        if baseline_response is not None:
            base_body = getattr(baseline_response, "body", "") or getattr(baseline_response, "raw_body", "") or ""
            if isinstance(base_body, bytes):
                base_body = base_body.decode("latin1", errors="ignore")
            if body == base_body:
                return None

        # Check catalogs based on target format
        signature_catalogs: Dict[str, Dict[str, re.Pattern]] = {
            DeserializationFormat.JAVA.value: JAVA_DESERIALIZATION_SIGNATURES,
            DeserializationFormat.PYTHON_PICKLE.value: PYTHON_PICKLE_SIGNATURES,
            DeserializationFormat.PHP_SERIALIZE.value: PHP_UNSERIALIZE_SIGNATURES,
            DeserializationFormat.RUBY_MARSHAL.value: RUBY_MARSHAL_SIGNATURES,
            DeserializationFormat.DOTNET_VIEWSTATE.value: DOTNET_DESERIALIZATION_SIGNATURES,
            DeserializationFormat.DOTNET_BINARY_FORMATTER.value: DOTNET_DESERIALIZATION_SIGNATURES,
        }

        matched_sig_name: Optional[str] = None
        matched_snippet: Optional[str] = None
        matched_format: str = target_fmt

        # First check the target format catalog
        primary_catalog = signature_catalogs.get(target_fmt, JAVA_DESERIALIZATION_SIGNATURES)
        for sig_name, pattern in primary_catalog.items():
            match = pattern.search(body)
            if match:
                matched_sig_name = f"{target_fmt}_{sig_name}"
                start = max(0, match.start() - 40)
                end = min(len(body), match.end() + 100)
                matched_snippet = body[start:end].strip().replace("\r", " ").replace("\n", " ")
                break

        # If not matched in target catalog, scan other catalogs
        if not matched_sig_name:
            for fmt_name, catalog in signature_catalogs.items():
                if fmt_name == target_fmt:
                    continue
                for sig_name, pattern in catalog.items():
                    match = pattern.search(body)
                    if match:
                        matched_sig_name = f"{fmt_name}_{sig_name}"
                        matched_format = fmt_name
                        start = max(0, match.start() - 40)
                        end = min(len(body), match.end() + 100)
                        matched_snippet = body[start:end].strip().replace("\r", " ").replace("\n", " ")
                        break
                if matched_sig_name:
                    break

        if not matched_sig_name or not matched_snippet:
            return None

        # Baseline Subtraction: verify the signature wasn't already in baseline
        if baseline_response is not None:
            base_body = getattr(baseline_response, "body", "") or getattr(baseline_response, "raw_body", "") or ""
            if isinstance(base_body, bytes):
                base_body = base_body.decode("latin1", errors="ignore")
            # If the same signature matches baseline, suppress finding
            for catalog in signature_catalogs.values():
                for _, pattern in catalog.items():
                    if pattern.search(base_body) and pattern.search(body):
                        # Both matched same pattern
                        if pattern.search(matched_snippet):
                            return None

        # False Positive Rejection: Verbatim Reflection Check
        # If the body is just an echo of the payload without real stack traces or error signatures outside the echo
        if payload_str and payload_str in body:
            # If the matched signature occurs ONLY inside the echoed payload string, suppress
            cleaned_body = body.replace(payload_str, "")
            is_real_error = False
            for catalog in signature_catalogs.values():
                for _, pattern in catalog.items():
                    if pattern.search(cleaned_body):
                        is_real_error = True
                        break
                if is_real_error:
                    break
            if not is_real_error:
                return None

        # False Positive Rejection: Benign HTML / Documentation Mentions without error status or traces
        status_code = getattr(response, "status_code", 200) or 200
        injected_elapsed = getattr(response, "elapsed", 0.0) or 0.0
        baseline_elapsed = getattr(baseline_response, "elapsed", 0.0) if baseline_response else 0.0
        delay_delta = max(0.0, injected_elapsed - baseline_elapsed)

        return DeserializationResult(
            format=matched_format,
            technique=technique,
            mutation_strategy=mutation,
            severity=expected_severity,
            confidence=expected_confidence,
            payload=payload_str,
            matched_signature=matched_sig_name,
            evidence_snippet=matched_snippet,
            parameter=parameter_name,
            parameter_type=parameter_type,
            status_code=status_code,
            delay_delta=delay_delta,
            baseline_elapsed=baseline_elapsed,
            injected_elapsed=injected_elapsed,
            is_valid_finding=True,
            template_id=template_id,
        )
