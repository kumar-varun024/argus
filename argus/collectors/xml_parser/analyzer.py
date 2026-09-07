"""xml_parser: Response analysis."""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from argus.http.client import HttpResponse
from argus.collectors.xml_parser.models import PARSER_ERROR_SIGNATURES, TARGET_FILE_SIGNATURES, XMLMutationStrategy, XMLTechnique, XMLValidationResult
from argus.collectors.xml_parser.payloads import XMLPayloadGenerator

logger = logging.getLogger(__name__)


class XMLParserAnalyzer:
    """
    Analyzes HTTP responses to detect genuine XML parser misconfigurations while
    eliminating false positives via baseline subtraction and echo guards.
    """

    LATENCY_THRESHOLD_SECONDS = 3.0
    LATENCY_FACTOR = 3.0

    def __init__(self):
        self.file_signatures = dict(TARGET_FILE_SIGNATURES)
        self.error_signatures = dict(PARSER_ERROR_SIGNATURES)

    def analyze_response(
        self,
        response: Optional[HttpResponse],
        payload_info: Dict[str, Any],
        baseline_response: Optional[HttpResponse] = None,
    ) -> Optional[XMLValidationResult]:
        """
        Analyzes response against expected vulnerability patterns and baseline.
        Returns XMLValidationResult on positive detection, None on benign/clean response.
        """
        if response is None:
            return None

        body = response.body or response.raw_body or ""
        status_code = response.status_code or 0
        elapsed = getattr(response, "elapsed", 0.0) or 0.0

        baseline_body = ""
        baseline_elapsed = 0.0
        if baseline_response is not None:
            baseline_body = baseline_response.body or baseline_response.raw_body or ""
            baseline_elapsed = getattr(baseline_response, "elapsed", 0.0) or 0.0

        technique = payload_info.get("technique", XMLTechnique.ENTITY_RESOLUTION.value)
        mutation = payload_info.get("mutation_strategy", XMLMutationStrategy.DOCTYPE_SYSTEM.value)
        target_file = payload_info.get("target_file", "")
        file_type = payload_info.get("file_type", "")
        payload_text = payload_info.get("payload", "")
        template_id = payload_info.get("template_id", "xxe")

        # Guard 1: Echo Guard — check if the response merely echoed the entity unexpanded
        # or echoed the exact payload text without resolution
        if self._is_unexpanded_reflection(body, payload_text):
            logger.debug("Echo guard triggered: Unexpanded reflection detected. Suppressing finding.")
            return None

        # 1. Check Reflected Entity Resolution / XInclude File Contents
        if technique in (XMLTechnique.ENTITY_RESOLUTION.value, XMLTechnique.XINCLUDE.value):
            # Canary Token Check
            if file_type == "canary" and XMLPayloadGenerator.CANARY_TOKEN in body:
                if XMLPayloadGenerator.CANARY_TOKEN not in baseline_body:
                    snippet = self._extract_snippet(body, XMLPayloadGenerator.CANARY_TOKEN)
                    return XMLValidationResult(
                        technique=technique,
                        mutation_strategy=mutation,
                        severity="critical",
                        confidence=0.95,
                        payload=payload_text,
                        matched_signature="canary_token",
                        evidence_snippet=snippet,
                        target_file="canary_token",
                        status_code=status_code,
                        baseline_elapsed=baseline_elapsed,
                        injected_elapsed=elapsed,
                        template_id=template_id,
                    )

            # Specific File Signature Check
            if file_type in self.file_signatures:
                pattern = self.file_signatures[file_type]
                match = pattern.search(body)
                if match:
                    matched_str = match.group(0)
                    # Baseline Subtraction: Ensure signature is NOT in clean baseline response
                    if not pattern.search(baseline_body):
                        # Ensure matched string is not just payload literal
                        if matched_str not in payload_text or file_type == "unix_hostname":
                            snippet = self._extract_snippet(body, matched_str)
                            return XMLValidationResult(
                                technique=technique,
                                mutation_strategy=mutation,
                                severity="critical",
                                confidence=0.95,
                                payload=payload_text,
                                matched_signature=file_type,
                                evidence_snippet=snippet,
                                target_file=target_file,
                                status_code=status_code,
                                baseline_elapsed=baseline_elapsed,
                                injected_elapsed=elapsed,
                                template_id=template_id,
                            )

            # Generic check across all known file signatures
            for sig_name, pattern in self.file_signatures.items():
                if sig_name == file_type:
                    continue
                match = pattern.search(body)
                if match and not pattern.search(baseline_body):
                    matched_str = match.group(0)
                    if matched_str not in payload_text:
                        snippet = self._extract_snippet(body, matched_str)
                        return XMLValidationResult(
                            technique=technique,
                            mutation_strategy=mutation,
                            severity="critical",
                            confidence=0.95,
                            payload=payload_text,
                            matched_signature=sig_name,
                            evidence_snippet=snippet,
                            target_file=target_file,
                            status_code=status_code,
                            baseline_elapsed=baseline_elapsed,
                            injected_elapsed=elapsed,
                            template_id=template_id,
                        )

        # 2. Check Parameter Entity / Error-Based File Leaks
        if technique == XMLTechnique.PARAMETER_ENTITY.value:
            # Check for error leaks containing target file content or path
            file_error_match = self.error_signatures["java_file_not_found_entity"].search(body)
            if file_error_match and not self.error_signatures["java_file_not_found_entity"].search(baseline_body):
                snippet = self._extract_snippet(body, file_error_match.group(0))
                return XMLValidationResult(
                    technique=technique,
                    mutation_strategy=mutation,
                    severity="critical" if ("/etc/" in snippet or "win.ini" in snippet) else "high",
                    confidence=0.95 if ("/etc/" in snippet or "win.ini" in snippet) else 0.85,
                    payload=payload_text,
                    matched_signature="parameter_entity_error_leak",
                    evidence_snippet=snippet,
                    target_file=target_file,
                    status_code=status_code,
                    baseline_elapsed=baseline_elapsed,
                    injected_elapsed=elapsed,
                    template_id=template_id,
                )

            # Check for file signatures inside error or body
            for sig_name, pattern in self.file_signatures.items():
                match = pattern.search(body)
                if match and not pattern.search(baseline_body):
                    matched_str = match.group(0)
                    if matched_str not in payload_text:
                        snippet = self._extract_snippet(body, matched_str)
                        return XMLValidationResult(
                            technique=technique,
                            mutation_strategy=mutation,
                            severity="critical",
                            confidence=0.95,
                            payload=payload_text,
                            matched_signature=f"parameter_entity_{sig_name}",
                            evidence_snippet=snippet,
                            target_file=target_file,
                            status_code=status_code,
                            baseline_elapsed=baseline_elapsed,
                            injected_elapsed=elapsed,
                            template_id=template_id,
                        )

            # DTD parsing confirmed signature
            libxml2_ext = self.error_signatures["libxml2_external_entity_error"].search(body)
            if libxml2_ext and not self.error_signatures["libxml2_external_entity_error"].search(baseline_body):
                snippet = self._extract_snippet(body, libxml2_ext.group(0))
                return XMLValidationResult(
                    technique=technique,
                    mutation_strategy=mutation,
                    severity="high",
                    confidence=0.85,
                    payload=payload_text,
                    matched_signature="libxml2_external_entity_error",
                    evidence_snippet=snippet,
                    target_file=target_file,
                    status_code=status_code,
                    baseline_elapsed=baseline_elapsed,
                    injected_elapsed=elapsed,
                    template_id=template_id,
                )

        # 3. Check Recursive Entity Expansion (Billion Laughs / Quadratic)
        if technique == XMLTechnique.RECURSIVE_ENTITY.value:
            delay_delta = elapsed - baseline_elapsed
            # Indicator A: Latency differential >= 3.0s and abnormal multiplier
            if elapsed >= self.LATENCY_THRESHOLD_SECONDS and (
                baseline_elapsed == 0.0 or elapsed >= (baseline_elapsed * self.LATENCY_FACTOR + 1.5)
            ):
                return XMLValidationResult(
                    technique=technique,
                    mutation_strategy=mutation,
                    severity="high",
                    confidence=0.85,
                    payload=payload_text,
                    matched_signature="latency_differential_delay",
                    evidence_snippet=f"Latency: {elapsed:.2f}s (baseline: {baseline_elapsed:.2f}s, delta: {delay_delta:.2f}s)",
                    target_file="recursive_expansion",
                    status_code=status_code,
                    delay_delta=delay_delta,
                    baseline_elapsed=baseline_elapsed,
                    injected_elapsed=elapsed,
                    template_id=template_id,
                )

            # Indicator B: Parser Expansion Limit Error Signatures
            for sig_name, pattern in self.error_signatures.items():
                if "limit" in sig_name or "amplification" in sig_name or "max_chars" in sig_name:
                    match = pattern.search(body)
                    if match and not pattern.search(baseline_body):
                        matched_str = match.group(0)
                        snippet = self._extract_snippet(body, matched_str)
                        return XMLValidationResult(
                            technique=technique,
                            mutation_strategy=mutation,
                            severity="medium",
                            confidence=0.80,
                            payload=payload_text,
                            matched_signature=sig_name,
                            evidence_snippet=snippet,
                            target_file="recursive_expansion",
                            status_code=status_code,
                            baseline_elapsed=baseline_elapsed,
                            injected_elapsed=elapsed,
                            template_id=template_id,
                        )

            # Indicator C: Full expansion reflection (Billion laughs token multiplied)
            if "argus_laugh_token_0123456789" in body and body.count("argus_laugh_token_0123456789") > 5:
                if baseline_body.count("argus_laugh_token_0123456789") == 0:
                    snippet = self._extract_snippet(body, "argus_laugh_token_0123456789")
                    return XMLValidationResult(
                        technique=technique,
                        mutation_strategy=mutation,
                        severity="high",
                        confidence=0.90,
                        payload=payload_text,
                        matched_signature="recursive_expansion_reflected",
                        evidence_snippet=snippet,
                        target_file="recursive_expansion",
                        status_code=status_code,
                        baseline_elapsed=baseline_elapsed,
                        injected_elapsed=elapsed,
                        template_id=template_id,
                    )

        return None

    def _is_unexpanded_reflection(self, body: str, payload: str) -> bool:
        """
        Determines whether the server merely echoed the raw unparsed XML markup
        or entity literal (e.g. &xxe; or &all; or <!DOCTYPE...) without resolving it.
        """
        if not body or not payload:
            return False

        # If &xxe; is in body and no target file was resolved, it's literal reflection
        if "&xxe;" in body and not any(sig.search(body) for sig in self.file_signatures.values()):
            # If the body contains literal &xxe; and nothing else from the file
            return True

        if "&all;" in body and not self.file_signatures["unix_passwd"].search(body):
            return True

        if "&lol4;" in body and "argus_laugh_token_0123456789" not in body:
            return True

        # Check if entire payload was verbatim echoed
        if len(payload) > 30 and payload.strip() in body:
            return True

        return False

    def _extract_snippet(self, body: str, match_term: str, window: int = 120) -> str:
        """Extracts a surrounding contextual snippet around the matched term."""
        idx = body.find(match_term)
        if idx == -1:
            return body[:window].strip()
        start = max(0, idx - 40)
        end = min(len(body), idx + len(match_term) + 80)
        return body[start:end].replace("\r", " ").replace("\n", " ").strip()
