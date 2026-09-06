"""SQL injection payload generation and mutation."""
from __future__ import annotations

import re
import urllib.parse
from typing import List, Optional, Tuple

from argus.collectors.sql_injection.models import (
    DEFAULT_ERROR_PAYLOADS,
    DEFAULT_BOOLEAN_PAIRS,
    DEFAULT_TIME_PAYLOADS_TEMPLATE,
)


class SQLInjectionPayloadGenerator:
    """
    Generates base payloads and applies 5 WAF bypass mutation strategies
    for error-based, boolean-based, and time-based SQL injection fuzzing.
    """

    SQL_KEYWORDS_PATTERN = re.compile(
        r"\b(SELECT|UNION|WHERE|AND|OR|SLEEP|WAITFOR|DELAY|CONVERT|CAST|FROM|ORDER|BY|HAVING|GROUP|LIMIT|EXEC|EXECUTE|DBMS_PIPE|RECEIVE_MESSAGE|DBMS_LOCK|PG_SLEEP|NULL|VERSION|BANNER|ROWNUM|COUNT|VARCHAR)\b",
        re.IGNORECASE,
    )

    def __init__(
        self,
        custom_error_payloads: Optional[List[str]] = None,
        custom_boolean_pairs: Optional[List[Tuple[str, str]]] = None,
        custom_time_payloads: Optional[List[str]] = None,
    ):
        self.custom_error_payloads = list(custom_error_payloads) if custom_error_payloads is not None else None
        self.custom_boolean_pairs = list(custom_boolean_pairs) if custom_boolean_pairs is not None else None
        self.custom_time_payloads = list(custom_time_payloads) if custom_time_payloads is not None else None

    def generate_error_payloads(self) -> List[str]:
        """Returns base error-based payloads."""
        if self.custom_error_payloads is not None:
            return list(self.custom_error_payloads)
        return list(DEFAULT_ERROR_PAYLOADS)

    def generate_boolean_payload_pairs(self) -> List[Tuple[str, str]]:
        """Returns base boolean TRUE/FALSE payload pairs."""
        if self.custom_boolean_pairs is not None:
            return list(self.custom_boolean_pairs)
        return list(DEFAULT_BOOLEAN_PAIRS)

    def generate_time_payloads(self, delay: int = 5) -> List[str]:
        """Returns base time-delay payloads configured with the given delay in seconds."""
        if self.custom_time_payloads is not None:
            return list(self.custom_time_payloads)
        return [p.format(delay=delay) for p in DEFAULT_TIME_PAYLOADS_TEMPLATE]

    # --- 5 Distinct WAF Bypass Mutation Strategies ---

    def mutate_case_alternation(self, payload: str) -> str:
        """
        Strategy 1: Case Alternation.
        Transforms SQL keyword characters into alternating case (e.g. sElEcT, uNiOn, sLeEp).
        """
        def _alternate(match: re.Match) -> str:
            word = match.group(0)
            chars = []
            for i, c in enumerate(word):
                chars.append(c.lower() if i % 2 == 0 else c.upper())
            return "".join(chars)

        return self.SQL_KEYWORDS_PATTERN.sub(_alternate, payload)

    def mutate_comment_insertion(self, payload: str) -> str:
        """
        Strategy 2: Comment Insertion.
        Inserts inline SQL comments /**/ inside or between keywords (e.g. SEL/**/ECT, UN/**/ION).
        """
        def _comment_inside(match: re.Match) -> str:
            word = match.group(0)
            if len(word) > 2:
                mid = len(word) // 2
                return f"{word[:mid]}/**/{word[mid:]}"
            return word

        return self.SQL_KEYWORDS_PATTERN.sub(_comment_inside, payload)

    def mutate_url_encoding(self, payload: str) -> str:
        """
        Strategy 3: URL Percent Encoding.
        Encodes special characters (', ", space, =, -, #, ;, (, ), ,) into percent format.
        """
        # Encode all non-alphanumeric characters except safe ones
        return urllib.parse.quote(payload, safe="")

    def mutate_double_url_encoding(self, payload: str) -> str:
        """
        Strategy 4: Double URL Percent Encoding.
        Double encodes special characters (e.g. %27 -> %2527) to bypass multi-tier WAF / reverse proxies.
        """
        first_pass = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(first_pass, safe="")

    def mutate_whitespace_substitution(self, payload: str) -> str:
        """
        Strategy 5: Whitespace Substitution.
        Replaces standard spaces with SQL-compatible alternatives (e.g. tab %09 or inline comments /**/).
        """
        if " " in payload:
            return payload.replace(" ", "%09")
        return payload

    def mutate_waf_bypass(self, payload: str) -> List[str]:
        """
        Applies all 5 WAF bypass mutation strategies to generate a unique list of variants.
        """
        variants: List[str] = [
            self.mutate_case_alternation(payload),
            self.mutate_comment_insertion(payload),
            self.mutate_url_encoding(payload),
            self.mutate_double_url_encoding(payload),
            self.mutate_whitespace_substitution(payload),
            payload.replace(" ", "/**/"),
            payload.replace(" ", "%0a"),
            payload.replace(" ", "+"),
        ]
        # Preserve order and deduplicate
        seen = set()
        unique_variants = []
        for v in variants:
            if v and v != payload and v not in seen:
                seen.add(v)
                unique_variants.append(v)
        return unique_variants

