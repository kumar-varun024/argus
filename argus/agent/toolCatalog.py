"""Tool allowlist + argument policy for the gated command executor.

The agent may only run tools defined here, only with flags on each tool's
allowlist, and never with a shell metacharacter or a destructive/evasion token
in any argument. Unknown tool, unknown flag, or a suspicious token -> rejected.
This is a pure, deterministic module (no I/O, no model) so it can be exhaustively
unit-tested; it is the first half of the command gate (scope is the second).

Expanding coverage is a data change: add a ToolSpec to ALLOWED_TOOLS.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Tuple, FrozenSet

# Any argument containing one of these is rejected outright -- they enable shell
# chaining, redirection, command substitution, or newline injection. Args are
# passed to the sandbox as an argv list (never a shell string), but we reject
# them anyway as defence in depth and to keep audit logs clean.
METACHAR_PATTERN = re.compile(r"[;&|`$><\n\r\\!(){}]")
COMMAND_SUB_TOKENS: Tuple[str, ...] = ("$(", "${", "`")

# Substrings (case-insensitive) that indicate a destructive, evasive, or
# system-altering intent regardless of tool. Rejected in any argument.
DENY_SUBSTRINGS: Tuple[str, ...] = (
    "rm ", "rmdir", "mkfs", "dd ", "sudo", "chmod", "chown", "passwd",
    "/etc/", "/dev/", "/proc/", "/root", "..", "~/", ".ssh", "id_rsa",
    "nc -e", "ncat -e", "bash -i", "sh -i", "/bin/sh", "/bin/bash",
    "curl", "wget", "| sh", "|sh", "apt", "yum", "pip install", "npm i",
    "reverse", "meterpreter", "/shadow",
)

# IPv4/CIDR, http(s) URL, and bare hostname -- used to identify which bare
# (non-flag) arguments are targets that must be scope-checked.
_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,2})?$")
_URL = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)
_HOST = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)


@dataclass(frozen=True)
class ToolSpec:
    """One allowlisted tool. allowed_flags is the exhaustive permitted flag set;
    value_flags are the subset that consume the following argv token as a value
    (that value is metachar/deny-checked but not required to be a target)."""

    tool_id: str
    binary: str
    description: str
    allowed_flags: FrozenSet[str]
    value_flags: FrozenSet[str] = field(default_factory=frozenset)
    timeout: float = 300.0
    needs_network: bool = True


ALLOWED_TOOLS = {
    spec.tool_id: spec
    for spec in (
        ToolSpec("nmap", "nmap", "Port/service scan",
                 frozenset({"-sV", "-sT", "-sS", "-Pn", "-p", "--top-ports", "-T4", "-T3", "-A", "-oX", "--open"}),
                 value_flags=frozenset({"-p", "--top-ports"})),
        ToolSpec("httpx", "httpx", "HTTP probe",
                 frozenset({"-u", "-l", "-json", "-silent", "-title", "-status-code", "-tech-detect"}),
                 value_flags=frozenset({"-u", "-l"})),
        ToolSpec("curl", "curl", "Single HTTP request",
                 frozenset({"-s", "-i", "-I", "-L", "-X", "-H", "-A", "--max-time", "--data"}),
                 value_flags=frozenset({"-X", "-H", "-A", "--max-time", "--data"})),
        ToolSpec("nuclei", "nuclei", "Template vuln scan",
                 frozenset({"-u", "-tags", "-severity", "-json", "-silent", "-rl"}),
                 value_flags=frozenset({"-u", "-tags", "-severity", "-rl"})),
        ToolSpec("ffuf", "ffuf", "Content/dir fuzz",
                 frozenset({"-u", "-w", "-mc", "-fc", "-t", "-rate"}),
                 value_flags=frozenset({"-u", "-w", "-mc", "-fc", "-t", "-rate"})),
        ToolSpec("gobuster", "gobuster", "Dir/dns brute",
                 frozenset({"dir", "dns", "-u", "-w", "-t"}),
                 value_flags=frozenset({"-u", "-w", "-t"})),
        ToolSpec("dig", "dig", "DNS lookup", frozenset({"+short", "any", "a", "aaaa", "mx", "ns", "txt"})),
        ToolSpec("whois", "whois", "WHOIS lookup", frozenset()),
        ToolSpec("whatweb", "whatweb", "Tech fingerprint", frozenset({"--color=never", "-a"}),
                 value_flags=frozenset({"-a"})),
        ToolSpec("wafw00f", "wafw00f", "WAF detection", frozenset({"-a"})),
    )
}


def isAllowedTool(tool_id: str) -> bool:
    return tool_id in ALLOWED_TOOLS


def _hasForbiddenToken(arg: str) -> bool:
    if METACHAR_PATTERN.search(arg):
        return True
    if any(token in arg for token in COMMAND_SUB_TOKENS):
        return True
    lowered = arg.lower()
    return any(bad in lowered for bad in DENY_SUBSTRINGS)


def _looksLikeTarget(arg: str) -> bool:
    return bool(_URL.match(arg) or _IPV4.match(arg) or _HOST.match(arg))


def extractTargets(tool_id: str, args: List[str]) -> List[str]:
    """Return the argument tokens that are hosts/URLs/IPs (to be scope-checked).
    Values consumed by value-flags are skipped -- they are options, not targets."""
    spec = ALLOWED_TOOLS.get(tool_id)
    if spec is None:
        return []
    targets: List[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-") or arg in spec.allowed_flags:
            base = arg.split("=", 1)[0]
            if base in spec.value_flags and "=" not in arg:
                skip_next = True
            continue
        if _looksLikeTarget(arg):
            targets.append(arg)
    return targets


def validateArgs(tool_id: str, args: List[str]) -> Tuple[bool, str]:
    """Deterministically validate a proposed command's arguments against the
    tool's policy. Returns (ok, reason)."""
    spec = ALLOWED_TOOLS.get(tool_id)
    if spec is None:
        return False, f"Tool '{tool_id}' is not on the allowlist."

    for arg in args:
        if _hasForbiddenToken(arg):
            return False, f"Argument '{arg}' contains a forbidden token."

    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            base = arg.split("=", 1)[0]
            if base not in spec.allowed_flags:
                return False, f"Flag '{base}' is not allowed for '{tool_id}'."
            if base in spec.value_flags and "=" not in arg:
                skip_next = True
            continue
        # A bare positional token must be a subcommand keyword (in allowed_flags)
        # or a target host/URL/IP. Anything else is rejected.
        if arg in spec.allowed_flags:
            continue
        if not _looksLikeTarget(arg):
            return False, f"Positional argument '{arg}' is neither a known subcommand nor a target."
    return True, ""
